"""Prompt loading, versioning and consistency checks.

Where the prompt lives — and why
--------------------------------
**In files under ``prompts/``, versioned in git, not in code and not in a
database.** The reasoning, restated here because it is an explicit deliverable:

* It is *security policy*, so it must be reviewed. A PR shows the exact diff of
  what the reviewer will now consider dangerous; an f-string buried in a module
  does not.
* It must be *auditable after the fact*. Every attestation carries
  ``prompt_version``, which is derived from the **content hash** — not a hand-kept
  number that someone forgets to bump. Re-running an old attestation is then
  possible by checking out the prompt with the same hash.
* It must be *iterable without a deploy*. Tuning wording is the common change;
  requiring a release for it guarantees the prompt never improves.
* It must be *testable*. `validate_prompt()` fails the build if the prompt and the
  JSON Schema drift apart (a category in the schema that the prompt never tells the
  model to look for is a silent detection gap).

Why not in the database: it would lose code review, which is the only quality gate
this artefact has. Why not in the client: the developer could rewrite it (E4 in the
threat model).

Version format: ``<file-stem>@<12 hex of sha256(prompt + schema)>``.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path

from aegis import canon
from aegis.contracts import OwaspCategory
from aegis.errors import ConfigError

#: Sections that must exist in the prompt. Deleting one silently removes a
#: mitigation, so their presence is asserted at load time and in CI.
REQUIRED_MARKERS: tuple[tuple[str, str], ...] = (
    ("Untrusted data", "the prompt-injection framing block"),
    ("evidence", "the evidence-anchoring instruction"),
    ("A03", "the injection category"),
)

#: Minimum prompt length. A truncated prompt is a catastrophic failure mode (the
#: model reverts to generic advice), and it would otherwise be invisible.
MIN_PROMPT_CHARS = 800


def _dig(node: object, *keys: str) -> object:
    """Walk nested dicts, returning ``None`` when the path does not exist."""
    current = node
    for key in keys:
        if not isinstance(current, dict):
            return None
        current = current.get(key)
    return current


@dataclass(frozen=True, slots=True)
class PromptBundle:
    """A loaded, verified prompt + schema pair."""

    name: str
    system_prompt: str
    schema: dict[str, object]
    version: str
    path: Path

    @property
    def schema_categories(self) -> frozenset[OwaspCategory]:
        """Categories the schema allows the model to report.

        Navigated defensively: this is a hand-authored JSON Schema, and a malformed
        one must fail with a clear ConfigError at load time rather than an
        AttributeError at the first analysis.
        """
        values = _dig(self.schema, "properties", "findings", "items", "properties", "category", "enum")
        if not isinstance(values, list):
            return frozenset()
        return frozenset(OwaspCategory(v) for v in values if isinstance(v, str))


def compute_version(*, name: str, prompt: str, schema: dict[str, object]) -> str:
    """Content-addressed version. Two different prompts can never share one."""
    digest = hashlib.sha256()
    digest.update(prompt.encode("utf-8"))
    digest.update(b"\x00")
    digest.update(canon.canonical_json(schema))
    return f"{name}@{digest.hexdigest()[:12]}"


def validate_prompt(text: str, *, name: str) -> None:
    """Fail loudly on a prompt that lost a required property."""
    if len(text) < MIN_PROMPT_CHARS:
        raise ConfigError(
            f"prompt {name!r} is only {len(text)} chars (min {MIN_PROMPT_CHARS}); it looks truncated"
        )
    missing = [f"{marker} ({why})" for marker, why in REQUIRED_MARKERS if marker not in text]
    if missing:
        raise ConfigError(f"prompt {name!r} is missing required content: {', '.join(missing)}")


def load_bundle(prompt_dir: Path, *, prompt_file: str = "analyze.v1.md") -> PromptBundle:
    """Load ``prompts/<prompt_file>`` + ``prompts/analysis.schema.json``."""
    directory = Path(prompt_dir).expanduser()
    prompt_path = directory / prompt_file
    schema_path = directory / "analysis.schema.json"

    try:
        prompt = prompt_path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ConfigError(f"cannot read prompt {prompt_path}: {exc}") from exc
    try:
        schema = json.loads(schema_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ConfigError(f"cannot read schema {schema_path}: {exc}") from exc
    if not isinstance(schema, dict):
        raise ConfigError(f"schema {schema_path} must be a JSON object")

    name = prompt_path.stem
    validate_prompt(prompt, name=name)
    bundle = PromptBundle(
        name=name,
        system_prompt=prompt,
        schema=schema,
        version=compute_version(name=name, prompt=prompt, schema=schema),
        path=prompt_path,
    )
    _check_prompt_schema_agree(bundle)
    return bundle


def _check_prompt_schema_agree(bundle: PromptBundle) -> None:
    """Detect drift between what the prompt asks for and what the schema allows."""
    schema_categories = bundle.schema_categories
    if not schema_categories:
        raise ConfigError(f"schema for {bundle.name!r} declares no owasp categories")
    missing = [c.value for c in schema_categories if c.value not in bundle.system_prompt]
    if missing:
        raise ConfigError(
            f"prompt {bundle.name!r} never mentions {missing}, but its schema allows them; "
            "the model would be asked to report a category it was not briefed on"
        )
    default_missing = [c.value for c in DEFAULT_SCOPE if c.value not in bundle.system_prompt]
    if default_missing:
        raise ConfigError(f"prompt {bundle.name!r} is missing default categories {default_missing}")


#: Categories the shipped profile promises. Kept here (not imported from
#: contracts) so the prompt check fails if someone narrows the product promise
#: without touching the prompt.
DEFAULT_SCOPE: tuple[OwaspCategory, ...] = (
    OwaspCategory.A01_BROKEN_ACCESS_CONTROL,
    OwaspCategory.A02_CRYPTOGRAPHIC_FAILURES,
    OwaspCategory.A03_INJECTION,
    OwaspCategory.A10_SSRF,
)


__all__ = [
    "DEFAULT_SCOPE",
    "MIN_PROMPT_CHARS",
    "REQUIRED_MARKERS",
    "PromptBundle",
    "compute_version",
    "load_bundle",
    "validate_prompt",
]
