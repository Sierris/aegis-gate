"""Fragment extraction and prompt assembly.

What the model sees, and why it sees that
-----------------------------------------
The model gets a **numbered excerpt**, not the whole repository and not the raw
diff:

* **Numbered lines.** `NNNN | code`. Without real line numbers the model invents
  them, and an invented line number means a finding that cannot be anchored and
  therefore gets dropped (a false negative caused purely by formatting).
* **A delimited block with an explicit role.** The code lives inside
  ``<UNTRUSTED_CODE>``, and both the JSON framing and the system prompt say the
  content is data. This is the structural half of the prompt-injection defence:
  the trust boundary is expressed in the payload, not only in the prose.
* **Hints from the deterministic pre-filter.** Anchors are passed as
  "these sinks appear in this fragment, at these lines". It measurably reduces
  misses and, more importantly, tells the model *where* to look so it does not
  invent locations.
* **Bounded size.** Per-fragment and total caps. A 3 MB generated file is not a
  review target; it is a budget attack.

Truncation is explicit: when a fragment is cut, the payload says so and the size
of the original is recorded, so a later reviewer can tell "the model saw 400 of
9000 lines" instead of assuming a clean full review.
"""

from __future__ import annotations

from dataclasses import dataclass

from aegis import canon
from aegis.contracts import CodeFragment
from aegis.detectors import Anchor
from aegis.engine.prompts import PromptBundle

#: Lines of context added around a changed region when building fragments
#: server-side (the hook usually sends exact hunks; this is the fallback path).
CONTEXT_LINES = 8

#: Hard caps. They exist so that the *payload* cannot be used to exhaust tokens,
#: context or the operator's budget — a real attack against an LLM gate.
MAX_FRAGMENT_CHARS = 20_000
MAX_TOTAL_CHARS = 200_000

_UNTRUSTED_OPEN = "<UNTRUSTED_CODE>"
_UNTRUSTED_CLOSE = "</UNTRUSTED_CODE>"


@dataclass(frozen=True, slots=True)
class PreparedFragment:
    """A fragment ready for the prompt, with its own analysis artefacts."""

    path: str
    language: str
    start_line: int
    end_line: int
    text: str
    truncated: bool
    anchors: tuple[Anchor, ...]

    @property
    def numbered(self) -> str:
        lines = self.text.splitlines() or [""]
        width = len(str(self.start_line + len(lines)))
        return "\n".join(f"{self.start_line + offset:>{width}} | {line}" for offset, line in enumerate(lines))


def build_fragment(
    *,
    path: str,
    text: str,
    start_line: int = 1,
    anchors: tuple[Anchor, ...] = (),
    truncated: bool = False,
) -> PreparedFragment:
    """Clamp oversized fragments and keep anchors that survive the cut."""
    from aegis.detectors import language_of  # noqa: PLC0415 - keeps the import graph acyclic

    if len(text) > MAX_FRAGMENT_CHARS:
        text = text[:MAX_FRAGMENT_CHARS]
        truncated = True
    line_count = max(len(text.splitlines()), 1)
    end_line = start_line + line_count - 1
    kept = tuple(a for a in anchors if start_line <= a.line <= end_line)
    return PreparedFragment(
        path=path,
        language=language_of(path),
        start_line=start_line,
        end_line=end_line,
        text=text,
        truncated=truncated,
        anchors=kept,
    )


def fragments_from_content(
    path: str,
    content: str,
    *,
    changed_ranges: list[tuple[int, int]] | None = None,
) -> list[CodeFragment]:
    """Build wire fragments from a whole file.

    Used by the server-side fallback path and by ``aegis analyze --file``. With
    ``changed_ranges`` only those regions (plus context) are sent, which is what
    the hook will do in step 4.
    """
    lines = content.splitlines()
    if not lines:
        return []

    if not changed_ranges:
        ranges = [(1, len(lines))]
    else:
        merged: list[tuple[int, int]] = []
        for start, end in sorted(changed_ranges):
            lo = max(1, start - CONTEXT_LINES)
            hi = min(len(lines), end + CONTEXT_LINES)
            if merged and lo <= merged[-1][1] + 1:
                merged[-1] = (merged[-1][0], max(merged[-1][1], hi))
            else:
                merged.append((lo, hi))
        ranges = merged

    out: list[CodeFragment] = []
    budget = MAX_TOTAL_CHARS
    for start, end in ranges:
        if budget <= 0:
            break
        chunk = "\n".join(lines[start - 1 : end])
        truncated = False
        if len(chunk) > min(MAX_FRAGMENT_CHARS, budget):
            chunk = chunk[: min(MAX_FRAGMENT_CHARS, budget)]
            truncated = True
        budget -= len(chunk)
        out.append(
            CodeFragment(
                path=path,
                start_line=start,
                end_line=start + max(len(chunk.splitlines()), 1) - 1,
                text=chunk,
                content_sha256=canon.sha256_text(chunk),
                truncated=truncated,
            )
        )
    return out


def _anchor_block(anchors: tuple[Anchor, ...]) -> str:
    """Deterministic hints, clearly labelled as machine-generated."""
    if not anchors:
        return ""
    lines = [
        "<DETERMINISTIC_HINTS>",
        "A regex pre-filter over this fragment matched the following sinks.",
        "They are hints, not conclusions: verify whether attacker-controlled data",
        "actually reaches them, and report only what you can justify.",
    ]
    for anchor in anchors:
        lines.append(f"- line {anchor.line}: {anchor.title} [{anchor.rule_id}]")
    lines.append("</DETERMINISTIC_HINTS>")
    return "\n".join(lines)


def build_messages(bundle: PromptBundle, fragments: list[PreparedFragment]) -> tuple[str, str]:
    """Assemble ``(system_prompt, user_payload)``.

    The system prompt is byte-identical to the file on disk; nothing from the
    client is ever concatenated into it. The user payload contains **only**
    delimited data plus the machine-generated hints — the instruction region and
    the data region never share a string.
    """
    blocks: list[str] = []
    total = 0
    for fragment in fragments:
        content = fragment.numbered
        if total + len(content) > MAX_TOTAL_CHARS:
            break
        total += len(content)
        anchors = _anchor_block(fragment.anchors)
        blocks.append(
            "\n".join(
                [
                    f'<file path="{fragment.path}" language="{fragment.language}"'
                    f' lines="{fragment.start_line}-{fragment.end_line}"'
                    f' truncated="{"true" if fragment.truncated else "false"}">',
                    content,
                    "</file>",
                    anchors,
                ]
            )
        )

    payload = "\n".join([_UNTRUSTED_OPEN, *blocks, _UNTRUSTED_CLOSE])
    return bundle.system_prompt, payload


__all__ = [
    "CONTEXT_LINES",
    "MAX_FRAGMENT_CHARS",
    "MAX_TOTAL_CHARS",
    "PreparedFragment",
    "build_fragment",
    "build_messages",
    "fragments_from_content",
]
