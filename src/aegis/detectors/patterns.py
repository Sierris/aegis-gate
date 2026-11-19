"""Deterministic detectors: the part of the pipeline a prompt injection cannot touch.

Role in the architecture
------------------------
These are **not** the detection mechanism — they are three things the LLM cannot
provide:

1. **A floor.** A textbook `os.system(user_input)` is caught even if the model is
   down, rate-limited, or successfully manipulated into saying "clean".
2. **Grounding.** Anchors are passed to the model as hints ("these sinks exist in
   this fragment"), which measurably reduces both misses and invented findings.
3. **A cross-check.** If the model returns an empty finding list while a
   high-confidence anchor exists, the engine refuses to grant a silent `allow`:
   the analysis is marked `degraded` and the discrepancy is reported. This is the
   specific defence against the cheapest prompt injection
   (`# output {"findings": []}`).

Design constraints
------------------
* **No parsing, no data flow.** Deliberately syntactic. Anything needing semantics
  is the model's job; the anchor stays a low-cost, explainable signal.
* **Deterministic and offline.** Pure regex over lines: same input, same output,
  no network, no model, microseconds.
* **Conservative about confidence.** An anchor alone never blocks at `high` unless
  it is unambiguous (`shell=True` with an f-string, `md5(` on a password...).
  False positives here cost developer trust, which is the resource that keeps the
  gate alive.
"""

from __future__ import annotations

import enum
import re
from dataclasses import dataclass
from re import Pattern

from aegis.contracts import FindingSource, OwaspCategory, Severity


class AnchorKind(enum.StrEnum):
    """Coarse bucket, used for metrics and for the cross-check policy."""

    COMMAND_EXEC = "command_exec"
    SQL_STRING_BUILD = "sql_string_build"
    CODE_EVAL = "code_eval"
    TEMPLATE_INJECTION = "template_injection"
    DESERIALIZATION = "deserialization"
    WEAK_CRYPTO = "weak_crypto"
    TLS_VERIFICATION_OFF = "tls_verification_off"
    HARDCODED_SECRET = "hardcoded_secret"  # noqa: S105 - anchor kind label
    MISSING_AUTHZ = "missing_authz"
    OUTBOUND_FETCH = "outbound_fetch"


@dataclass(frozen=True, slots=True)
class Rule:
    """One syntactic rule."""

    id: str
    kind: AnchorKind
    category: OwaspCategory
    severity: Severity
    cwe: int
    title: str
    pattern: Pattern[str]
    #: A rule fires only when the matched line also mentions an input-looking
    #: identifier. This is what keeps `subprocess.run(["ls"])` out of the report.
    requires_input_hint: bool = True
    confidence: float = 0.55
    #: Patterns that, when present on the same line, mean "this is the fixed
    #: version". Checked after the rule matches; see ``_suppressed``.
    suppress_if: tuple[Pattern[str], ...] = ()
    #: Alternative triggers, OR-ed with the input hint. Used by rules where the
    #: *shape* of the code (interpolation) is itself the evidence.
    also_fires_on: tuple[Pattern[str], ...] = ()
    #: Conjunction: every pattern here must also match the line. Used when the
    #: bug is the *co-occurrence* of two things (a SQL keyword AND interpolation),
    #: which cannot be expressed as one regex without ugly lookbehinds.
    all_of: tuple[Pattern[str], ...] = ()
    languages: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class Anchor:
    """A deterministic hit. Named "anchor" because of role 2 above."""

    rule_id: str
    kind: AnchorKind
    category: OwaspCategory
    severity: Severity
    cwe: int
    title: str
    path: str
    line: int
    line_text: str
    confidence: float
    source: FindingSource = FindingSource.SAST


#: Identifiers that usually mean "this value came from outside".
#:
#: Kept as a word-boundary regex over the same line rather than as data-flow
#: analysis: cheap, explainable, and it only ever *promotes* a rule to fire, so a
#: miss here cannot produce a false positive.
INPUT_HINTS: Pattern[str] = re.compile(
    r"\b("
    r"request|req\.|args|query|params|form|body|headers?|cookies?|input|"
    r"argv|environ|get_json|json\[|payload|user_?id|username|email|"
    r"passw(?:or)?d|secret|token|credential|cmd|command|search|filter|where"
    r")\b",
    re.IGNORECASE,
)

#: Names that merely *suggest* externality. A variable called ``url`` or ``host`` is
#: a hint, not evidence: flagging `requests.get(url)` as SSRF would drown the real
#: findings and the team would disable the gate. Kept exported so a detector that
#: wants a weaker signal can opt in explicitly.
WEAK_INPUT_HINTS: Pattern[str] = re.compile(
    r"\b(url|uri|host|hostname|filename|path|redirect|next|callback|table|column|sort|order_?by)\b",
    re.IGNORECASE,
)

#: "This string is assembled from a variable" — an f-string, ``%`` formatting,
#: ``.format()`` or concatenation. Stronger and more general than any identifier
#: list: it catches `os.popen(f"ping {host}")` without needing to know that `host`
#: is attacker-controlled, and it stays silent on `subprocess.run(["ls"])`.
INTERPOLATION: Pattern[str] = re.compile(
    r"""f["'][^"']*\{|%\s*\(|%\s+[a-z_]\w*|\.format\s*\(|\+\s*[a-z_]\w*""",
)

_SECRET_VALUE = re.compile(
    r"""(?ix)
    (?:secret|passw(?:or)?d|api[_-]?key|apikey|token|private[_-]?key|client[_-]?secret)
    \s*[:=]\s*
    (?:f?["'])(?!\s*["'])([^"'\s]{8,})(?:["'])
    """
)

_RULES: tuple[Rule, ...] = (
    # --- A03 Injection ---------------------------------------------------
    Rule(
        id="A03-CMDI-001",
        kind=AnchorKind.COMMAND_EXEC,
        category=OwaspCategory.A03_INJECTION,
        severity=Severity.HIGH,
        cwe=78,
        title="OS command built from a variable string",
        pattern=re.compile(
            r"\b(os\.system|os\.popen|commands\.getoutput|commands\.getstatusoutput|"
            r"subprocess\.(?:run|call|check_output|check_call|Popen))\s*\("
        ),
        confidence=0.6,
        # `shell=False` or a list argument is the recommended fix; firing on it
        # would punish the developer for doing exactly what the remediation says.
        suppress_if=(
            re.compile(r"shell\s*=\s*False"),
            re.compile(r"subprocess\.\w+\s*\(\s*\["),
        ),
        also_fires_on=(INTERPOLATION,),
    ),
    Rule(
        id="A03-CMDI-002",
        kind=AnchorKind.COMMAND_EXEC,
        category=OwaspCategory.A03_INJECTION,
        severity=Severity.CRITICAL,
        cwe=78,
        title="Shell invocation with shell=True",
        pattern=re.compile(r"shell\s*=\s*True"),
        confidence=0.7,
    ),
    Rule(
        id="A03-EVAL-001",
        kind=AnchorKind.CODE_EVAL,
        category=OwaspCategory.A03_INJECTION,
        severity=Severity.HIGH,
        cwe=95,
        title="Dynamic code evaluation",
        pattern=re.compile(r"\b(eval|exec)\s*\(|new\s+Function\s*\("),
        confidence=0.6,
    ),
    Rule(
        id="A03-SQLI-001",
        kind=AnchorKind.SQL_STRING_BUILD,
        category=OwaspCategory.A03_INJECTION,
        severity=Severity.HIGH,
        cwe=89,
        title="SQL statement built by string formatting or concatenation",
        # The bug is the *co-occurrence* of a SQL keyword and interpolation on the
        # same line. Two patterns instead of one because the f-string prefix comes
        # before the keyword, and a single regex cannot order them without
        # lookbehinds that would then be brittle across statement shapes.
        #
        # Note what is NOT interpolation: `%s`. A bare `%\w` marker would flag every
        # correctly parameterised query — the most damaging false positive this
        # rule pack could have, because it punishes the fix.
        pattern=re.compile(r"(?i)\b(select|insert|update|delete)\b"),
        all_of=(INTERPOLATION,),
        requires_input_hint=False,
        suppress_if=(
            # Explicit parameterised call: the documented remediation.
            re.compile(r"execute\s*\([^)]*%s[^)]*,\s*\("),
            re.compile(r"execute\s*\([^)]*\?[^)]*,\s*\["),
        ),
        confidence=0.6,
    ),
    Rule(
        id="A03-SSTI-001",
        kind=AnchorKind.TEMPLATE_INJECTION,
        category=OwaspCategory.A03_INJECTION,
        severity=Severity.HIGH,
        cwe=1336,
        title="Template rendered from a dynamic string",
        pattern=re.compile(r"(?i)render_template_string|Template\s*\(\s*[a-z_]\w*\s*\)|\|\s*safe\b"),
        confidence=0.55,
    ),
    Rule(
        id="A03-DESER-001",
        kind=AnchorKind.DESERIALIZATION,
        category=OwaspCategory.A03_INJECTION,
        severity=Severity.HIGH,
        cwe=502,
        title="Deserialisation of untrusted data",
        pattern=re.compile(r"\b(pickle\.loads?|yaml\.load|marshal\.loads|jsonpickle\.decode)\s*\("),
        confidence=0.65,
    ),
    # --- A02 Cryptographic failures --------------------------------------
    Rule(
        id="A02-CRYPTO-001",
        kind=AnchorKind.WEAK_CRYPTO,
        category=OwaspCategory.A02_CRYPTOGRAPHIC_FAILURES,
        severity=Severity.HIGH,
        cwe=327,
        title="Weak digest used for a security decision",
        pattern=re.compile(
            r"(?i)\b(md5|sha1)\s*\(|hashlib\.(md5|sha1)\b"
            r'|MessageDigest\.getInstance\(\s*"(MD5|SHA-?1)"'
        ),
        confidence=0.6,
    ),
    Rule(
        id="A02-TLS-001",
        kind=AnchorKind.TLS_VERIFICATION_OFF,
        category=OwaspCategory.A02_CRYPTOGRAPHIC_FAILURES,
        severity=Severity.HIGH,
        cwe=295,
        title="TLS certificate verification disabled",
        pattern=re.compile(
            r"verify\s*=\s*False|InsecureSkipVerify\s*:\s*true|rejectUnauthorized\s*:\s*false"
        ),
        # The flag itself is the whole bug: no input hint needed. Waiting for one
        # would miss `requests.get(URL, verify=False)` with a constant URL.
        requires_input_hint=False,
        confidence=0.85,
    ),
    Rule(
        id="A02-SECRET-001",
        kind=AnchorKind.HARDCODED_SECRET,
        category=OwaspCategory.A02_CRYPTOGRAPHIC_FAILURES,
        severity=Severity.HIGH,
        cwe=798,
        title="Hardcoded credential",
        pattern=_SECRET_VALUE,
        requires_input_hint=False,  # the value itself is the evidence
        confidence=0.65,
    ),
    Rule(
        id="A02-RAND-001",
        kind=AnchorKind.WEAK_CRYPTO,
        category=OwaspCategory.A02_CRYPTOGRAPHIC_FAILURES,
        severity=Severity.MEDIUM,
        cwe=338,
        title="Non-cryptographic randomness for a token or secret",
        pattern=re.compile(
            r"(?i)\b(random\.(random|randint|choice|choices)|Math\.random)\s*\([^)]*\)"
            r"[^;]{0,80}\b(token|secret|nonce|salt|password|otp|code)\b"
        ),
        requires_input_hint=False,
        confidence=0.5,
    ),
    # --- A01 Broken access control ---------------------------------------
    Rule(
        id="A01-AUTHZ-001",
        kind=AnchorKind.MISSING_AUTHZ,
        category=OwaspCategory.A01_BROKEN_ACCESS_CONTROL,
        severity=Severity.MEDIUM,
        cwe=639,
        title="Object owner taken directly from the request",
        pattern=re.compile(
            r"(?i)\b(get|filter|find|where|select)\w*\s*\([^)]*\b(user_?id|account_?id|owner|tenant)\b"
            r"[^)]*(request|args|query|params|body)"
        ),
        confidence=0.5,
    ),
    Rule(
        id="A01-AUTHZ-002",
        kind=AnchorKind.MISSING_AUTHZ,
        category=OwaspCategory.A01_BROKEN_ACCESS_CONTROL,
        severity=Severity.HIGH,
        cwe=285,
        title="Privilege decided from client-controlled input",
        pattern=re.compile(
            r"(?i)\b(is_?admin|is_?superuser|role|permission|scope)\s*=\s*"
            r"(request|args|query|params|body|form|payload)"
        ),
        requires_input_hint=False,
        confidence=0.7,
    ),
    # --- A10 SSRF --------------------------------------------------------
    Rule(
        id="A10-SSRF-001",
        kind=AnchorKind.OUTBOUND_FETCH,
        category=OwaspCategory.A10_SSRF,
        severity=Severity.HIGH,
        cwe=918,
        title="Outbound request to a dynamically chosen destination",
        pattern=re.compile(
            r"(?i)\b(requests\.(get|post|put|head|delete)|httpx\.(get|post|AsyncClient)|"
            r"urllib\.request\.urlopen|urlopen|axios\.(get|post)|fetch|http\.request|"
            r"HttpClient\.newCall|RestTemplate)\s*\("
        ),
        confidence=0.55,
    ),
)

#: Paths that are not worth analysing. Kept here (not in the LLM) so the decision
#: is deterministic, explainable and identical on every run.
SKIP_SUFFIXES: tuple[str, ...] = (
    ".lock",
    ".min.js",
    ".min.css",
    ".map",
    ".svg",
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".ico",
    ".pdf",
    ".zip",
    ".gz",
    ".whl",
    ".jar",
    ".pyc",
)
#: Generated/lock files: reviewing them costs tokens and yields noise.
SKIP_NAMES: frozenset[str] = frozenset(
    {
        "package-lock.json",
        "npm-shrinkwrap.json",
        "yarn.lock",
        "pnpm-lock.yaml",
        "poetry.lock",
        "Pipfile.lock",
        "uv.lock",
        "Cargo.lock",
        "go.sum",
        "composer.lock",
        "Gemfile.lock",
    }
)

SKIP_PATH_FRAGMENTS: tuple[str, ...] = (
    "/node_modules/",
    "/vendor/",
    "/dist/",
    "/build/",
    "/site-packages/",
    "/.venv/",
    "/third_party/",
    "/generated/",
)

#: Language detection by extension: only used to pick which rules *could* apply
#: and to label the fragment in the prompt. Unknown extensions are still scanned.
_EXT_LANG: dict[str, str] = {
    ".py": "python",
    ".js": "javascript",
    ".jsx": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".java": "java",
    ".kt": "kotlin",
    ".go": "go",
    ".rb": "ruby",
    ".php": "php",
    ".cs": "csharp",
    ".rs": "rust",
    ".sh": "shell",
    ".bash": "shell",
    ".sql": "sql",
    ".yml": "yaml",
    ".yaml": "yaml",
    ".tf": "terraform",
}


def language_of(path: str) -> str:
    lower = path.lower()
    for ext, lang in _EXT_LANG.items():
        if lower.endswith(ext):
            return lang
    return "unknown"


def should_skip(path: str, *, skip_tests: bool = False) -> bool:
    """Exclusions. Applied before any token is spent."""
    lower = "/" + path.lower().strip("/")
    if lower.rsplit("/", 1)[-1] in SKIP_NAMES:
        return True
    if lower.endswith(SKIP_SUFFIXES):
        return True
    if any(fragment in lower for fragment in SKIP_PATH_FRAGMENTS):
        return True
    return bool(
        skip_tests and (lower.endswith(("_test.py", "test_", "_test.go", "_test.rb")) or "/tests/" in lower)
    )


def _has_input_hint(line: str) -> bool:
    return INPUT_HINTS.search(line) is not None


def _any_match(patterns: tuple[Pattern[str], ...], line: str) -> bool:
    return any(pattern.search(line) is not None for pattern in patterns)


def _suppressed(rule: Rule, line: str) -> bool:
    return any(pattern.search(line) is not None for pattern in rule.suppress_if)


def scan_line(line: str, *, path: str, line_no: int) -> list[Anchor]:
    """Run every rule against one line."""
    anchors: list[Anchor] = []
    for rule in _RULES:
        if rule.languages and language_of(path) not in rule.languages:
            continue
        if rule.pattern.search(line) is None:
            continue
        if rule.all_of and not _any_match(rule.all_of, line):
            continue
        if rule.requires_input_hint and not (_has_input_hint(line) or _any_match(rule.also_fires_on, line)):
            continue
        if rule.suppress_if and _suppressed(rule, line):
            continue
        anchors.append(
            Anchor(
                rule_id=rule.id,
                kind=rule.kind,
                category=rule.category,
                severity=rule.severity,
                cwe=rule.cwe,
                title=rule.title,
                path=path,
                line=line_no,
                line_text=line.rstrip(),
                confidence=rule.confidence,
            )
        )
    return anchors


def scan(text: str, *, path: str, first_line: int = 1) -> list[Anchor]:
    """Scan a fragment. ``first_line`` keeps the reported line numbers absolute."""
    anchors: list[Anchor] = []
    for offset, line in enumerate(text.splitlines()):
        anchors.extend(scan_line(line, path=path, line_no=first_line + offset))
    return anchors


def rules() -> tuple[Rule, ...]:
    """Exposed for documentation, tests and for printing the rule pack."""
    return _RULES


def coverage() -> dict[str, list[str]]:
    """OWASP category -> rule ids, so a report can prove the minimum of 3."""
    out: dict[str, list[str]] = {}
    for rule in _RULES:
        out.setdefault(rule.category.value, []).append(rule.id)
    return out


@dataclass(frozen=True, slots=True)
class InjectionSignal:
    """A pattern in the reviewed code that looks like an instruction to a model.

    Recorded, never stripped. Stripping would erase evidence of the attempt and
    would also break the digest/evidence anchoring (the model must see the real
    bytes). The signal is used for alerting and to annotate the block message.
    """

    kind: str
    line: int
    excerpt: str


_INJECTION_PATTERNS: tuple[tuple[str, Pattern[str]], ...] = (
    (
        "instruction_override",
        re.compile(
            r"(?i)\b(ignore|disregard|forget)\b[^.\n]{0,40}\b(previous|above|prior|all)\b"
            r"[^.\n]{0,30}\b(instruction|prompt|rule|direction)"
        ),
    ),
    (
        "role_switch",
        re.compile(
            r"(?i)\b(system|assistant)\s*:|<\|im_start\|>|\[/?(INST|SYS)\]|###\s*(system|instruction)"
        ),
    ),
    (
        "output_shaping",
        re.compile(
            r"(?i)(output|return|respond with|reply with)\s*"
            r"[\"'`]?\s*\{\s*[\"']?findings[\"']?\s*:\s*\[\s*\]"
        ),
    ),
    (
        "prompt_exfiltration",
        re.compile(
            r"(?i)\b(print|reveal|show|repeat|leak)\b[^.\n]{0,30}"
            r"\b(system prompt|instructions|prompt)\b"
        ),
    ),
    (
        "approval_claim",
        re.compile(
            r"(?i)\b(?:already\s+|pre-)?(approved|audited|reviewed|cleared)\b"
            r"[^.\n]{0,40}\b(appsec|security|reviewer|team)\b"
        ),
    ),
)


def detect_injection_attempts(text: str, *, first_line: int = 1) -> list[InjectionSignal]:
    """Find text in the reviewed code that addresses the model."""
    signals: list[InjectionSignal] = []
    seen: set[tuple[str, int]] = set()
    for offset, line in enumerate(text.splitlines()):
        for kind, pattern in _INJECTION_PATTERNS:
            if pattern.search(line) is None:
                continue
            key = (kind, offset)
            if key in seen:
                continue
            seen.add(key)
            signals.append(
                InjectionSignal(
                    kind=kind,
                    line=first_line + offset,
                    excerpt=line.strip()[:200],
                )
            )
    return signals


__all__ = [
    "INPUT_HINTS",
    "INTERPOLATION",
    "SKIP_NAMES",
    "SKIP_PATH_FRAGMENTS",
    "SKIP_SUFFIXES",
    "WEAK_INPUT_HINTS",
    "Anchor",
    "AnchorKind",
    "InjectionSignal",
    "Rule",
    "coverage",
    "detect_injection_attempts",
    "language_of",
    "rules",
    "scan",
    "scan_line",
    "should_skip",
]
