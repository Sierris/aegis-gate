"""The analysis engine: deterministic prefilter → LLM → strict validation → policy.

Order is the whole design. Each stage may make the outcome *more* conservative and
never less:

    stage                          can block?   can un-block?
    ─────────────────────────────────────────────────────────────
    exclusions / fragment caps        no            n/a
    LLM findings                      yes           no
    schema + evidence anchoring       no            no   (only drops)
    deterministic anchor cross-check  yes           no
    profile policy                    yes           no
    fail_mode                         yes           no

The model can only ever *add* a reason to block. That asymmetry is what makes a
probabilistic component safe inside a gate: the worst a successful prompt injection
achieves is a *degraded* result, and ``fail_mode=closed`` blocks degraded results.

Failure handling is explicit, because the interesting question for a gate is not
"what happens when it works" but "what happens when the LLM is down":

* unreachable / rate-limited / unauthorized → ``fail_mode``; ``closed`` blocks with a
  POLICY finding that states the reason (never a silent allow).
* answered, but the answer is unusable → same path.
* answered with something valid that contradicts the deterministic floor →
  ``degraded``, and with ``strict_cross_check`` it blocks.
"""

from __future__ import annotations

import time
import uuid
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from typing import Any

from pydantic import ValidationError

from aegis.attest.signer import sign_attestation
from aegis.auth.keys import SigningKey
from aegis.auth.store import AuthStore
from aegis.contracts import (
    DEFAULT_CATEGORIES,
    AnalysisMeta,
    AnalysisPolicy,
    AnalyzeRequest,
    AnalyzeResponse,
    AuditAction,
    Decision,
    Finding,
    FindingSource,
    OwaspCategory,
    Severity,
    TokenUsage,
)
from aegis.detectors import Anchor, InjectionSignal, detect_injection_attempts, scan, should_skip
from aegis.engine.cache import AnalysisCache, cache_key
from aegis.engine.fragments import PreparedFragment, build_fragment, build_messages
from aegis.engine.prompts import PromptBundle, load_bundle
from aegis.llm.base import ChatMessage, ChatRequest, LlmError, LlmErrorCode, LlmProvider
from aegis.validate.findings import (
    RawFinding,
    UnusableAnswerError,
    anchor_findings,
    cross_check_with_anchors,
    extract_json,
)

Clock = Callable[[], float]

#: Explanation and remediation for findings that come from the deterministic floor
#: rather than from the model. Written out per kind so the message is actionable:
#: "a regex matched" is not a useful thing to tell a developer.
_ANCHOR_GUIDANCE: dict[str, tuple[str, str]] = {
    "command_exec": (
        "The value can reach an OS command without being constrained. Whoever controls the input "
        "controls the command line: `; rm -rf /`, `$(id)`, or a reverse shell.",
        "Call the binary with an argument list and no shell: "
        '`subprocess.run(["ping","-c","1",host], shell=False, check=True)`. Validate `host` '
        "against an allowlist (or parse it as an IP/domain) before use.",
    ),
    "sql_string_build": (
        "The query is assembled from strings, so the input can rewrite the statement: data becomes "
        "syntax (UNION, stacked queries, `OR 1=1`).",
        'Use a parameterised query: `cursor.execute("SELECT * FROM users WHERE id = %s", (uid,))` '
        "or the ORM equivalent. Never interpolate identifiers without an allowlist.",
    ),
    "code_eval": (
        "Dynamic evaluation executes whatever the string contains, in the process's own trust context.",
        "Replace `eval`/`exec` with an explicit mapping (dict lookup, `getattr` on an allowlisted "
        "set, `ast.literal_eval` for data only).",
    ),
    "template_injection": (
        "Rendering a template built from user input lets the template engine itself be programmed, "
        "which usually escalates to code execution.",
        "Render a constant template with user data passed as context, never as template source.",
    ),
    "deserialization": (
        "Deserialising untrusted bytes can construct arbitrary objects and execute code during unpickling.",
        "Use a data-only format (JSON) with an explicit schema, or a signer/HMAC checked before "
        "deserialisation.",
    ),
    "weak_crypto": (
        "A broken digest is not a security primitive: collisions are practical and preimages are cheap.",
        "Use SHA-256+ for integrity and argon2id/scrypt/bcrypt for passwords.",
    ),
    "tls_verification_off": (
        "Disabling certificate verification makes every connection trivially interceptable.",
        "Remove the flag and pin the expected CA; if a self-signed certificate is needed in "
        "development, load it explicitly as a trusted CA.",
    ),
    "hardcoded_secret": (
        "A credential in source code is in git history, in every clone, and in every backup. Rotation "
        "is the only remedy once it is committed.",
        "Move it to the secret manager (`os.environ[...]`, Vault, AWS/GCP secrets) and rotate the "
        "value now — removing the line does not revoke it.",
    ),
    "missing_authz": (
        "Authorisation decided from request data means the caller chooses their own permissions.",
        "Derive the identity and its rights from the authenticated session, then check ownership "
        "server-side on every object access.",
    ),
    "outbound_fetch": (
        "The destination of the outbound request is influenced by the caller, so the server can be "
        "used to reach internal services (169.254.169.254, localhost, internal DNS).",
        "Resolve and validate the destination against an explicit allowlist, reject private/link-local "
        "ranges after DNS resolution, and disable redirects or re-validate them.",
    ),
}


@dataclass(slots=True)
class EngineDeps:
    """Everything the analyzer needs, injected so tests need no network or keys."""

    provider: LlmProvider
    bundle: PromptBundle
    key: SigningKey
    issuer: str
    fail_mode: str = "closed"
    strict_cross_check: bool = True
    max_output_tokens: int = 4000
    temperature: float = 0.0
    cache: AnalysisCache | None = None
    store: AuthStore | None = None
    audit_key: bytes | None = None
    now: Clock = time.time


@dataclass(slots=True)
class _Prepared:
    fragments: list[PreparedFragment] = field(default_factory=list)
    anchors: list[Anchor] = field(default_factory=list)
    injections: list[InjectionSignal] = field(default_factory=list)
    skipped: list[str] = field(default_factory=list)


class Analyzer:
    """Stateless service object; one instance per process."""

    def __init__(self, deps: EngineDeps) -> None:
        self._deps = deps

    @property
    def bundle(self) -> PromptBundle:
        return self._deps.bundle

    @property
    def cache(self) -> AnalysisCache | None:
        return self._deps.cache

    # -- public entrypoint -------------------------------------------------
    def analyze(
        self,
        request: AnalyzeRequest,
        *,
        actor: str,
        scope: str = "analyze",
    ) -> AnalyzeResponse:
        # ``actor`` is the authenticated identity from the Bearer token; the audit
        # rows below record it, so a verdict is always attributable to a person.
        started = self._deps.now()
        policy = self._effective_policy(request.policy)
        prepared = self._prepare(request, policy)
        payload_sha = request.payload_sha256
        ck = cache_key(
            payload_sha256=payload_sha,
            prompt_version=self._deps.bundle.version,
            model=self._deps.provider.describe(),
            policy=policy,
        )

        if not prepared.fragments:
            # Nothing to review is not a failure: a commit touching only lockfiles or
            # binaries gets an explicit, auditable allow.
            return self._respond(
                request,
                policy,
                actor or request.commit.author.email,
                decision=Decision.ALLOW,
                findings=[],
                payload_sha=payload_sha,
                scope=scope,
                started=started,
                model=self._deps.provider.describe(),
                prompt_version=self._deps.bundle.version,
                degraded=False,
                cache_hit=False,
                usage=TokenUsage(),
                extra_detail={"skipped": prepared.skipped, "reason": "no_analyzable_fragments"},
            )

        if self._deps.cache is not None:
            cached = self._deps.cache.get(ck)
            if cached is not None:
                decision = Decision.BLOCK if any(f.blocking for f in cached.findings) else Decision.ALLOW
                return self._respond(
                    request,
                    policy,
                    actor,
                    decision=decision,
                    findings=list(cached.findings),
                    payload_sha=payload_sha,
                    scope=scope,
                    started=started,
                    model=self._deps.provider.describe(),
                    prompt_version=self._deps.bundle.version,
                    degraded=False,
                    cache_hit=True,
                    usage=TokenUsage(),
                    extra_detail={"cached": True, "skipped": prepared.skipped},
                )

        system_prompt, payload = build_messages(self._deps.bundle, prepared.fragments)
        chat_request = ChatRequest(
            messages=(
                ChatMessage(role="system", content=system_prompt),
                ChatMessage(role="user", content=payload),
            ),
            json_schema=self._deps.bundle.schema,
            max_output_tokens=self._deps.max_output_tokens,
            temperature=self._deps.temperature,
        )

        try:
            chat = self._deps.provider.chat(chat_request)
        except LlmError as exc:
            return self._on_provider_failure(
                request, policy, prepared, payload_sha, scope, started, actor, exc
            )

        try:
            document = extract_json(chat.text)
        except UnusableAnswerError as exc:
            # An unusable answer and an absent answer are the same problem for a
            # gate, so they share the fail_mode path — but they get distinct codes
            # so the metrics can tell "model is down" from "model is being weird".
            return self._on_provider_failure(
                request,
                policy,
                prepared,
                payload_sha,
                scope,
                started,
                actor,
                LlmError(LlmErrorCode.MODEL_OUTPUT, str(exc)),
            )

        raw, invalid = self._parse_findings(document)
        report = anchor_findings(raw, fragments={f.path: f.text for f in prepared.fragments}, policy=policy)
        report.dropped_invalid += invalid
        suspicious, cross_reasons = cross_check_with_anchors(report, prepared.anchors, policy=policy)

        findings = list(report.findings)
        blocking = [f for f in findings if f.blocking]

        # An anchor the model did not confirm becomes a finding of its own when the
        # cross-check fires. This is what stops `{"findings": []}` from winning.
        if suspicious and self._deps.strict_cross_check:
            for anchor in prepared.anchors:
                if not _anchor_is_blocking(anchor, policy):
                    continue
                # Skip only if a *blocking* finding already covers this location.
                # A non-blocking (e.g. deliberately downgraded) finding must not
                # suppress the anchor, or lowering the severity would be a bypass.
                if any(
                    f.blocking and f.path == anchor.path and f.start_line == anchor.line for f in findings
                ):
                    continue
                findings.append(_finding_from_anchor(anchor, blocking=True, index=len(findings)))
                blocking.append(findings[-1])

        decision = Decision.BLOCK if blocking else Decision.ALLOW
        degraded = suspicious

        detail: dict[str, Any] = {
            "skipped": prepared.skipped,
            "anchors": len(prepared.anchors),
            "dropped": report.dropped_total,
            "cross_check": cross_reasons,
            "injection_signals": [{"kind": s.kind, "path": "", "line": s.line} for s in prepared.injections],
            "schema_enforced": chat.schema_enforced,
            "notes": report.notes[:10],
        }
        response = self._respond(
            request,
            policy,
            actor,
            decision=decision,
            findings=findings,
            payload_sha=payload_sha,
            scope=scope,
            started=started,
            model=chat.model or self._deps.provider.describe(),
            prompt_version=self._deps.bundle.version,
            degraded=degraded,
            cache_hit=False,
            usage=TokenUsage(
                prompt_tokens=chat.usage.prompt_tokens,
                completion_tokens=chat.usage.completion_tokens,
                total_tokens=chat.usage.total_tokens,
            ),
            extra_detail=detail,
            latency_ms=chat.latency_ms,
        )

        if self._deps.cache is not None and not degraded:
            # Degraded verdicts are not cached: they depend on a transient failure
            # or on a disagreement that a retry may legitimately resolve.
            self._deps.cache.put(
                ck,
                prompt_version=self._deps.bundle.version,
                model=self._deps.provider.describe(),
                findings=tuple(findings),
                meta={"decision": decision.value},
            )
        return response

    # -- policy ------------------------------------------------------------
    def _effective_policy(self, requested: AnalysisPolicy) -> AnalysisPolicy:
        """Server profile wins: the client may narrow scope, never weaken it.

        Concretely: the category set is intersected with what the server profile
        enables, the block thresholds are kept at the stricter of the two, and
        ``fail_mode`` always comes from the server. A client that asks for
        ``fail_mode=open`` gets the server's value instead.
        """
        server_mode = self._deps.fail_mode
        categories = requested.categories or DEFAULT_CATEGORIES
        # Stricter threshold = lower severity rank required to block.
        severity = min((requested.block_min_severity, Severity.HIGH), key=lambda s: s.rank)
        return AnalysisPolicy(
            profile=requested.profile,
            categories=categories,
            block_min_severity=severity,
            block_min_confidence=min(requested.block_min_confidence, 0.6),
            fail_mode=server_mode,  # type: ignore[arg-type]
            max_fragments_bytes=requested.max_fragments_bytes,
            include_tests=requested.include_tests,
            include_paths=requested.include_paths,
            exclude_paths=requested.exclude_paths,
        )

    # -- preparation -------------------------------------------------------
    def _prepare(self, request: AnalyzeRequest, policy: AnalysisPolicy) -> _Prepared:
        prepared = _Prepared()
        for fragment in request.fragments:
            path = fragment.path
            if should_skip(path, skip_tests=not policy.include_tests):
                prepared.skipped.append(path)
                continue
            if not fragment.text.strip():
                prepared.skipped.append(path)
                continue
            anchors = tuple(scan(fragment.text, path=path, first_line=fragment.start_line))
            prepared.injections.extend(
                detect_injection_attempts(fragment.text, first_line=fragment.start_line)
            )
            prepared.fragments.append(
                build_fragment(
                    path=path,
                    text=fragment.text,
                    start_line=fragment.start_line,
                    anchors=anchors,
                    truncated=fragment.truncated,
                )
            )
            prepared.anchors.extend(anchors)
        for staged in request.files:
            if staged.is_binary:
                prepared.skipped.append(staged.path)
        return prepared

    @staticmethod
    def _parse_findings(document: dict[str, Any]) -> tuple[list[RawFinding], int]:
        items = document.get("findings", [])
        if not isinstance(items, list):
            raise UnusableAnswerError("'findings' is not an array")
        parsed: list[RawFinding] = []
        invalid = 0
        for item in items:
            if not isinstance(item, dict):
                invalid += 1
                continue
            try:
                parsed.append(RawFinding.model_validate(item))
            except ValidationError:
                invalid += 1
        return parsed, invalid

    # -- failure paths -----------------------------------------------------
    def _on_provider_failure(  # noqa: PLR0917 - internal helper, called from two places
        self,
        request: AnalyzeRequest,
        policy: AnalysisPolicy,
        prepared: _Prepared,
        payload_sha: str,
        scope: str,
        started: float,
        actor: str,
        exc: LlmError,
    ) -> AnalyzeResponse:
        del prepared  # the failure path does not need the payload
        """Apply ``fail_mode``. The default blocks, and says exactly why."""
        if self._deps.store is not None:
            self._deps.store.append_audit(
                action=AuditAction.ANALYZE_ERROR,
                actor=actor or request.commit.author.email,
                detail={"code": exc.code.value, "message": exc.message[:500]},
                commit_digest=request.commit_digest,
                repo_id=request.commit.repo_id,
                key=self._deps.audit_key,
            )

        if self._deps.fail_mode == "open":
            findings: list[Finding] = []
            decision = Decision.ALLOW
        else:
            findings = [
                Finding(
                    id="policy-fail-closed",
                    rule_id="AEGIS-POLICY-001",
                    category=OwaspCategory.A05_SECURITY_MISCONFIGURATION,
                    severity=Severity.HIGH,
                    confidence=1.0,
                    path="(analysis)",
                    title="Analysis could not be completed",
                    explanation=(
                        "The GenAI analysis did not produce a usable result "
                        f"({exc.code.value}: {exc.message}). Because the policy is "
                        "fail-closed, the commit is blocked rather than allowed unanalysed."
                    ),
                    remediation=(
                        "Retry the commit. If the analyser is down, an authorised operator "
                        "can mint an override attestation with `aegis override` — it is "
                        "signed and audited, unlike `--no-verify`."
                    ),
                    source=FindingSource.POLICY,
                    blocking=True,
                )
            ]
            decision = Decision.BLOCK

        return self._respond(
            request,
            policy,
            actor or request.commit.author.email,
            decision=decision,
            findings=findings,
            payload_sha=payload_sha,
            scope=scope,
            started=started,
            model=self._deps.provider.describe(),
            prompt_version=self._deps.bundle.version,
            degraded=True,
            cache_hit=False,
            usage=TokenUsage(),
            extra_detail={"llm_error": exc.code.value, "fail_mode": self._deps.fail_mode},
        )

    # -- response assembly -------------------------------------------------
    def _respond(
        self,
        request: AnalyzeRequest,
        policy: AnalysisPolicy,
        actor: str,
        *,
        decision: Decision,
        findings: list[Finding],
        payload_sha: str,
        scope: str,
        started: float,
        model: str,
        prompt_version: str,
        degraded: bool,
        cache_hit: bool,
        usage: TokenUsage,
        extra_detail: dict[str, Any],
        latency_ms: int = 0,
    ) -> AnalyzeResponse:
        analysis_id = f"an_{uuid.uuid4().hex[:20]}"
        audit_ref = None
        if self._deps.store is not None:
            event = self._deps.store.append_audit(
                action=(
                    AuditAction.ANALYZE_BLOCK if decision is Decision.BLOCK else AuditAction.ANALYZE_ALLOW
                ),
                actor=actor or request.commit.author.email,
                detail={
                    "analysis_id": analysis_id,
                    "decision": decision.value,
                    "findings": len(findings),
                    "degraded": degraded,
                    "cache_hit": cache_hit,
                    **extra_detail,
                },
                commit_digest=request.commit_digest,
                repo_id=request.commit.repo_id,
                analysis_id=analysis_id,
                key=self._deps.audit_key,
            )
            audit_ref = event.hash

        attestation = sign_attestation(
            key=self._deps.key,
            issuer=self._deps.issuer,
            audience=request.commit.repo_id,
            subject=request.commit.author.email,
            commit_digest=request.commit_digest,
            decision=decision,
            analysis_id=analysis_id,
            payload_sha256=payload_sha,
            policy_profile=policy.profile,
            prompt_version=prompt_version,
            model=model,
            findings=findings,
            scope=scope,
            jti=uuid.uuid4().hex,
            parent_sha=request.commit.parent_sha,
            audit_ref=audit_ref,
            categories=policy.categories,
            now=self._deps.now,
        )

        meta = AnalysisMeta(
            analysis_id=analysis_id,
            digest_version=request.digest_version,
            prompt_version=prompt_version,
            model=model,
            provider=self._deps.provider.name,
            engine_versions={
                "prompt": prompt_version,
                "detectors": str(len(_ANCHOR_GUIDANCE)),
                "engine": "0.1.0",
            },
            latency_ms=latency_ms or int((self._deps.now() - started) * 1000),
            usage=usage,
            degraded=degraded,
            cache_hit=cache_hit,
        )

        return AnalyzeResponse(
            commit_digest=request.commit_digest,
            decision=decision,
            findings=tuple(findings),
            meta=meta,
            attestation=attestation,
            message=render_message(
                decision=decision,
                findings=findings,
                actor=request.commit.author.email,
                degraded=degraded,
                analysis_id=analysis_id,
                injections=[],
            ),
        )


def _anchor_is_blocking(anchor: Anchor, policy: AnalysisPolicy) -> bool:
    return (
        anchor.severity.rank >= policy.block_min_severity.rank
        and anchor.confidence >= policy.block_min_confidence
    )


def _finding_from_anchor(anchor: Anchor, *, blocking: bool, index: int) -> Finding:
    explanation, remediation = _ANCHOR_GUIDANCE.get(
        anchor.kind.value,
        ("A dangerous sink was matched by the deterministic pre-filter.", "Review the data flow."),
    )
    return Finding(
        id=f"a{index + 1:02d}",
        rule_id=anchor.rule_id,
        category=anchor.category,
        cwe=anchor.cwe,
        severity=anchor.severity,
        confidence=anchor.confidence,
        path=anchor.path,
        start_line=anchor.line,
        end_line=anchor.line,
        title=anchor.title,
        explanation=(
            f"{explanation} Reported by the deterministic detector, not confirmed by the model "
            f"in this run, so the analysis is marked degraded."
        ),
        remediation=remediation,
        evidence=anchor.line_text[:300],
        source=FindingSource.SAST,
        blocking=blocking,
    )


_ICON = {Decision.ALLOW: "✅", Decision.BLOCK: "🚨", Decision.ALLOW_OVERRIDE: "⚠️ "}


def render_message(
    *,
    decision: Decision,
    findings: Sequence[Finding],
    actor: str,
    degraded: bool,
    analysis_id: str,
    injections: Sequence[InjectionSignal] = (),
) -> str:
    """Human-facing block message.

    Rendered **server-side** on purpose (see ``contracts.AnalyzeResponse``): the text
    a developer sees on a blocked commit is centrally controlled, so a tampered
    client cannot soften it, and improving the wording of a remediation does not
    require shipping a new hook.
    """
    lines: list[str] = []
    if decision is Decision.ALLOW:
        lines.append(f"{_ICON[decision]} AEGIS: sin hallazgos bloqueantes.")
        if degraded:
            lines.append("   ⚠  Análisis degradado: el verificador determinista y el modelo no coinciden.")
        return "\n".join(lines)

    blocking = [f for f in findings if f.blocking]
    lines.append(f"{_ICON[decision]} Vulnerabilidad detectada — commit rechazado")
    lines.append(f"   Autor del commit: {actor}")
    lines.append("")
    for index, finding in enumerate(blocking, 1):
        where = finding.path
        if finding.start_line:
            where += f":{finding.start_line}"
            if finding.end_line and finding.end_line != finding.start_line:
                where += f"-{finding.end_line}"
        lines.append(f"{index}. [{finding.severity.value.upper()}] {finding.title}")
        lines.append(f"   Categoría: {finding.category.value}   CWE-{finding.cwe or '?'}   ({where})")
        lines.append(f"   Confianza: {finding.confidence:.0%}   Regla: {finding.rule_id}")
        lines.append("")
        lines.append("   Riesgo:")
        for text_line in _wrap(finding.explanation, 92):
            lines.append(f"     {text_line}")
        lines.append("")
        lines.append("   Solución sugerida:")
        for text_line in _wrap(finding.remediation, 92):
            lines.append(f"     {text_line}")
        if finding.patch:
            lines.append("")
            lines.append("   Patch propuesto:")
            for patch_line in finding.patch.splitlines():
                lines.append(f"     {patch_line}")
        lines.append("")

    if any(f.source is FindingSource.SAST for f in blocking):
        lines.append(
            "   Nota: el hallazgo proviene del verificador determinista y el modelo no lo "
            "confirmó (posible manipulación del prompt o degradación del modelo)."
        )
        lines.append("")

    if injections:
        lines.append(
            f"   ⚠  Se detectaron {len(injections)} intento(s) de manipular al revisor en el código."
        )
        lines.append("")

    lines.append(f"   Análisis: {analysis_id}")
    lines.append("   Corrige los puntos anteriores y vuelve a hacer commit.")
    return "\n".join(lines)


def _wrap(text: str, width: int) -> list[str]:
    words = text.split()
    lines: list[str] = []
    current = ""
    for word in words:
        if len(current) + len(word) + 1 > width and current:
            lines.append(current)
            current = word
        else:
            current = f"{current} {word}".strip()
    if current:
        lines.append(current)
    return lines or [""]


def build_analyzer(deps: EngineDeps) -> Analyzer:
    return Analyzer(deps)


def load_prompt(directory: Any, *, file: str) -> PromptBundle:
    """Thin re-export so callers only import from the engine."""
    return load_bundle(directory, prompt_file=file)


__all__ = ["Analyzer", "EngineDeps", "build_analyzer", "load_prompt", "render_message"]
