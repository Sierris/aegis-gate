"""Frozen wire contract between the AEGIS client (git hook / CLI) and server.

Design rules that this module enforces
--------------------------------------
1. **One definition, two consumers.** The hook and the API import these same
   models. A field renamed on one side is a *type error at build time*, not a
   silent ``KeyError`` inside a developer's terminal at 2 a.m.
2. **``extra="forbid"``.** Unknown fields are rejected. This blocks a class of
   privilege-escalation-by-extra-field bugs (``{"policy": {...}, "skip_scan":
   true}``) and makes version skew loud instead of invisible.
3. **``frozen=True``.** Models are value objects; nothing in the request path is
   allowed to mutate an authenticated payload after it was validated.
4. **``schema_version`` is mandatory.** The server refuses unknown versions, so
   an old hook can never be tricked into consuming a new response shape.
5. **Enums, not free strings.** Detection categories, severities and decisions
   are closed sets. The LLM must land inside them (see the prompt contract in
   ``docs/architecture.md``); arbitrary strings from a model output are a
   prompt-injection foothold.

Versioning policy: additive optional fields with defaults are non-breaking;
anything else bumps ``SCHEMA_VERSION`` and the server serves both for one
release window.
"""

from __future__ import annotations

import enum
from datetime import UTC, datetime
from typing import Annotated, Literal

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    StringConstraints,
    field_validator,
    model_validator,
)

from aegis import canon

#: Bumped only on breaking changes. The server rejects other values.
SCHEMA_VERSION: Literal["1"] = "1"

#: Digest format this build produces/consumes. Kept separate from the schema
#: version because a digest change invalidates *historical attestations*, which
#: is a much bigger deal than a field rename.
# The value is imported (not duplicated) and its Literal type is enforced by
# mypy, so the two declarations can never drift apart.
DIGEST_VERSION: Literal["aegis-digest/v1"] = canon.DIGEST_VERSION

Sha256Hex = Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{64}$")]
GitSha = Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{40}$")]
GitFileMode = Annotated[str, StringConstraints(pattern=r"^(100644|100755|120000|160000|40000)$")]
Nonce = Annotated[str, StringConstraints(min_length=16, max_length=128)]


class StrictModel(BaseModel):
    """Base for every wire model: immutable, closed, round-trip safe."""

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        populate_by_name=True,
        str_strip_whitespace=False,
        validate_assignment=False,
    )


# --------------------------------------------------------------------------- #
# Enumerations
# --------------------------------------------------------------------------- #
class OwaspCategory(enum.StrEnum):
    """OWASP Top 10 — 2021. The full list is modelled so a policy can enable any
    subset; the shipped default profile (/docs/architecture.md#cobertura) covers
    four of them, above the three-category minimum of the challenge.
    """

    A01_BROKEN_ACCESS_CONTROL = "A01:2021"
    A02_CRYPTOGRAPHIC_FAILURES = "A02:2021"
    A03_INJECTION = "A03:2021"
    A04_INSECURE_DESIGN = "A04:2021"
    A05_SECURITY_MISCONFIGURATION = "A05:2021"
    A06_VULNERABLE_COMPONENTS = "A06:2021"
    A07_IDENTIFICATION_AUTH_FAILURES = "A07:2021"
    A08_SOFTWARE_DATA_INTEGRITY_FAILURES = "A08:2021"
    A09_SECURITY_LOGGING_MONITORING_FAILURES = "A09:2021"
    A10_SSRF = "A10:2021"


class Severity(enum.StrEnum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        """Numeric rank so policies can express ``>= high``."""
        return _SEVERITY_RANK[self]


_SEVERITY_RANK: dict[Severity, int] = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


class ChangeKind(enum.StrEnum):
    """Git change kind, as a closed set (mirrors ``git diff --diff-filter``)."""

    ADDED = "A"
    MODIFIED = "M"
    DELETED = "D"
    RENAMED = "R"
    MODE_CHANGED = "T"


class Decision(enum.StrEnum):
    """Terminal verdict of one analysis run.

    ``ALLOW_OVERRIDE`` is *not* a bypass of the control: it is an attestation
    minted by the server after a second identity approved the finding
    (break-glass flow, see architecture doc). It exists so that the escape hatch
    is authenticated, attributed and auditable instead of being ``--no-verify``.
    """

    ALLOW = "allow"
    BLOCK = "block"
    ALLOW_OVERRIDE = "allow_override"


class FindingSource(enum.StrEnum):
    """Provenance of a finding. Kept explicit so a report can separate
    deterministic evidence from model inference — they have different trust
    levels and different false-positive profiles.
    """

    LLM = "llm"
    SAST = "sast"  # deterministic prefilter (semgrep/bandit rules)
    HEURISTIC = "heuristic"  # secret/entropy/pattern scanners
    POLICY = "policy"  # generated by the policy engine itself


# --------------------------------------------------------------------------- #
# Commit description (the "what am I about to commit" half of the digest)
# --------------------------------------------------------------------------- #
class Identity(StrictModel):
    """A git identity. E-mail is the accountability anchor."""

    name: str = Field(min_length=1, max_length=256)
    email: str = Field(min_length=3, max_length=320)

    @field_validator("email")
    @classmethod
    def _lower(cls, v: str) -> str:
        return canon.normalize_identity("x", v)[1]

    @field_validator("name")
    @classmethod
    def _clean(cls, v: str) -> str:
        return canon.normalize_identity(v, "x@x")[0] or v


class CommitRef(StrictModel):
    """Everything that identifies the commit independently of its diff.

    ``parent_sha`` is ``None`` for a root commit. Note that the *commit object*
    does not exist yet at pre-commit time — the client reports HEAD as the
    future parent, and the verifier checks that relationship against the real
    commit graph.
    """

    repo_id: str = Field(min_length=3, max_length=512)
    ref: str = Field(min_length=1, max_length=1024)
    parent_sha: GitSha | None = None
    author: Identity
    committer: Identity
    message_sha256: Sha256Hex
    subject: str | None = Field(default=None, max_length=200)
    is_merge_commit: bool = False
    is_amend: bool = False
    #: Informational only — never part of the digest.
    branch: str | None = Field(default=None, max_length=1024)

    @field_validator("repo_id")
    @classmethod
    def _repo(cls, v: str) -> str:
        return canon.normalize_repo_id(v)


class StagedFile(StrictModel):
    """One path in the staged set, described by git object data only.

    ``blob_sha256`` is the SHA-256 of the staged blob *content* (not git's own
    SHA-1/256 object id). We recompute our own hash so the digest does not depend
    on the repository's object format.
    """

    path: str = Field(min_length=1, max_length=4096)
    old_path: str | None = Field(default=None, max_length=4096)
    mode: GitFileMode = "100644"
    change: ChangeKind
    blob_sha256: Sha256Hex | None = None
    size_bytes: int = Field(default=0, ge=0)
    language: str | None = Field(default=None, max_length=64)
    is_binary: bool = False

    @field_validator("path")
    @classmethod
    def _p(cls, v: str) -> str:
        return canon.normalize_path(v)

    @field_validator("old_path")
    @classmethod
    def _op(cls, v: str | None) -> str | None:
        return canon.normalize_path(v) if v else None

    @model_validator(mode="after")
    def _consistent(self) -> StagedFile:
        if self.change is ChangeKind.DELETED:
            if self.blob_sha256 is not None:
                # A deletion has no post-image; accepting a blob here would let a
                # client "prove" content that never gets committed.
                raise ValueError("deleted file must not carry blob_sha256")
        elif self.blob_sha256 is None:
            raise ValueError(f"{self.change.value} file requires blob_sha256")
        if self.change is ChangeKind.RENAMED and not self.old_path:
            raise ValueError("renamed file requires old_path")
        if self.change is not ChangeKind.RENAMED and self.old_path:
            raise ValueError("old_path only valid for renames")
        return self


class CodeFragment(StrictModel):
    """A contiguous slice of a file, exactly as it will be shown to the model.

    Fragments are what the LLM actually sees, so they carry their own digest:
    ``payload_sha256`` in the attestation commits to this precise set of texts.
    Hunk extraction happens client-side (we only ship changed regions + a few
    lines of context) to keep token cost and data egress minimal — the blob
    hashes in ``StagedFile`` remain the ground truth for the *whole* file.
    """

    path: str = Field(min_length=1, max_length=4096)
    start_line: int = Field(ge=1)
    end_line: int = Field(ge=1)
    text: str = Field(max_length=200_000)
    content_sha256: Sha256Hex
    truncated: bool = False

    @field_validator("path")
    @classmethod
    def _p(cls, v: str) -> str:
        return canon.normalize_path(v)

    @model_validator(mode="after")
    def _range(self) -> CodeFragment:
        if self.end_line < self.start_line:
            raise ValueError("end_line < start_line")
        if canon.sha256_text(self.text) != self.content_sha256:
            raise ValueError("content_sha256 does not match text")
        return self


# --------------------------------------------------------------------------- #
# Policy
# --------------------------------------------------------------------------- #
#: Categories enabled by the shipped default profile. Four, deliberately: the
#: challenge requires three, and these four are the ones where an LLM adds real
#: value over a regex linter (they need data-flow reasoning, not pattern match).
DEFAULT_CATEGORIES: tuple[OwaspCategory, ...] = (
    OwaspCategory.A01_BROKEN_ACCESS_CONTROL,
    OwaspCategory.A02_CRYPTOGRAPHIC_FAILURES,
    OwaspCategory.A03_INJECTION,
    OwaspCategory.A10_SSRF,
)


class AnalysisPolicy(StrictModel):
    """Client-visible policy. The client may *request* a profile but cannot
    weaken the effective one: the server intersects the request with the profile
    stored server-side (``policy_profiles.yaml``), and records both in the audit
    log. ``requested_profile`` is therefore advisory and logged for anomaly
    detection ("who keeps asking for a weaker profile?").
    """

    profile: str = Field(default="owasp-core", max_length=64)
    categories: tuple[OwaspCategory, ...] = DEFAULT_CATEGORIES
    block_min_severity: Severity = Severity.HIGH
    block_min_confidence: float = Field(default=0.6, ge=0.0, le=1.0)
    fail_mode: Literal["closed", "open"] = "closed"
    max_fragments_bytes: int = Field(default=400_000, ge=1024)
    include_tests: bool = True
    include_paths: tuple[str, ...] = ()
    exclude_paths: tuple[str, ...] = ()

    @field_validator("categories")
    @classmethod
    def _non_empty(cls, v: tuple[OwaspCategory, ...]) -> tuple[OwaspCategory, ...]:
        if not v:
            raise ValueError("at least one OWASP category must be enabled")
        return tuple(dict.fromkeys(v))  # dedupe, keep order


# --------------------------------------------------------------------------- #
# Request
# --------------------------------------------------------------------------- #
class ClientInfo(StrictModel):
    """Hook fingerprint. Used for version-skew detection and for alerting when
    hooks are outdated (an old hook is an evasion vector: it may not compute the
    current digest version).
    """

    name: str = Field(default="aegis-hook", max_length=64)
    version: str = Field(max_length=32)
    os: str = Field(max_length=64)
    python: str = Field(max_length=32)
    git_version: str | None = Field(default=None, max_length=64)
    #: Client-generated random per analysis. The server rejects a nonce it has
    #: seen before for the same user, which defeats replaying a cached "allow".
    nonce: Nonce


class AnalyzeRequest(StrictModel):
    """``POST /v1/analyze`` body.

    The client sends the *staged* state, never working-tree mutations, because
    the index is what becomes the commit.
    """

    schema_version: Literal["1"] = SCHEMA_VERSION
    digest_version: Literal["aegis-digest/v1"] = DIGEST_VERSION
    commit_digest: Sha256Hex
    commit: CommitRef
    files: tuple[StagedFile, ...] = ()
    fragments: tuple[CodeFragment, ...] = ()
    policy: AnalysisPolicy = AnalysisPolicy()
    client: ClientInfo
    requested_at: datetime = Field(default_factory=lambda: datetime.now(UTC))

    @model_validator(mode="after")
    def _digests_match(self) -> AnalyzeRequest:
        """Fail fast when the client's digest is not derivable from its payload.

        This is a self-consistency check, not a security boundary: the server
        recomputes the digest from the *payload* and later re-derives it from the
        *pushed commit*. Doing it here means a buggy hook errors out locally,
        before it burns a token or writes a bogus audit record.
        """
        expected = canon.compute_commit_digest(
            version=self.digest_version,
            repo_id=self.commit.repo_id,
            parent_sha=self.commit.parent_sha,
            author_email=self.commit.author.email,
            message_sha256=self.commit.message_sha256,
            entries=[(f.change.value, f.mode, f.blob_sha256, f.path, f.old_path) for f in self.files],
        )
        if expected != self.commit_digest:
            raise ValueError(
                f"commit_digest mismatch: request declares {self.commit_digest}, payload yields {expected}"
            )
        # Bound the analysis input by the same limits the server enforces.
        if sum(s.size_bytes for s in self.files) > self.policy.max_fragments_bytes:
            raise ValueError("staged content exceeds policy.max_fragments_bytes")
        return self

    @property
    def payload_sha256(self) -> str:
        """Digest of the exact fragments sent to the model (for the attestation)."""
        return canon.fragments_digest([(f.path, f.text, f.start_line, f.end_line) for f in self.fragments])


# --------------------------------------------------------------------------- #
# Findings & response
# --------------------------------------------------------------------------- #
class Finding(StrictModel):
    """A single reported issue.

    ``evidence`` and the line range are **mandatory for blocking findings**:
    every finding the model produces is checked against the payload, and a
    finding that points at a path/line the model was never shown is discarded.
    That single rule kills the most common LLM-injection outcome ("report a fake
    finding" or "invent a line") and most hallucinated findings.
    """

    id: str = Field(max_length=64)
    rule_id: str = Field(max_length=64)
    category: OwaspCategory
    cwe: int | None = Field(default=None, ge=1, le=1200)
    severity: Severity
    confidence: float = Field(ge=0.0, le=1.0)
    path: str
    start_line: int | None = Field(default=None, ge=1)
    end_line: int | None = Field(default=None, ge=1)
    title: str = Field(min_length=1, max_length=200)
    explanation: str = Field(min_length=1, max_length=4000)
    remediation: str = Field(min_length=1, max_length=4000)
    patch: str | None = Field(default=None, max_length=8000)
    evidence: str | None = Field(default=None, max_length=2000)
    source: FindingSource = FindingSource.LLM
    blocking: bool = False

    @field_validator("path")
    @classmethod
    def _p(cls, v: str) -> str:
        return canon.normalize_path(v)


class TokenUsage(StrictModel):
    prompt_tokens: int = Field(default=0, ge=0)
    completion_tokens: int = Field(default=0, ge=0)
    total_tokens: int = Field(default=0, ge=0)
    cost_usd: float | None = Field(default=None, ge=0.0)


class AnalysisMeta(StrictModel):
    """Provenance of the analysis. Every field here is also mirrored into the
    attestation, so a finding can be explained months later: which prompt
    version, which model, which detectors, how long it took.
    """

    analysis_id: str = Field(max_length=64)
    digest_version: str
    prompt_version: str = Field(max_length=64)
    model: str = Field(max_length=128)
    provider: str = Field(max_length=64)
    engine_versions: dict[str, str] = Field(default_factory=dict)
    latency_ms: int = Field(default=0, ge=0)
    usage: TokenUsage = TokenUsage()
    #: True when a detector failed and the configured ``fail_mode`` decided the
    #: outcome. Surfaced to the developer so a "block" is never unexplained.
    degraded: bool = False
    cache_hit: bool = False
    #: True when the model's raw output failed schema validation and had to be
    #: repaired/retried. A rising rate here is an injection or prompt-drift signal.
    output_repaired: bool = False


class AnalyzeResponse(StrictModel):
    """``POST /v1/analyze`` response. The human-readable part (``message``)
    is rendered by the server, not the client, so block messages and remediation
    text are centrally controlled and cannot be spoofed by a tampered hook.
    """

    schema_version: Literal["1"] = SCHEMA_VERSION
    commit_digest: Sha256Hex
    decision: Decision
    findings: tuple[Finding, ...] = ()
    meta: AnalysisMeta
    #: Compact JWS (EdDSA). Self-contained proof of the verdict; the hook stores
    #: it as a git note and CI verifies it without calling the server.
    attestation: str = Field(min_length=32)
    message: str = Field(default="", max_length=8000)
    override_token: str | None = Field(default=None, max_length=4096)


# --------------------------------------------------------------------------- #
# Attestation (the integrity artefact)
# --------------------------------------------------------------------------- #
class AttestationClaims(StrictModel):
    """JWS payload proving *who* ran *which* analysis over *which* bytes.

    Verification contract (see ``aegis.attest.verify`` in a later step):

    1. signature validates against the server public key (``kid`` selects it);
    2. ``aud`` equals the normalised repo id being verified;
    3. ``iss`` equals the configured server issuer;
    4. ``iat``/``nbf``/``exp`` are within the accepted skew;
    5. ``commit_digest`` recomputed from the pushed commit object matches;
    6. ``commit_sha`` — when present — matches the commit being verified. It is
       absent for pre-commit attestations (the object does not exist yet) and
       filled in by the server when it later binds the attestation to the real
       commit at push/CI time;
    7. ``decision`` is ``allow``/``allow_override``;
    8. ``payload_sha256`` matches the fragments the server records for that
       analysis (defends against "analysed a subset" downgrade).
    """

    iss: str = Field(max_length=256)
    sub: str = Field(max_length=320)
    aud: str = Field(max_length=512)
    iat: int = Field(ge=0)
    nbf: int | None = Field(default=None, ge=0)
    exp: int = Field(ge=0)
    jti: str = Field(max_length=64)

    commit_digest: Sha256Hex
    commit_sha: GitSha | None = None
    parent_sha: GitSha | None = None

    decision: Decision
    analysis_id: str = Field(max_length=64)
    payload_sha256: Sha256Hex

    policy_profile: str = Field(max_length=64)
    prompt_version: str = Field(max_length=64)
    model: str = Field(max_length=128)
    findings_count: int = Field(ge=0)
    #: Digest over the full findings array. Lets a consumer prove the findings it
    #: displays are the ones the server produced, without shipping them in the JWS.
    findings_sha256: Sha256Hex
    severity_max: Severity = Severity.INFO
    #: Opaque reference to the audit record (hash-chain link) for this analysis.
    audit_ref: Sha256Hex | None = None
    #: Set when a plain ``allow`` attestation was re-issued as ``allow_override``
    #: after a second-identity approval.
    approver: str | None = Field(default=None, max_length=320)
    #: Space-separated capabilities, mirrors the OAuth scope that authorised the
    #: analysis. A token minted for ``analyze`` must not be usable to ``override``.
    scope: str = Field(default="analyze", max_length=128)

    @field_validator("aud")
    @classmethod
    def _aud(cls, v: str) -> str:
        return canon.normalize_repo_id(v)

    @model_validator(mode="after")
    def _time(self) -> AttestationClaims:
        if self.exp <= self.iat:
            raise ValueError("exp must be greater than iat")
        if self.nbf is not None and self.nbf > self.iat:
            raise ValueError("nbf must not be in the future relative to iat")
        return self


class JwkPublicKey(StrictModel):
    """Public signing key, as published on ``GET /v1/keys`` (JWKS entry)."""

    kty: Literal["OKP"] = "OKP"
    crv: Literal["Ed25519"] = "Ed25519"
    x: str
    kid: str
    use: Literal["sig"] = "sig"
    alg: Literal["EdDSA"] = "EdDSA"
    not_before: datetime | None = None
    not_after: datetime | None = None


# --------------------------------------------------------------------------- #
# Verification (CI / pre-push / auditor)
# --------------------------------------------------------------------------- #
class VerifyReason(enum.StrEnum):
    """Machine-readable reasons. CI policy and alerting key off these, never off
    free-text messages (which drift and get reworded).
    """

    OK = "ok"
    MISSING_ATTESTATION = "missing_attestation"
    BAD_SIGNATURE = "bad_signature"
    DIGEST_MISMATCH = "digest_mismatch"
    WRONG_AUDIENCE = "wrong_audience"
    EXPIRED = "expired"
    NOT_YET_VALID = "not_yet_valid"
    ISSUER_MISMATCH = "issuer_mismatch"
    DECISION_BLOCK = "decision_block"
    PAYLOAD_MISMATCH = "payload_mismatch"
    UNKNOWN_KEY = "unknown_key"
    SCHEMA_UNSUPPORTED = "schema_unsupported"
    MERGE_COMMIT_SKIPPED = "merge_commit_skipped"
    UNVERIFIED_LOCAL = "unverified_local"


class CommitVerification(StrictModel):
    """Result for one commit in a push/PR. ``ok`` is the only thing CI branches on."""

    commit_sha: GitSha
    ok: bool
    reason: VerifyReason
    detail: str = Field(default="", max_length=2000)
    claims: AttestationClaims | None = None


class VerifyBatchRequest(StrictModel):
    """``POST /v1/verify`` body used by CI when it wants the server's opinion
    (network available). Offline CI verifies the JWS locally with the public key
    and produces the same shape.
    """

    schema_version: Literal["1"] = SCHEMA_VERSION
    repo_id: str
    commits: tuple[GitSha, ...] = Field(min_length=1, max_length=250)
    require_attestation: bool = True

    @field_validator("repo_id")
    @classmethod
    def _repo(cls, v: str) -> str:
        return canon.normalize_repo_id(v)


class VerifyBatchResponse(StrictModel):
    schema_version: Literal["1"] = SCHEMA_VERSION
    repo_id: str
    results: tuple[CommitVerification, ...] = ()
    #: ``all(ok)`` for convenience, but computed server-side so CI cannot get it
    #: wrong by iterating partially.
    all_ok: bool = False
    checked_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


# --------------------------------------------------------------------------- #
# Auth (OAuth 2.0 Device Authorization Grant, RFC 8628)
# --------------------------------------------------------------------------- #
class DeviceAuthorizationRequest(StrictModel):
    client_id: str = Field(max_length=128)
    scope: str = Field(default="analyze", max_length=128)


class DeviceAuthorizationResponse(StrictModel):
    """Device flow step 1. Chosen over a browser redirect because the hook runs in
    a terminal, often over SSH, and cannot receive a ``redirect_uri`` callback.
    """

    device_code: str
    user_code: str
    verification_uri: str
    verification_uri_complete: str | None = None
    expires_in: int = Field(ge=1)
    interval: int = Field(default=5, ge=1)


class TokenRequest(StrictModel):
    grant_type: Literal["urn:ietf:params:oauth:grant-type:device_code"] = (
        "urn:ietf:params:oauth:grant-type:device_code"
    )
    device_code: str
    client_id: str


class TokenResponse(StrictModel):
    access_token: str
    # "Bearer" is an OAuth token *type* (RFC 6750), not a credential.
    token_type: Literal["Bearer"] = "Bearer"  # noqa: S105
    expires_in: int = Field(ge=1)
    refresh_token: str | None = None
    scope: str = "analyze"


class UserInfo(StrictModel):
    """``GET /v1/userinfo`` — the accountability anchor surfaced in the block
    message ("blocked for juan.sierra@…") and in every audit row."""

    sub: str = Field(max_length=320)
    email: str
    name: str | None = None
    provider: str = Field(max_length=64)
    scopes: tuple[str, ...] = ()


# --------------------------------------------------------------------------- #
# Audit
# --------------------------------------------------------------------------- #
class AuditAction(enum.StrEnum):
    ANALYZE_ALLOW = "analyze.allow"
    ANALYZE_BLOCK = "analyze.block"
    ANALYZE_ERROR = "analyze.error"
    OVERRIDE_REQUEST = "override.request"
    OVERRIDE_APPROVE = "override.approve"
    OVERRIDE_DENY = "override.deny"
    PUSH_VERIFIED = "push.verified"
    PUSH_REJECTED = "push.rejected"
    TOKEN_ISSUED = "auth.token_issued"  # noqa: S105 - audit action name
    TOKEN_REVOKED = "auth.token_revoked"  # noqa: S105 - audit action name
    POLICY_CHANGED = "policy.changed"


class AuditEvent(StrictModel):
    """One row of the append-only log (keyed-hash chained, see ``canon.chain_hash``)."""

    seq: int = Field(ge=0)
    ts: datetime = Field(default_factory=lambda: datetime.now(UTC))
    action: AuditAction
    actor: str = Field(max_length=320)
    repo_id: str | None = None
    commit_digest: Sha256Hex | None = None
    analysis_id: str | None = None
    detail: dict[str, object] = Field(default_factory=dict)
    prev_hash: Sha256Hex
    hash: Sha256Hex


__all__ = [
    "DEFAULT_CATEGORIES",
    "DIGEST_VERSION",
    "SCHEMA_VERSION",
    "AnalysisMeta",
    "AnalysisPolicy",
    "AnalyzeRequest",
    "AnalyzeResponse",
    "AttestationClaims",
    "AuditAction",
    "AuditEvent",
    "ChangeKind",
    "ClientInfo",
    "CodeFragment",
    "CommitRef",
    "CommitVerification",
    "Decision",
    "DeviceAuthorizationRequest",
    "DeviceAuthorizationResponse",
    "Finding",
    "FindingSource",
    "GitFileMode",
    "GitSha",
    "Identity",
    "JwkPublicKey",
    "Nonce",
    "OwaspCategory",
    "Severity",
    "Sha256Hex",
    "StagedFile",
    "StrictModel",
    "TokenRequest",
    "TokenResponse",
    "TokenUsage",
    "UserInfo",
    "VerifyBatchRequest",
    "VerifyBatchResponse",
    "VerifyReason",
]
