"""Offline verification of attestations.

Why offline
-----------
The verifier must not depend on the analysis server being up. Concretely: the
enforcement point is CI, the server may be a single VM behind a VPN, and a push
must not be blocked *or* allowed because an unrelated host is unreachable. A JWS
plus a public key is self-contained, so verification needs nothing but the JWKS.

What is checked, in order, and what each check stops
----------------------------------------------------
1. **Header/algorithm allowlist** — ``EdDSA`` only. Same reasoning as access
   tokens: ``alg: none`` and HMAC-with-the-public-key are the two classic forgery
   paths, and an allowlist makes them inexpressible rather than "mitigated".
2. **Signature against the JWKS by ``kid``** — proofs a client cannot mint.
3. **Issuer** — must be *our* server; otherwise any host could sign attestations
   for any repository.
4. **Audience == normalised repo id** — stops the obvious cross-repo replay: an
   attestation minted for a low-security repository cannot be presented as
   covering a commit in a protected one.
5. **Temporal validity** (``exp``/``nbf``/``iat`` against an injected clock) — a
   proof of an analysis performed a year ago is not a proof about today's code
   unless the policy says the TTL covers it.
6. **``commit_digest`` equals the digest recomputed from the commit object** — the
   core claim. Everything else is supporting evidence for this one line.
7. **Decision is an allowing one** — a signed `block` attestation is proof of the
   opposite of permission.
8. **``commit_sha`` when present** — a bound attestation must name the same commit.

Any failure returns a :class:`VerifyReason`; CI policy branches on the enum, never
on message text.
"""

from __future__ import annotations

import json
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import httpx
import jwt
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from aegis.auth.keys import b64url_decode, key_id_from_raw_public
from aegis.contracts import AttestationClaims, CommitVerification, Decision, VerifyReason
from aegis.errors import IntegrityError

Clock = Callable[[], float]

#: The only signature algorithm we accept for attestations.
ALLOWED_ALGORITHM = "EdDSA"

#: Refuse absurdly large tokens before parsing them.
MAX_TOKEN_LENGTH = 8192

#: Decisions that mean "this commit is allowed".
ALLOWING_DECISIONS: frozenset[Decision] = frozenset({Decision.ALLOW, Decision.ALLOW_OVERRIDE})


class Jwks:
    """The set of public keys we trust, indexed by ``kid``.

    Loading is deliberately strict: an entry that is not a 32-byte Ed25519 key is
    rejected rather than skipped, because a silently-empty key set would make every
    verification fail with ``UNKNOWN_KEY`` and look like an outage.
    """

    def __init__(self, keys: dict[str, Ed25519PublicKey]) -> None:
        if not keys:
            raise IntegrityError("the JWKS contains no usable keys")
        self._keys = dict(keys)

    def __len__(self) -> int:
        return len(self._keys)

    def __contains__(self, kid: object) -> bool:
        return kid in self._keys

    @property
    def kids(self) -> tuple[str, ...]:
        return tuple(sorted(self._keys))

    def public_key(self, kid: str) -> Ed25519PublicKey | None:
        return self._keys.get(kid)

    @classmethod
    def from_json(cls, data: object) -> Jwks:
        if not isinstance(data, dict):
            raise IntegrityError("JWKS must be a JSON object")
        entries = data.get("keys")
        if not isinstance(entries, list):
            raise IntegrityError("JWKS has no 'keys' array")
        parsed: dict[str, Ed25519PublicKey] = {}
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            if entry.get("kty") != "OKP" or entry.get("crv") != "Ed25519":
                continue
            kid = entry.get("kid")
            x = entry.get("x")
            if not isinstance(kid, str) or not isinstance(x, str):
                raise IntegrityError("JWKS entry is missing 'kid' or 'x'")
            raw = b64url_decode(x)
            if len(raw) != 32:
                raise IntegrityError(f"JWKS entry {kid!r} is not a 32-byte Ed25519 key")
            expected_kid = key_id_from_raw_public(raw)
            if expected_kid != kid:
                # The kid is derived from the key, so a mismatch means the document
                # was edited or corrupted — and would let two keys claim one id.
                raise IntegrityError(f"JWKS entry {kid!r} does not match its key (expected {expected_kid!r})")
            parsed[kid] = Ed25519PublicKey.from_public_bytes(raw)
        return cls(parsed)

    @classmethod
    def load(cls, source: str | Path) -> Jwks:
        """Load from a file path or an ``http(s)`` URL.

        ``file:`` and plain paths are read from disk so that CI can pin the key
        without any network access — the recommended deployment for a demo, and a
        legitimate choice in production too (a reviewed commit changing the trust
        anchor is easier to audit than an out-of-band fetch).
        """
        text = str(source)
        if text.startswith(("http://", "https://")):
            try:
                response = httpx.get(text, timeout=10.0)
                response.raise_for_status()
            except httpx.HTTPError as exc:
                raise IntegrityError(f"cannot fetch JWKS from {text}: {exc}") from exc
            return cls.from_json(response.json())
        path = Path(text).expanduser()
        try:
            return cls.from_json(json.loads(path.read_text(encoding="utf-8")))
        except OSError as exc:
            raise IntegrityError(f"cannot read JWKS {path}: {exc}") from exc
        except json.JSONDecodeError as exc:
            raise IntegrityError(f"JWKS {path} is not valid JSON: {exc}") from exc


@dataclass(frozen=True, slots=True)
class VerificationFailure:
    """Why verification failed, in the shape CI consumes."""

    reason: VerifyReason
    detail: str


class AttestationVerifier:
    """Verifies one attestation at a time."""

    def __init__(
        self,
        *,
        jwks: Jwks,
        issuer: str,
        leeway_seconds: int = 300,
        now: Clock = time.time,
    ) -> None:
        self._jwks = jwks
        self._issuer = issuer.rstrip("/")
        self._leeway = max(0, leeway_seconds)
        self._now = now

    @property
    def kids(self) -> tuple[str, ...]:
        return self._jwks.kids

    def verify(self, token: str, *, audience: str) -> AttestationClaims:
        """Verify signature and claims. Raises :class:`VerificationError`."""
        if not token or not isinstance(token, str):
            raise VerificationError(VerifyReason.MISSING_ATTESTATION, "no token")
        if len(token) > MAX_TOKEN_LENGTH:
            raise VerificationError(VerifyReason.BAD_SIGNATURE, "token too large")

        try:
            header = jwt.get_unverified_header(token)
        except jwt.PyJWTError as exc:
            raise VerificationError(VerifyReason.BAD_SIGNATURE, f"malformed token: {exc}") from exc

        if header.get("alg") != ALLOWED_ALGORITHM:
            raise VerificationError(
                VerifyReason.BAD_SIGNATURE,
                f"unsupported algorithm {header.get('alg')!r}; only {ALLOWED_ALGORITHM}",
            )
        kid = header.get("kid")
        if not isinstance(kid, str) or not kid:
            raise VerificationError(VerifyReason.BAD_SIGNATURE, "attestation has no kid")
        public_key = self._jwks.public_key(kid)
        if public_key is None:
            raise VerificationError(
                VerifyReason.UNKNOWN_KEY,
                f"kid {kid!r} is not in the trusted key set {self._jwks.kids}",
            )

        try:
            raw = jwt.decode(
                token,
                public_key,
                algorithms=[ALLOWED_ALGORITHM],
                audience=audience,
                issuer=self._issuer,
                leeway=self._leeway,
                options={
                    "require": [
                        "iss",
                        "sub",
                        "aud",
                        "exp",
                        "iat",
                        "jti",
                        "commit_digest",
                        "decision",
                        "analysis_id",
                        "payload_sha256",
                        "prompt_version",
                        "model",
                        "findings_count",
                        "findings_sha256",
                    ],
                    "verify_signature": True,
                    "verify_aud": True,
                    "verify_iss": True,
                    # Time is checked below against the injected clock; see
                    # aegis.auth.jwt for the same reasoning.
                    "verify_exp": False,
                    "verify_nbf": False,
                    "verify_iat": False,
                },
            )
        except jwt.InvalidAudienceError as exc:
            raise VerificationError(
                VerifyReason.WRONG_AUDIENCE,
                f"attestation audience is not {audience!r}",
            ) from exc
        except jwt.InvalidIssuerError as exc:
            raise VerificationError(
                VerifyReason.ISSUER_MISMATCH, f"attestation issuer is not {self._issuer!r}"
            ) from exc
        except jwt.PyJWTError as exc:
            raise VerificationError(VerifyReason.BAD_SIGNATURE, f"signature rejected: {exc}") from exc

        self._check_time(raw)
        try:
            return AttestationClaims.model_validate(raw)
        except ValueError as exc:
            raise VerificationError(
                VerifyReason.SCHEMA_UNSUPPORTED, f"attestation claims are invalid: {exc}"
            ) from exc

    def _check_time(self, raw: dict[str, Any]) -> None:
        now = int(self._now())
        exp = raw.get("exp")
        iat = raw.get("iat")
        nbf = raw.get("nbf", iat)
        if not isinstance(exp, int) or not isinstance(iat, int) or not isinstance(nbf, int):
            raise VerificationError(VerifyReason.SCHEMA_UNSUPPORTED, "exp/iat/nbf must be integers")
        if now >= exp + self._leeway:
            raise VerificationError(
                VerifyReason.EXPIRED,
                f"attestation expired at {exp} (now {now}); re-analysis is required",
            )
        if now + self._leeway < nbf:
            raise VerificationError(
                VerifyReason.NOT_YET_VALID, f"attestation is not valid until {nbf} (now {now})"
            )
        if iat > now + self._leeway:
            raise VerificationError(
                VerifyReason.NOT_YET_VALID, f"attestation was issued in the future ({iat})"
            )


class VerificationError(IntegrityError):
    """Carries the machine-readable reason alongside the message."""

    def __init__(self, reason: VerifyReason, detail: str) -> None:
        super().__init__(detail)
        self.reason = reason
        self.detail = detail


def check_commit(  # noqa: PLR0911 - one return per reason; a table would hide the order
    *,
    verifier: AttestationVerifier,
    note: str | None,
    commit_sha: str,
    commit_digest: str,
    repo_id: str,
    require_attestation: bool = True,
) -> CommitVerification:
    """Turn a note + a recomputed digest into a verifiable statement about a commit.

    Every branch returns a :class:`CommitVerification` instead of raising, because
    the caller (CI, pre-push) must be able to report *all* offending commits in one
    run rather than stopping at the first.
    """
    if note is None:
        return CommitVerification(
            commit_sha=commit_sha,
            ok=not require_attestation,
            reason=(
                VerifyReason.MISSING_ATTESTATION if require_attestation else VerifyReason.UNVERIFIED_LOCAL
            ),
            detail=(
                "no attestation for this commit: it was pushed without the pre-commit "
                "gate (e.g. `git commit --no-verify`)"
                if require_attestation
                else "no attestation (report-only mode)"
            ),
        )

    try:
        payload = json.loads(note)
    except json.JSONDecodeError:
        return CommitVerification(
            commit_sha=commit_sha,
            ok=False,
            reason=VerifyReason.MISSING_ATTESTATION,
            detail="the git note is not valid JSON",
        )
    if not isinstance(payload, dict):
        return CommitVerification(
            commit_sha=commit_sha,
            ok=False,
            reason=VerifyReason.MISSING_ATTESTATION,
            detail="the git note is not a JSON object",
        )

    token = payload.get("attestation")
    if not isinstance(token, str) or not token:
        return CommitVerification(
            commit_sha=commit_sha,
            ok=False,
            reason=VerifyReason.MISSING_ATTESTATION,
            detail="the git note carries no attestation",
        )

    try:
        claims = verifier.verify(token, audience=repo_id)
    except VerificationError as exc:
        return CommitVerification(
            commit_sha=commit_sha,
            ok=False,
            reason=exc.reason,
            detail=exc.detail,
        )

    if claims.commit_digest != commit_digest:
        return CommitVerification(
            commit_sha=commit_sha,
            ok=False,
            reason=VerifyReason.DIGEST_MISMATCH,
            detail=(
                "the attestation covers a different tree: the commit was modified after "
                f"analysis (attested {claims.commit_digest[:16]}…, actual {commit_digest[:16]}…)"
            ),
            claims=claims,
        )

    if claims.commit_sha is not None and claims.commit_sha != commit_sha:
        return CommitVerification(
            commit_sha=commit_sha,
            ok=False,
            reason=VerifyReason.DIGEST_MISMATCH,
            detail=f"the attestation names commit {claims.commit_sha[:12]}, not this one",
            claims=claims,
        )

    if claims.decision not in ALLOWING_DECISIONS:
        return CommitVerification(
            commit_sha=commit_sha,
            ok=False,
            reason=VerifyReason.DECISION_BLOCK,
            detail=f"the attested decision is {claims.decision.value!r}",
            claims=claims,
        )

    return CommitVerification(
        commit_sha=commit_sha,
        ok=True,
        reason=VerifyReason.OK,
        detail=(
            f"verified as {claims.sub} · prompt {claims.prompt_version} · {claims.findings_count} finding(s)"
        ),
        claims=claims,
    )


__all__ = [
    "ALLOWED_ALGORITHM",
    "ALLOWING_DECISIONS",
    "AttestationVerifier",
    "Jwks",
    "VerificationError",
    "check_commit",
]
