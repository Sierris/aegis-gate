"""Signing of commit attestations.

An attestation is a compact JWS over :class:`aegis.contracts.AttestationClaims`,
signed with the same Ed25519 key that signs access tokens (see
``auth.keys.SigningKey`` for why one key).

What the signature buys, precisely
----------------------------------
* **Non-repudiation of the verdict.** The server cannot later claim it allowed a
  different decision, and a client cannot fabricate an `allow`: it does not have
  the key.
* **Binding.** ``commit_digest`` is inside the signed payload, so the attestation
  is worthless for any other commit. Changing one byte invalidates it.
* **Offline verification.** CI verifies with the JWKS from ``/v1/keys`` and needs
  neither the server's uptime nor a shared secret.

What it does *not* buy: freshness. A replayed attestation for the same
``commit_digest`` is valid by design — the digest *is* the content, so replaying it
for the same content is not an attack. ``jti`` exists so a specific attestation can
be revoked out of band.
"""

from __future__ import annotations

import time
from collections.abc import Callable, Sequence

import jwt

from aegis import canon
from aegis.auth.keys import SigningKey
from aegis.contracts import (
    AttestationClaims,
    Decision,
    Finding,
    OwaspCategory,
    Severity,
)

ALGORITHM = "EdDSA"

#: How long an attestation stays verifiable. Long by design: a commit may be
#: pushed days after it was created, and a rebased-but-identical change should not
#: need re-analysis. 30 days matches the refresh-token lifetime.
DEFAULT_TTL_SECONDS = 30 * 24 * 3600


def findings_digest(findings: Sequence[Finding]) -> str:
    """Digest over the findings, so a report can prove it shows the real ones.

    The findings themselves are not embedded in the JWS: they can be large, and a
    verdict only needs a commitment to them. Anyone holding the findings can prove
    they match; anyone without them learns nothing extra.
    """
    return canon.sha256_bytes(canon.canonical_json([finding.model_dump(mode="json") for finding in findings]))


def max_severity(findings: Sequence[Finding]) -> Severity:
    if not findings:
        return Severity.INFO
    return max((f.severity for f in findings), key=lambda s: s.rank)


def sign_attestation(
    *,
    key: SigningKey,
    issuer: str,
    audience: str,
    subject: str,
    commit_digest: str,
    decision: Decision,
    analysis_id: str,
    payload_sha256: str,
    policy_profile: str,
    prompt_version: str,
    model: str,
    findings: Sequence[Finding],
    scope: str,
    jti: str,
    parent_sha: str | None = None,
    commit_sha: str | None = None,
    approver: str | None = None,
    audit_ref: str | None = None,
    categories: Sequence[OwaspCategory] = (),
    ttl_seconds: int = DEFAULT_TTL_SECONDS,
    now: Callable[[], float] = time.time,
) -> str:
    """Build and sign the attestation. Returns the compact JWS."""
    issued = int(now())
    claims = AttestationClaims(
        iss=issuer,
        sub=subject,
        aud=audience,
        iat=issued,
        nbf=issued,
        exp=issued + ttl_seconds,
        jti=jti,
        commit_digest=commit_digest,
        commit_sha=commit_sha,
        parent_sha=parent_sha,
        decision=decision,
        analysis_id=analysis_id,
        payload_sha256=payload_sha256,
        policy_profile=policy_profile,
        prompt_version=prompt_version,
        model=model,
        findings_count=len(findings),
        findings_sha256=findings_digest(findings),
        severity_max=max_severity(findings),
        audit_ref=audit_ref,
        approver=approver,
        scope=scope,
    )
    # `categories` is informational for the verifier; it is carried as a private
    # claim so adding it does not change the frozen AttestationClaims shape.
    payload = claims.model_dump(mode="json")
    if categories:
        payload["cat"] = sorted(c.value for c in categories)
    return jwt.encode(
        payload,
        key.private_key,
        algorithm=ALGORITHM,
        headers={"kid": key.kid, "typ": "JWT"},
    )


def decode_attestation_unverified(token: str) -> dict[str, object]:
    """Read the claims without verifying. Diagnostics only — never a decision."""
    raw = jwt.decode(token, options={"verify_signature": False})
    return raw if isinstance(raw, dict) else {}


__all__ = [
    "ALGORITHM",
    "DEFAULT_TTL_SECONDS",
    "decode_attestation_unverified",
    "findings_digest",
    "max_severity",
    "sign_attestation",
]
