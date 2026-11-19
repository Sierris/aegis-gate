"""Attestations: signing (server) and offline verification (CI, pre-push)."""

from __future__ import annotations

from aegis.attest.signer import (
    DEFAULT_TTL_SECONDS,
    decode_attestation_unverified,
    findings_digest,
    max_severity,
    sign_attestation,
)
from aegis.attest.verify import (
    ALLOWING_DECISIONS,
    AttestationVerifier,
    Jwks,
    VerificationError,
    check_commit,
)

__all__ = [
    "ALLOWING_DECISIONS",
    "DEFAULT_TTL_SECONDS",
    "AttestationVerifier",
    "Jwks",
    "VerificationError",
    "check_commit",
    "decode_attestation_unverified",
    "findings_digest",
    "max_severity",
    "sign_attestation",
]
