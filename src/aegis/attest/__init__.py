"""Attestation signing (verification lands in step 5)."""

from __future__ import annotations

from aegis.attest.signer import (
    DEFAULT_TTL_SECONDS,
    decode_attestation_unverified,
    findings_digest,
    max_severity,
    sign_attestation,
)

__all__ = [
    "DEFAULT_TTL_SECONDS",
    "decode_attestation_unverified",
    "findings_digest",
    "max_severity",
    "sign_attestation",
]
