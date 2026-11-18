"""Exception hierarchy for AEGIS.

The client maps exceptions to process exit codes in a single place
(``aegis.cli.exit_codes``) so that a hook never exits 0 by accident:

    1  -> block (a vulnerability was found)
    2  -> usage / configuration error (misconfigured hook, missing repo)
    3  -> authentication problem (no token, expired, not logged in)
    4  -> transport problem (server unreachable, timeout)
    5  -> integrity problem (digest mismatch, bad attestation)
    6  -> internal/unexpected

Exit code 1 blocks the commit (git aborts on any non-zero), and the remaining
codes exist purely so a developer (or CI log parser) can tell *why* it failed
without reading a traceback.
"""

from __future__ import annotations


class AegisError(Exception):
    """Base class. ``exit_code`` is the process status the hook should return."""

    exit_code: int = 6
    #: Short machine-readable slug for logs/telemetry.
    slug: str = "internal"

    def __init__(self, message: str, *, hint: str | None = None) -> None:
        super().__init__(message)
        self.message = message
        self.hint = hint

    def render(self) -> str:
        """Human-facing text: message plus an actionable hint when available."""
        if self.hint:
            return f"{self.message}\n  → {self.hint}"
        return self.message


class BlockedError(AegisError):
    """The analysis produced a blocking verdict."""

    exit_code = 1
    slug = "blocked"


class ConfigError(AegisError):
    """The hook or server is misconfigured."""

    exit_code = 2
    slug = "config"


class AuthError(AegisError):
    """Missing, expired or invalid credentials."""

    exit_code = 3
    slug = "auth"


class TransportError(AegisError):
    """Could not reach or talk to the analysis server."""

    exit_code = 4
    slug = "transport"


class IntegrityError(AegisError):
    """Digest, attestation or audit-chain verification failed."""

    exit_code = 5
    slug = "integrity"


class PolicyError(AegisError):
    """The requested policy is invalid or weaker than the server-side profile."""

    exit_code = 2
    slug = "policy"


__all__ = [
    "AegisError",
    "AuthError",
    "BlockedError",
    "ConfigError",
    "IntegrityError",
    "PolicyError",
    "TransportError",
]
