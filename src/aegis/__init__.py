"""AEGIS — AppSec GenAI Integrity Sentinel.

Deterministic-first, LLM-second commit gate: a ``pre-commit`` hook ships the exact
staged bytes to a server-side analysis pipeline which uses an LLM to reason about
OWASP Top 10 flaws, returns an *attestation* bound to those bytes, and lets CI
prove that what was pushed is what was analysed.
"""

from __future__ import annotations

__version__ = "0.1.0"
__all__ = ["__version__"]
