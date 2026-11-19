"""Authentication and authorisation for AEGIS.

Layers, bottom-up:

* ``keys``     — Ed25519 key material, ``kid`` derivation, JWKS export.
* ``scopes``   — the closed set of capabilities and its implication rules.
* ``jwt``      — access-token encode/decode with an explicit algorithm allowlist.
* ``store``    — SQLite persistence (device codes, refresh families, users, audit).
* ``provider`` — identity providers (local password, GitHub upstream token).
* ``service``  — the OAuth 2.0 Device Authorization Grant state machine.
* ``client``   — client-side token cache and login orchestration.
* ``binding``  — identity <-> commit-author binding check.
"""

from __future__ import annotations

__all__: list[str] = []
