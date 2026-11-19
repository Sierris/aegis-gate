"""Access-token encoding/decoding (JWS compact, EdDSA/Ed25519).

Why PyJWT rather than hand-rolled JWS
-------------------------------------
Signing a token is 5 lines; *rejecting* a malformed or hostile one correctly is
where implementations break. PyJWT centralises the well-known pitfalls, and we
then remove its remaining degrees of freedom:

* **Algorithm allowlist is a literal**: ``algorithms=["EdDSA"]``. This is the
  single most exploited JWT vulnerability class (``alg: none``, and HS256/RSA
  confusion where the public key is used as an HMAC secret). With an EdDSA-only
  allowlist, neither variant is expressible.
* **``kid`` is required**, so a token can never be verified against "whatever key
  happens to be loaded" during a rotation window.
* **Mandatory claims** via ``options={"require": [...]}`` — no implicit defaults.
* **``typ`` is checked by us** after decoding, because PyJWT does not care about
  it and a refresh/id token accepted as an access token would be a
  privilege-confusion bug.
* **Limits**: ``leeway`` is a small explicit value (clock skew), never "whatever
  the system clock says"; and the token length is bounded before parsing to
  avoid feeding a 10 MB blob to a JSON decoder.
* **Temporal validation is ours, not the library's.** PyJWT reads
  ``datetime.now()`` internally, which makes it untestable and makes the expiry
  window a property of the host clock. We therefore verify the signature,
  issuer, audience and required claims with PyJWT and then check ``exp``/``nbf``/
  ``iat`` explicitly against the injected clock. One place, one semantic, fully
  reproducible in tests.

Token claims are intentionally *not* in ``contracts.py``: the access token is
opaque to the hook (it only forwards it as a Bearer credential), so its internal
shape must stay free to evolve without bumping the client contract.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from typing import Any, Literal

import jwt
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from pydantic import Field

from aegis.auth import scopes as scopes_mod
from aegis.auth.keys import SigningKey, verify_public_of
from aegis.contracts import StrictModel
from aegis.errors import AuthError

#: The only algorithm we ever accept. See module docstring.
ALLOWED_ALGORITHM = "EdDSA"

#: Reject absurdly large tokens before handing them to the parser.
MAX_TOKEN_LENGTH = 4096

#: Audience of access tokens. Distinct from the attestation audience (a repo id)
#: so that an attestation can never be replayed as a bearer token or vice versa.
ACCESS_TOKEN_AUDIENCE = "aegis-api"  # noqa: S105 - JWT audience, not a secret

_TOKEN_TYPE = "access"  # noqa: S105 - token type marker, not a secret

Clock = Callable[[], float]


class AccessTokenClaims(StrictModel):
    """Decoded, validated access token."""

    iss: str = Field(max_length=256)
    sub: str = Field(min_length=1, max_length=320)
    aud: str = Field(max_length=128)
    exp: int = Field(ge=0)
    iat: int = Field(ge=0)
    nbf: int = Field(ge=0)
    jti: str = Field(max_length=64)
    scope: str = Field(default="", max_length=256)
    typ: Literal["access"] = "access"
    email: str = Field(min_length=3, max_length=320)
    name: str | None = Field(default=None, max_length=256)
    provider: str = Field(max_length=64)
    #: ``kid`` of the signing key, surfaced for rotation debugging.
    kid: str | None = Field(default=None, max_length=64)

    @property
    def scopes(self) -> frozenset[scopes_mod.Scope]:
        return scopes_mod.parse_scopes(self.scope)

    def require(self, scope: scopes_mod.Scope) -> None:
        scopes_mod.require_scope(self.scopes, scope, actor=self.email)


def encode_access_token(
    *,
    key: SigningKey,
    issuer: str,
    subject: str,
    email: str,
    name: str | None,
    provider: str,
    scopes: frozenset[scopes_mod.Scope],
    ttl_seconds: int,
    jti: str,
    now: Clock = time.time,
    audience: str = ACCESS_TOKEN_AUDIENCE,
) -> str:
    """Sign an access token.

    ``jti`` is supplied by the caller (not generated here) so the service can
    record it in the audit log *before* the token exists anywhere else — an
    issued token always has a corresponding audit entry.
    """
    issued = int(now())
    payload: dict[str, Any] = {
        "iss": issuer,
        "sub": subject,
        "aud": audience,
        "iat": issued,
        "nbf": issued,
        "exp": issued + ttl_seconds,
        "jti": jti,
        "scope": scopes_mod.format_scopes(scopes),
        "typ": _TOKEN_TYPE,
        "email": email,
        "provider": provider,
    }
    if name:
        payload["name"] = name
    return jwt.encode(
        payload,
        key.private_key,
        algorithm=ALLOWED_ALGORITHM,
        headers={"kid": key.kid, "typ": "JWT"},
    )


def decode_access_token(
    token: str,
    *,
    public_key: SigningKey | Ed25519PublicKey | bytes,
    issuer: str,
    now: Clock = time.time,
    leeway_seconds: int = 30,
    audience: str = ACCESS_TOKEN_AUDIENCE,
) -> AccessTokenClaims:
    """Verify and decode an access token. Raises :class:`AuthError` on any defect."""
    if not token or not isinstance(token, str):
        raise AuthError("missing access token")
    if len(token) > MAX_TOKEN_LENGTH:
        raise AuthError("access token too large")

    try:
        header = jwt.get_unverified_header(token)
    except jwt.PyJWTError as exc:
        raise AuthError(f"malformed access token: {exc}") from exc
    if header.get("alg") != ALLOWED_ALGORITHM:
        # Explicit, because this is the attack path we care most about.
        raise AuthError(
            f"unsupported token algorithm: {header.get('alg')!r}",
            hint=f"Only {ALLOWED_ALGORITHM} is accepted.",
        )
    if not header.get("kid"):
        raise AuthError("token has no kid; cannot select a verification key")

    try:
        raw = jwt.decode(
            token,
            verify_public_of(public_key),
            algorithms=[ALLOWED_ALGORITHM],
            audience=audience,
            issuer=issuer,
            leeway=leeway_seconds,
            options={
                "require": ["iss", "sub", "aud", "exp", "iat", "nbf", "jti", "scope", "typ"],
                # Signature / issuer / audience are the library's job.
                "verify_signature": True,
                "verify_aud": True,
                "verify_iss": True,
                # Time is ours: see the module docstring and _check_temporal().
                "verify_exp": False,
                "verify_nbf": False,
                "verify_iat": False,
            },
        )
    except jwt.InvalidAudienceError as exc:
        raise AuthError(f"access token audience mismatch (expected {audience!r})") from exc
    except jwt.InvalidIssuerError as exc:
        raise AuthError("access token issuer mismatch") from exc
    except jwt.PyJWTError as exc:
        raise AuthError(f"invalid access token: {exc}") from exc

    if raw.get("typ") != _TOKEN_TYPE:
        # A refresh/ID token must never be usable as an access token.
        raise AuthError(f"wrong token type: {raw.get('typ')!r}")

    _check_temporal(raw, now=now, leeway_seconds=leeway_seconds)
    return AccessTokenClaims.model_validate({**raw, "kid": header.get("kid")})


def _check_temporal(raw: dict[str, Any], *, now: Clock, leeway_seconds: int) -> None:
    """Validate ``exp`` / ``nbf`` / ``iat`` against the injected clock.

    Asymmetry on purpose: tolerance is applied to ``exp`` (an honest verifier may
    be slightly ahead) but a token that is not yet valid is rejected outright
    beyond the skew, because "issued slightly in the future" is also what a
    clock-rollback attack looks like.
    """
    current = int(now())
    skew = max(leeway_seconds, 0)

    exp = raw.get("exp")
    nbf = raw.get("nbf")
    iat = raw.get("iat")
    if not isinstance(exp, int) or not isinstance(iat, int) or not isinstance(nbf, int):
        raise AuthError("token is missing an integer exp/nbf/iat claim")

    if current >= exp + skew:
        raise AuthError("access token expired", hint="Run `aegis login` again.")
    if current + skew < nbf:
        raise AuthError(
            f"access token not yet valid (nbf={nbf}, now={current})",
            hint="Check the clock on this machine.",
        )
    if iat > current + skew:
        raise AuthError(f"access token issued in the future (iat={iat}, now={current})")
