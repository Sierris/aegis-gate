"""Unit tests: keys, scopes, JWT, password hashing.

These cover the primitives whose failure mode is silent — a JWT accepted with the
wrong algorithm, a scope that implies too much, a key file that is world-readable.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import stat
from pathlib import Path

import jwt as pyjwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from aegis.auth import jwt as jwt_mod
from aegis.auth import scopes as scopes_mod
from aegis.auth.keys import SigningKey, b64url, key_id_from_raw_public
from aegis.auth.provider import hash_password, verify_password_hash
from aegis.errors import AuthError, ConfigError

ISS = "http://aegis.test"


# --------------------------------------------------------------------------- #
# Signing keys
# --------------------------------------------------------------------------- #
def test_key_is_persisted_with_owner_only_permissions(tmp_path: Path) -> None:
    path = tmp_path / "keys" / "aegis.pem"
    key = SigningKey.load_or_create(path)
    mode = stat.S_IMODE(path.stat().st_mode)
    assert mode == 0o600, f"private key must be 0600, got {mode:o}"
    assert stat.S_IMODE(path.parent.stat().st_mode) == 0o700
    assert key.kid


def test_key_round_trips_through_pem(tmp_path: Path) -> None:
    path = tmp_path / "k.pem"
    first = SigningKey.load_or_create(path)
    second = SigningKey.load_or_create(path)
    assert first.kid == second.kid
    assert first.raw_public == second.raw_public


def test_world_readable_key_is_refused(tmp_path: Path) -> None:
    path = tmp_path / "k.pem"
    SigningKey.load_or_create(path)
    path.chmod(0o644)
    with pytest.raises(ConfigError, match="readable by group/other"):
        SigningKey.load_or_create(path)


def test_kid_is_derived_from_the_public_key() -> None:
    key = SigningKey.generate()
    assert key.kid == key_id_from_raw_public(key.raw_public)
    other = SigningKey.generate()
    assert key.kid != other.kid


def test_repr_never_leaks_private_material() -> None:
    key = SigningKey.generate()
    text = repr(key)
    pem_fragment = b64url(key.to_pem())[:16]
    assert pem_fragment not in text
    assert "private" not in text.replace("SigningKey", "")


def test_jwks_entry_shape() -> None:
    key = SigningKey.generate()
    jwk = key.public_jwk().model_dump()
    assert jwk["kty"] == "OKP"
    assert jwk["crv"] == "Ed25519"
    assert jwk["alg"] == "EdDSA"
    assert jwk["kid"] == key.kid
    assert len(jwk["x"]) == 43  # 32 bytes base64url without padding
    json.dumps(jwk)  # must be serialisable


def test_non_ed25519_key_is_rejected() -> None:
    from cryptography.hazmat.primitives.asymmetric import rsa

    rsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = rsa_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    with pytest.raises(ConfigError, match="not Ed25519"):
        SigningKey.from_pem(pem)


# --------------------------------------------------------------------------- #
# Scopes
# --------------------------------------------------------------------------- #
def test_parse_and_format_round_trip() -> None:
    parsed = scopes_mod.parse_scopes("analyze analyze:any")
    assert parsed == {scopes_mod.Scope.ANALYZE, scopes_mod.Scope.ANALYZE_ANY}
    assert scopes_mod.format_scopes(parsed) == "analyze analyze:any"


def test_unknown_scope_is_a_hard_error() -> None:
    """A typo must never produce a no-op token that satisfies no check."""
    with pytest.raises(AuthError, match="unknown scope"):
        scopes_mod.parse_scopes("analyze superuser")


def test_empty_scope_yields_nothing_rather_than_everything() -> None:
    assert scopes_mod.parse_scopes(None) == frozenset()
    assert scopes_mod.parse_scopes("   ") == frozenset()


def test_implication_graph() -> None:
    admin = scopes_mod.expand(frozenset({scopes_mod.Scope.ADMIN}))
    assert scopes_mod.Scope.OVERRIDE in admin
    assert scopes_mod.Scope.ANALYZE in admin
    # analyze:any implies analyze, but not the other way round.
    assert scopes_mod.has_scope(frozenset({scopes_mod.Scope.ANALYZE_ANY}), scopes_mod.Scope.ANALYZE)
    assert not scopes_mod.has_scope(frozenset({scopes_mod.Scope.ANALYZE}), scopes_mod.Scope.ANALYZE_ANY)
    assert not scopes_mod.has_scope(frozenset({scopes_mod.Scope.ANALYZE}), scopes_mod.Scope.OVERRIDE)


def test_require_scope_raises_with_actionable_hint() -> None:
    with pytest.raises(AuthError) as exc:
        scopes_mod.require_scope(frozenset({scopes_mod.Scope.ANALYZE}), scopes_mod.Scope.OVERRIDE)
    assert "override" in str(exc.value)
    assert exc.value.hint


def test_clamp_only_downscopes() -> None:
    issuable = frozenset({scopes_mod.Scope.ANALYZE})
    granted = scopes_mod.clamp_requested(
        frozenset({scopes_mod.Scope.ANALYZE, scopes_mod.Scope.ADMIN}), issuable
    )
    assert granted == frozenset({scopes_mod.Scope.ANALYZE})


# --------------------------------------------------------------------------- #
# Password hashing
# --------------------------------------------------------------------------- #
def test_scrypt_hash_is_salted_and_verifiable() -> None:
    a = hash_password("hunter2hunter2")
    b = hash_password("hunter2hunter2")
    assert a != b, "identical passwords must not produce identical hashes"
    assert verify_password_hash("hunter2hunter2", a)
    assert not verify_password_hash("hunter2hunter3", a)


def test_hash_format_is_self_describing() -> None:
    """Parameters live in the string so they can be raised without locking users out."""
    stored = hash_password("hunter2hunter2")
    scheme, n, r, p, salt, dk = stored.split("$")
    assert (scheme, n, r, p) == ("scrypt", "16384", "8", "1")
    assert salt and dk


@pytest.mark.parametrize("garbage", ["", "not-a-hash", "scrypt$bad", "md5$1$2$3$4$5"])
def test_malformed_hash_verifies_false_without_raising(garbage: str) -> None:
    assert verify_password_hash("whatever", garbage) is False


# --------------------------------------------------------------------------- #
# JWT
# --------------------------------------------------------------------------- #
def _token(**overrides: object) -> str:
    params: dict[str, object] = {
        "key": SigningKey.generate(),
        "issuer": ISS,
        "subject": "dev@mercadolibre.com",
        "email": "dev@mercadolibre.com",
        "name": "Dev",
        "provider": "local",
        "scopes": frozenset({scopes_mod.Scope.ANALYZE}),
        "ttl_seconds": 3600,
        "jti": "j" * 32,
        "now": lambda: 1_700_000_000.0,
    }
    params.update(overrides)
    return jwt_mod.encode_access_token(**params)  # type: ignore[arg-type]


def test_token_round_trip() -> None:
    key = SigningKey.generate()
    token = _token(key=key)
    claims = jwt_mod.decode_access_token(token, public_key=key, issuer=ISS, now=lambda: 1_700_000_100.0)
    assert claims.sub == "dev@mercadolibre.com"
    assert claims.typ == "access"
    assert claims.scopes == {scopes_mod.Scope.ANALYZE}
    assert claims.kid == key.kid
    assert claims.aud == jwt_mod.ACCESS_TOKEN_AUDIENCE


def test_tampered_payload_is_rejected() -> None:
    key = SigningKey.generate()
    token = _token(key=key)
    header, _, signature = token.split(".")
    forged_payload = b64url(
        json.dumps(
            {
                "iss": ISS,
                "sub": "attacker@evil.com",
                "aud": jwt_mod.ACCESS_TOKEN_AUDIENCE,
                "iat": 1_700_000_000,
                "nbf": 1_700_000_000,
                "exp": 1_700_003_600,
                "jti": "j" * 32,
                "scope": "admin",
                "typ": "access",
                "email": "attacker@evil.com",
                "provider": "local",
            }
        ).encode()
    )
    with pytest.raises(AuthError, match="invalid access token"):
        jwt_mod.decode_access_token(f"{header}.{forged_payload}.{signature}", public_key=key, issuer=ISS)


def test_alg_none_is_rejected() -> None:
    """The classic JWT attack. Our allowlist makes it unexpressible."""
    key = SigningKey.generate()
    header = b64url(json.dumps({"alg": "none", "typ": "JWT", "kid": key.kid}).encode())
    payload = b64url(json.dumps({"sub": "attacker", "typ": "access"}).encode())
    with pytest.raises(AuthError, match="unsupported token algorithm"):
        jwt_mod.decode_access_token(f"{header}.{payload}.", public_key=key, issuer=ISS)


def test_hs256_confusion_is_rejected() -> None:
    """A token HMAC-signed with the *public* key must never verify.

    PyJWT's encoder refuses to build this (asymmetric key + HMAC), which is
    itself a mitigation — so the token is assembled by hand here. That is the
    honest test: an attacker writes bytes, not PyJWT calls.
    """
    key = SigningKey.generate()
    public_pem = key.public_key.public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    header = b64url(json.dumps({"alg": "HS256", "typ": "JWT", "kid": key.kid}).encode())
    payload = b64url(
        json.dumps(
            {
                "iss": ISS,
                "sub": "attacker@evil.com",
                "aud": jwt_mod.ACCESS_TOKEN_AUDIENCE,
                "iat": 1_700_000_000,
                "nbf": 1_700_000_000,
                "exp": 1_700_003_600,
                "jti": "j" * 32,
                "scope": "admin",
                "typ": "access",
                "email": "attacker@evil.com",
                "provider": "local",
            }
        ).encode()
    )
    signature = b64url(hmac.new(public_pem, f"{header}.{payload}".encode(), hashlib.sha256).digest())
    with pytest.raises(AuthError, match="unsupported token algorithm"):
        jwt_mod.decode_access_token(
            f"{header}.{payload}.{signature}",
            public_key=key,
            issuer=ISS,
            now=lambda: 1_700_000_100.0,
        )


def test_missing_kid_is_rejected() -> None:
    key = SigningKey.generate()
    token = pyjwt.encode({"sub": "x", "typ": "access"}, Ed25519PrivateKey.generate(), algorithm="EdDSA")
    with pytest.raises(AuthError, match="no kid"):
        jwt_mod.decode_access_token(token, public_key=key, issuer=ISS)


def test_expired_token_is_rejected_with_actionable_message() -> None:
    key = SigningKey.generate()
    token = _token(key=key, ttl_seconds=60)
    with pytest.raises(AuthError) as exc:
        jwt_mod.decode_access_token(token, public_key=key, issuer=ISS, now=lambda: 1_700_000_999.0)
    assert "expired" in str(exc.value)
    assert "aegis login" in (exc.value.hint or "")


def test_wrong_issuer_and_audience_are_rejected() -> None:
    key = SigningKey.generate()
    token = _token(key=key)
    with pytest.raises(AuthError, match="issuer"):
        jwt_mod.decode_access_token(
            token, public_key=key, issuer="http://other.test", now=lambda: 1_700_000_100.0
        )
    with pytest.raises(AuthError, match="audience"):
        jwt_mod.decode_access_token(
            token,
            public_key=key,
            issuer=ISS,
            audience="some-other-api",
            now=lambda: 1_700_000_100.0,
        )


def test_non_access_token_type_is_rejected() -> None:
    """A refresh/ID token must never be usable as a bearer credential."""
    key = SigningKey.generate()
    token = pyjwt.encode(
        {
            "iss": ISS,
            "sub": "dev@mercadolibre.com",
            "aud": jwt_mod.ACCESS_TOKEN_AUDIENCE,
            "iat": 1_700_000_000,
            "nbf": 1_700_000_000,
            "exp": 1_700_003_600,
            "jti": "j" * 32,
            "scope": "analyze",
            "typ": "refresh",
            "email": "dev@mercadolibre.com",
            "provider": "local",
        },
        key.private_key,
        algorithm="EdDSA",
        headers={"kid": key.kid},
    )
    with pytest.raises(AuthError, match="wrong token type"):
        jwt_mod.decode_access_token(token, public_key=key, issuer=ISS, now=lambda: 1_700_000_100.0)


def test_oversized_token_is_rejected_before_parsing() -> None:
    with pytest.raises(AuthError, match="too large"):
        jwt_mod.decode_access_token("a" * 5000, public_key=SigningKey.generate(), issuer=ISS)


def test_require_scope_on_claims() -> None:
    key = SigningKey.generate()
    claims = jwt_mod.decode_access_token(
        _token(key=key), public_key=key, issuer=ISS, now=lambda: 1_700_000_100.0
    )
    claims.require(scopes_mod.Scope.ANALYZE)  # ok
    with pytest.raises(AuthError):
        claims.require(scopes_mod.Scope.OVERRIDE)
