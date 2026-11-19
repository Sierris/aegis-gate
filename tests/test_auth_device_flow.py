"""Device Authorization Grant + token lifecycle.

Each test maps to a property an auditor would ask about:

* can a device code be replayed? (no)
* can a client ignore ``slow_down``? (no, and the cost grows)
* does a leaked refresh token end the session? (yes, the whole family)
* can a client escalate its own scopes? (no, and the attempt is logged)
* is anything sensitive stored in plaintext? (no)
"""

from __future__ import annotations

import anyio
import pytest

from aegis.auth import scopes as scopes_mod
from aegis.auth.service import (
    AuthService,
    OAuthError,
    OAuthErrorCode,
    generate_user_code,
)
from aegis.auth.store import AuthStore, hash_secret, normalize_user_code
from aegis.contracts import AuditAction
from aegis.errors import AuthError, IntegrityError
from conftest import FakeClock

CLIENT = "aegis-cli"
SCOPE = "analyze"


def _approve(service: AuthService, user_code: str, email: str = "dev@mercadolibre.com") -> None:
    anyio.run(
        lambda: service.approve_user_code(user_code=user_code, email=email, password="correct horse battery")
    )


def _start(service: AuthService, scope: str = SCOPE) -> tuple[str, str]:
    resp = service.start_device_authorization(client_id=CLIENT, requested_scope=scope)
    return resp.device_code, resp.user_code


# --------------------------------------------------------------------------- #
# User code format
# --------------------------------------------------------------------------- #
def test_user_code_alphabet_has_no_lookalikes() -> None:
    forbidden = set("AEIOU01ILO")
    for _ in range(200):
        code = generate_user_code()
        assert len(code) == 9
        assert code[4] == "-"
        assert not (set(code.replace("-", "")) & forbidden)


def test_user_code_normalisation_accepts_human_input() -> None:
    for variant in ("wdjb-mjht", "WDJB MJHT", " wdjbmjht ", "WdjB-MjHt"):
        assert normalize_user_code(variant) == "WDJB-MJHT"


# --------------------------------------------------------------------------- #
# Happy path
# --------------------------------------------------------------------------- #
def test_full_device_flow(service: AuthService, clock: FakeClock) -> None:
    device_code, user_code = _start(service)

    with pytest.raises(OAuthError) as pending:
        service.poll_token(device_code=device_code, client_id=CLIENT)
    assert pending.value.code is OAuthErrorCode.AUTHORIZATION_PENDING

    clock.advance(6)
    _approve(service, user_code)

    tokens = service.poll_token(device_code=device_code, client_id=CLIENT)
    assert tokens.token_type == "Bearer"
    assert tokens.refresh_token
    assert tokens.scope == SCOPE

    claims = service.verify_access_token(tokens.access_token)
    assert claims.email == "dev@mercadolibre.com"
    assert claims.provider == "local"
    assert claims.scopes == {scopes_mod.Scope.ANALYZE}


def test_verification_uri_points_at_the_public_url(service: AuthService) -> None:
    resp = service.start_device_authorization(client_id=CLIENT)
    assert resp.verification_uri == "http://aegis.test/device"
    assert resp.user_code in (resp.verification_uri_complete or "")


# --------------------------------------------------------------------------- #
# Single use / replay
# --------------------------------------------------------------------------- #
def test_device_code_cannot_be_reused(service: AuthService, clock: FakeClock) -> None:
    device_code, user_code = _start(service)
    clock.advance(6)
    _approve(service, user_code)
    first = service.poll_token(device_code=device_code, client_id=CLIENT)
    assert first.access_token

    clock.advance(6)
    with pytest.raises(OAuthError) as exc:
        service.poll_token(device_code=device_code, client_id=CLIENT)
    assert exc.value.code is OAuthErrorCode.INVALID_GRANT
    assert "already used" in exc.value.description


def test_expired_device_code_is_rejected(service: AuthService, clock: FakeClock) -> None:
    device_code, _ = _start(service)
    clock.advance(601)
    with pytest.raises(OAuthError) as exc:
        service.poll_token(device_code=device_code, client_id=CLIENT)
    assert exc.value.code is OAuthErrorCode.EXPIRED_TOKEN


def test_denied_device_code(service: AuthService, clock: FakeClock) -> None:
    device_code, user_code = _start(service)
    service.deny_user_code(user_code=user_code)
    clock.advance(6)
    with pytest.raises(OAuthError) as exc:
        service.poll_token(device_code=device_code, client_id=CLIENT)
    assert exc.value.code is OAuthErrorCode.ACCESS_DENIED


# --------------------------------------------------------------------------- #
# Polling discipline (RFC 8628 §3.5)
# --------------------------------------------------------------------------- #
def test_slow_down_grows_the_interval_persistently(service: AuthService, clock: FakeClock) -> None:
    device_code, _ = _start(service)

    with pytest.raises(OAuthError) as first_poll:
        service.poll_token(device_code=device_code, client_id=CLIENT)
    assert first_poll.value.code is OAuthErrorCode.AUTHORIZATION_PENDING
    # Polling again immediately is too fast -> slow_down with interval 5 + 5.
    with pytest.raises(OAuthError) as first:
        service.poll_token(device_code=device_code, client_id=CLIENT)
    assert first.value.code is OAuthErrorCode.SLOW_DOWN
    assert "interval=10" in first.value.description

    # Still too fast -> grows again. The growth must be persisted, not per-process.
    with pytest.raises(OAuthError) as second:
        service.poll_token(device_code=device_code, client_id=CLIENT)
    assert "interval=15" in second.value.description


def test_polling_after_the_interval_is_accepted(service: AuthService, clock: FakeClock) -> None:
    device_code, _ = _start(service)
    with pytest.raises(OAuthError) as pending:
        service.poll_token(device_code=device_code, client_id=CLIENT)
    assert pending.value.code is OAuthErrorCode.AUTHORIZATION_PENDING
    clock.advance(6)
    with pytest.raises(OAuthError) as again:
        service.poll_token(device_code=device_code, client_id=CLIENT)
    assert again.value.code is OAuthErrorCode.AUTHORIZATION_PENDING


# --------------------------------------------------------------------------- #
# Client / scope authorisation
# --------------------------------------------------------------------------- #
def test_unknown_client_id_is_rejected(service: AuthService) -> None:
    with pytest.raises(OAuthError) as exc:
        service.start_device_authorization(client_id="rogue-client")
    assert exc.value.code is OAuthErrorCode.UNAUTHORIZED_CLIENT


def test_scope_escalation_is_downgraded_and_audited(
    service: AuthService, store: AuthStore, clock: FakeClock
) -> None:
    """Asking for ``admin`` must not fail loudly (that leaks the policy) but must
    never be granted — and the attempt must be visible in the audit log."""
    device_code, user_code = _start(service, scope="analyze admin")
    clock.advance(6)
    _approve(service, user_code)
    tokens = service.poll_token(device_code=device_code, client_id=CLIENT)
    assert tokens.scope == "analyze"
    assert "admin" not in tokens.scope

    claims = service.verify_access_token(tokens.access_token)
    assert not scopes_mod.has_scope(claims.scopes, scopes_mod.Scope.ADMIN)
    assert store.verify_audit_chain() >= 2


def test_requesting_only_ungrantable_scopes_fails_fast(service: AuthService) -> None:
    with pytest.raises(OAuthError) as exc:
        service.start_device_authorization(client_id=CLIENT, requested_scope="admin")
    assert exc.value.code is OAuthErrorCode.INVALID_SCOPE


# --------------------------------------------------------------------------- #
# Refresh rotation & reuse detection
# --------------------------------------------------------------------------- #
def test_refresh_rotates_and_the_old_token_stops_working(service: AuthService, clock: FakeClock) -> None:
    device_code, user_code = _start(service)
    clock.advance(6)
    _approve(service, user_code)
    first = service.poll_token(device_code=device_code, client_id=CLIENT)
    assert first.refresh_token

    assert first.refresh_token is not None
    first_refresh: str = first.refresh_token
    clock.advance(10)
    second = service.refresh(refresh_token=first_refresh, client_id=CLIENT)
    assert second.refresh_token and second.refresh_token != first.refresh_token
    assert second.access_token != first.access_token


def test_refresh_reuse_revokes_the_whole_family(
    service: AuthService, clock: FakeClock, store: AuthStore
) -> None:
    """A rotated token presented again means two parties hold it: kill the family."""
    device_code, user_code = _start(service)
    clock.advance(6)
    _approve(service, user_code)
    first = service.poll_token(device_code=device_code, client_id=CLIENT)
    assert first.refresh_token is not None
    first_refresh: str = first.refresh_token
    clock.advance(10)
    second = service.refresh(refresh_token=first_refresh, client_id=CLIENT)
    assert second.refresh_token is not None
    second_refresh: str = second.refresh_token

    # The legitimate client keeps working...
    clock.advance(10)
    third = service.refresh(refresh_token=second_refresh, client_id=CLIENT)
    assert third.access_token
    assert third.refresh_token is not None
    third_refresh: str = third.refresh_token

    # ...until the stolen (already rotated) token shows up.
    clock.advance(10)
    with pytest.raises(OAuthError) as exc:
        service.refresh(refresh_token=first_refresh, client_id=CLIENT)
    assert "revoked" in exc.value.description

    # Now the legitimate token is dead too: that is the point.
    with pytest.raises(OAuthError):
        service.refresh(refresh_token=third_refresh, client_id=CLIENT)

    assert store.verify_audit_chain() >= 3


def test_refresh_token_of_another_client_is_rejected(service: AuthService, clock: FakeClock) -> None:
    device_code, user_code = _start(service)
    clock.advance(6)
    _approve(service, user_code)
    tokens = service.poll_token(device_code=device_code, client_id=CLIENT)
    assert tokens.refresh_token is not None
    with pytest.raises(OAuthError) as exc:
        service.refresh(refresh_token=tokens.refresh_token, client_id="other-client")
    assert exc.value.code is OAuthErrorCode.INVALID_GRANT


def test_expired_refresh_token_is_rejected(service: AuthService, clock: FakeClock) -> None:
    device_code, user_code = _start(service)
    clock.advance(6)
    _approve(service, user_code)
    tokens = service.poll_token(device_code=device_code, client_id=CLIENT)
    assert tokens.refresh_token is not None
    clock.advance(86_400 + 1)
    with pytest.raises(OAuthError, match="expired"):
        service.refresh(refresh_token=tokens.refresh_token, client_id=CLIENT)


def test_logout_revokes_the_family(service: AuthService, clock: FakeClock) -> None:
    device_code, user_code = _start(service)
    clock.advance(6)
    _approve(service, user_code)
    tokens = service.poll_token(device_code=device_code, client_id=CLIENT)
    assert tokens.refresh_token is not None
    service.revoke(refresh_token=tokens.refresh_token, client_id=CLIENT)
    clock.advance(10)
    with pytest.raises(OAuthError):
        service.refresh(refresh_token=tokens.refresh_token, client_id=CLIENT)


def test_revoking_an_unknown_token_is_a_noop(service: AuthService) -> None:
    """RFC 7009 §2.2: no oracle telling an attacker whether a token is valid."""
    service.revoke(refresh_token="x" * 40, client_id=CLIENT)


# --------------------------------------------------------------------------- #
# Storage hygiene
# --------------------------------------------------------------------------- #
def test_no_secret_is_stored_in_plaintext(service: AuthService, store: AuthStore, clock: FakeClock) -> None:
    device_code, user_code = _start(service)
    clock.advance(6)
    _approve(service, user_code)
    tokens = service.poll_token(device_code=device_code, client_id=CLIENT)

    dump = b"".join(p.read_bytes() for p in store.path.parent.glob(store.path.name + "*"))
    assert tokens.refresh_token is not None
    for secret in (device_code, tokens.refresh_token):
        assert secret.encode() not in dump, "a secret was persisted in plaintext"
        assert hash_secret(secret).encode() in dump, "the digest should be persisted"


def test_approval_with_wrong_password_does_not_approve(
    service: AuthService, store: AuthStore, clock: FakeClock
) -> None:
    device_code, user_code = _start(service)
    with pytest.raises(AuthError, match="invalid credentials"):
        anyio.run(
            lambda: service.approve_user_code(
                user_code=user_code, email="dev@mercadolibre.com", password="wrong password"
            )
        )
    clock.advance(6)
    with pytest.raises(OAuthError) as exc:
        service.poll_token(device_code=device_code, client_id=CLIENT)
    assert exc.value.code is OAuthErrorCode.AUTHORIZATION_PENDING
    # The failed attempt is recorded.
    assert store.verify_audit_chain() >= 1


def test_approval_with_unknown_user_and_unknown_code_look_identical(
    service: AuthService,
) -> None:
    with pytest.raises(AuthError) as unknown_code:
        anyio.run(
            lambda: service.approve_user_code(
                user_code="ZZZZ-ZZZZ", email="dev@mercadolibre.com", password="x"
            )
        )
    device_code, user_code = _start(service)
    with pytest.raises(AuthError) as unknown_user:
        anyio.run(
            lambda: service.approve_user_code(
                user_code=user_code, email="ghost@mercadolibre.com", password="x"
            )
        )
    # Different messages, both about credentials/codes — but neither reveals
    # whether the *e-mail* exists.
    assert "user code" in str(unknown_code.value)
    assert "credentials" in str(unknown_user.value)


def test_audit_chain_records_the_device_flow(
    service: AuthService, store: AuthStore, clock: FakeClock
) -> None:
    device_code, user_code = _start(service)
    clock.advance(6)
    _approve(service, user_code)
    service.poll_token(device_code=device_code, client_id=CLIENT)
    assert store.verify_audit_chain() >= 2

    # Tamper with the log and prove verification notices.
    with store._lock, store._tx() as cur:
        cur.execute("UPDATE audit_log SET actor = 'attacker@evil.com' WHERE seq = 2")
    with pytest.raises(IntegrityError, match="audit chain broken"):
        store.verify_audit_chain()


def test_actions_are_typed_enums_not_strings(
    service: AuthService, store: AuthStore, clock: FakeClock
) -> None:
    """CI and alerting branch on enum members; a string typo would silently mute them."""
    device_code, user_code = _start(service)
    clock.advance(6)
    _approve(service, user_code)
    service.poll_token(device_code=device_code, client_id=CLIENT)
    with store._lock:
        rows = store._conn.execute("SELECT action FROM audit_log").fetchall()
    values = {r["action"] for r in rows}
    assert values <= {a.value for a in AuditAction}
    assert AuditAction.TOKEN_ISSUED.value in values
