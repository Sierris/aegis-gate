"""End-to-end tests of the HTTP surface and the client.

The API tests drive the real ``FastAPI`` app with ``TestClient`` against a temp
SQLite file and a real Ed25519 key, so they exercise the same code paths as
production. Only the clock is faked (otherwise the suite would sleep).

The client tests run against a ``MockTransport`` that speaks the same routes, so
``AuthClient`` is tested without a server process.
"""

from __future__ import annotations

import json
import stat
from collections.abc import Iterator
from typing import Any

import httpx
import pytest
from fastapi.testclient import TestClient

from aegis.auth.binding import bind_identity
from aegis.auth.client import AuthClient, CachedToken, TokenCache
from aegis.auth.keys import SigningKey
from aegis.auth.provider import LocalIdentityProvider
from aegis.auth.service import AuthService
from aegis.auth.store import AuthStore
from aegis.config import ClientSettings, ServerSettings
from aegis.errors import AuthError
from conftest import FakeClock

CLIENT_ID = "aegis-cli"


# --------------------------------------------------------------------------- #
# Fixtures
# --------------------------------------------------------------------------- #
@pytest.fixture
def app_client(
    server_settings: ServerSettings,
    store: AuthStore,
    key: SigningKey,
    local_provider: LocalIdentityProvider,
    clock: FakeClock,
) -> Iterator[tuple[TestClient, FakeClock]]:
    from aegis.server.app import create_app

    app = create_app(server_settings, store=store, key=key, provider=local_provider, now=clock)
    with TestClient(app) as client:
        yield client, clock


def _device_start(client: TestClient) -> dict[str, Any]:
    r = client.post("/v1/auth/device", json={"client_id": CLIENT_ID, "scope": "analyze"})
    assert r.status_code == 200, r.text
    return dict(r.json())


def _approve(client: TestClient, user_code: str, email: str = "dev@mercadolibre.com") -> None:
    r = client.post(
        "/device",
        data={
            "user_code": user_code,
            "email": email,
            "password": "correct horse battery",
            "action": "approve",
        },
    )
    assert r.status_code == 200, r.text
    assert "concedida" in r.text.lower()


# --------------------------------------------------------------------------- #
# Auth API
# --------------------------------------------------------------------------- #
def test_healthz_exposes_no_secret(app_client: tuple[TestClient, FakeClock]) -> None:
    client, _ = app_client
    body = client.get("/healthz").json()
    assert body["status"] == "ok"
    assert body["kid"]
    assert "key" not in body
    assert "secret" not in json.dumps(body).lower()


def test_jwks_is_public_and_cacheable(app_client: tuple[TestClient, FakeClock]) -> None:
    client, _ = app_client
    r = client.get("/v1/keys")
    assert r.status_code == 200
    assert "max-age" in r.headers["cache-control"]
    keys = r.json()["keys"]
    assert len(keys) == 1
    assert keys[0]["alg"] == "EdDSA"
    assert "d" not in keys[0], "a JWKS must never contain private material"


def test_device_flow_over_http(app_client: tuple[TestClient, FakeClock]) -> None:
    client, clock = app_client
    start = _device_start(client)

    pending = client.post(
        "/v1/auth/token",
        json={
            "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
            "device_code": start["device_code"],
            "client_id": CLIENT_ID,
        },
    )
    assert pending.status_code == 400
    assert pending.json()["error"] == "authorization_pending"

    clock.advance(6)
    _approve(client, start["user_code"])

    tokens = client.post(
        "/v1/auth/token",
        json={
            "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
            "device_code": start["device_code"],
            "client_id": CLIENT_ID,
        },
    )
    assert tokens.status_code == 200, tokens.text
    body = tokens.json()
    assert body["token_type"] == "Bearer"
    assert body["access_token"]

    info = client.get("/v1/userinfo", headers={"Authorization": f"Bearer {body['access_token']}"})
    assert info.status_code == 200
    assert info.json()["email"] == "dev@mercadolibre.com"
    assert "analyze" in info.json()["scopes"]


def test_userinfo_requires_a_bearer_token(app_client: tuple[TestClient, FakeClock]) -> None:
    client, _ = app_client
    assert client.get("/v1/userinfo").status_code == 401
    bad = client.get("/v1/userinfo", headers={"Authorization": "Basic abc"})
    assert bad.status_code == 401
    forged = client.get("/v1/userinfo", headers={"Authorization": "Bearer not-a-jwt"})
    assert forged.status_code == 401


def test_wrong_password_renders_an_error_not_a_token(app_client: tuple[TestClient, FakeClock]) -> None:
    client, _ = app_client
    start = _device_start(client)
    r = client.post(
        "/device",
        data={
            "user_code": start["user_code"],
            "email": "dev@mercadolibre.com",
            "password": "nope",
            "action": "approve",
        },
    )
    assert r.status_code == 400
    assert "credenciales" in r.text.lower()


def test_deny_flow(app_client: tuple[TestClient, FakeClock]) -> None:
    client, clock = app_client
    start = _device_start(client)
    r = client.post(
        "/device",
        data={"user_code": start["user_code"], "email": "", "password": "", "action": "deny"},
    )
    assert r.status_code == 200
    clock.advance(6)
    polled = client.post(
        "/v1/auth/token",
        json={
            "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
            "device_code": start["device_code"],
            "client_id": CLIENT_ID,
        },
    )
    assert polled.json()["error"] == "access_denied"


def test_device_page_escapes_the_user_code(app_client: tuple[TestClient, FakeClock]) -> None:
    """The user_code comes from the query string straight into the HTML."""
    client, _ = app_client
    payload = '"><script>alert(1)</script>'
    r = client.get("/device", params={"user_code": payload})
    assert r.status_code == 200
    lowered = r.text.lower()
    assert "<script" not in lowered
    assert "&lt;script" in lowered
    assert "onerror=" not in lowered


def test_refresh_then_reuse_detection_over_http(app_client: tuple[TestClient, FakeClock]) -> None:
    client, clock = app_client
    start = _device_start(client)
    clock.advance(6)
    _approve(client, start["user_code"])
    tokens = client.post(
        "/v1/auth/token",
        json={
            "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
            "device_code": start["device_code"],
            "client_id": CLIENT_ID,
        },
    ).json()

    clock.advance(10)
    refreshed = client.post(
        "/v1/auth/refresh",
        json={"refresh_token": tokens["refresh_token"], "client_id": CLIENT_ID},
    )
    assert refreshed.status_code == 200
    new_token = refreshed.json()["refresh_token"]
    assert new_token != tokens["refresh_token"]

    clock.advance(10)
    reused = client.post(
        "/v1/auth/refresh",
        json={"refresh_token": tokens["refresh_token"], "client_id": CLIENT_ID},
    )
    assert reused.status_code == 400
    assert reused.json()["error"] == "invalid_grant"

    # The family is dead, including the token the legitimate client holds.
    dead = client.post("/v1/auth/refresh", json={"refresh_token": new_token, "client_id": CLIENT_ID})
    assert dead.status_code == 400


def test_revoke_returns_204_and_is_idempotent(app_client: tuple[TestClient, FakeClock]) -> None:
    client, clock = app_client
    start = _device_start(client)
    clock.advance(6)
    _approve(client, start["user_code"])
    tokens = client.post(
        "/v1/auth/token",
        json={
            "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
            "device_code": start["device_code"],
            "client_id": CLIENT_ID,
        },
    ).json()
    body = {"refresh_token": tokens["refresh_token"], "client_id": CLIENT_ID}
    assert client.post("/v1/auth/revoke", json=body).status_code == 204
    assert client.post("/v1/auth/revoke", json=body).status_code == 204


# --------------------------------------------------------------------------- #
# Client
# --------------------------------------------------------------------------- #
def test_token_cache_writes_0600_and_reads_back(client_settings: ClientSettings) -> None:
    cache = TokenCache(client_settings.token_cache, server_url=client_settings.server_url, use_keyring=False)
    cache.save(
        CachedToken(
            refresh_token="r" * 40,
            server_url=client_settings.server_url,
            subject="dev@mercadolibre.com",
            refresh_expires_at=9_999_999_999,
            issued_at=0,
        )
    )
    path = client_settings.token_cache
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert stat.S_IMODE(path.parent.stat().st_mode) == 0o700
    loaded = cache.load()
    assert loaded and loaded.refresh_token == "r" * 40
    assert "r" * 40 in path.read_text()


def test_insecure_cache_permissions_are_refused(client_settings: ClientSettings) -> None:
    cache = TokenCache(client_settings.token_cache, server_url=client_settings.server_url, use_keyring=False)
    cache.save(
        CachedToken(
            refresh_token="r" * 40,
            server_url=client_settings.server_url,
            subject="s",
            refresh_expires_at=9_999_999_999,
            issued_at=0,
        )
    )
    client_settings.token_cache.chmod(0o644)
    with pytest.raises(AuthError, match="readable by group/other"):
        cache.load()


def test_cache_bound_to_another_server_is_ignored(
    client_settings: ClientSettings,
) -> None:
    """A token minted for server A must never be sent to server B."""
    cache_a = TokenCache(client_settings.token_cache, server_url="http://a.test", use_keyring=False)
    cache_a.save(
        CachedToken(
            refresh_token="r" * 40,
            server_url="http://a.test",
            subject="s",
            refresh_expires_at=9_999_999_999,
            issued_at=0,
        )
    )
    cache_b = TokenCache(client_settings.token_cache, server_url="http://b.test", use_keyring=False)
    assert cache_b.load() is None


def test_corrupt_cache_is_dropped_not_fatal(client_settings: ClientSettings) -> None:
    path = client_settings.token_cache
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("{not json", encoding="utf-8")
    path.chmod(0o600)
    cache = TokenCache(path, server_url=client_settings.server_url, use_keyring=False)
    assert cache.load() is None
    assert not path.exists(), "a corrupt cache must be removed, not reused"


def test_env_token_short_circuits_the_cache(
    client_settings: ClientSettings, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("AEGIS_TOKEN", "env-token-value")
    with AuthClient(client_settings, transport=httpx.MockTransport(_fail_handler)) as client:
        assert client.access_token() == "env-token-value"


def test_env_token_can_be_forbidden(client_settings: ClientSettings, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AEGIS_TOKEN", "env-token-value")
    settings = client_settings.model_copy(update={"allow_env_token": False})
    with AuthClient(settings, transport=httpx.MockTransport(_fail_handler)) as client:
        with pytest.raises(AuthError, match="not authenticated"):
            client.access_token()


def test_missing_credentials_produce_an_actionable_error(client_settings: ClientSettings) -> None:
    with AuthClient(client_settings, transport=httpx.MockTransport(_fail_handler)) as client:
        with pytest.raises(AuthError) as exc:
            client.access_token()
    assert "aegis login" in (exc.value.hint or "")


def _fail_handler(request: httpx.Request) -> httpx.Response:  # pragma: no cover - guard
    raise AssertionError(f"unexpected request to {request.url}")


# --------------------------------------------------------------------------- #
# Identity binding
# --------------------------------------------------------------------------- #
def _claims_for(service: AuthService, clock: FakeClock, email: str, scope: str) -> Any:
    import anyio

    resp = service.start_device_authorization(client_id=CLIENT_ID, requested_scope=scope)
    clock.advance(6)
    anyio.run(
        lambda: service.approve_user_code(
            user_code=resp.user_code, email=email, password="correct horse battery"
        )
    )
    tokens = service.poll_token(device_code=resp.device_code, client_id=CLIENT_ID)
    return service.verify_access_token(tokens.access_token)


def test_binding_accepts_matching_identity(service: AuthService, clock: FakeClock) -> None:
    claims = _claims_for(service, clock, "dev@mercadolibre.com", "analyze")
    assert bind_identity(claims, author_email="DEV@MercadoLibre.com") == "dev@mercadolibre.com"


def test_binding_rejects_a_commit_by_someone_else(service: AuthService, clock: FakeClock) -> None:
    claims = _claims_for(service, clock, "dev@mercadolibre.com", "analyze")
    with pytest.raises(AuthError, match="does not match"):
        bind_identity(claims, author_email="someone.else@mercadolibre.com")


def test_analyze_any_allows_acting_for_others(service: AuthService, clock: FakeClock) -> None:
    claims = _claims_for(service, clock, "dev@mercadolibre.com", "analyze:any")
    assert bind_identity(claims, author_email="someone.else@mercadolibre.com")


def test_access_token_is_cached_so_commits_do_not_refresh_every_time(
    client_settings: ClientSettings, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A commit hook must not pay a refresh round-trip per commit.

    The fake clock keeps the cached access token inside its validity window and
    the transport asserts that *no* request is made: the assertion is the point.
    """
    from conftest import FakeClock as _Clock

    clock = _Clock()
    cache = TokenCache(client_settings.token_cache, server_url=client_settings.server_url, use_keyring=False)
    cache.save(
        CachedToken(
            refresh_token="r" * 40,
            server_url=client_settings.server_url,
            subject="dev@mercadolibre.com",
            refresh_expires_at=10_000_000_000,
            issued_at=clock(),
            access_token="cached-access-token",
            access_expires_at=clock() + 600,
        )
    )
    monkeypatch.setattr("aegis.auth.client.time.time", clock)

    with AuthClient(
        client_settings,
        transport=httpx.MockTransport(_fail_handler),
        now=clock,
        cache=cache,
    ) as client:
        assert client.access_token() == "cached-access-token"


def test_expired_cached_access_token_falls_back_to_refresh(
    client_settings: ClientSettings, monkeypatch: pytest.MonkeyPatch
) -> None:
    from conftest import FakeClock as _Clock

    clock = _Clock()
    cache = TokenCache(client_settings.token_cache, server_url=client_settings.server_url, use_keyring=False)
    cache.save(
        CachedToken(
            refresh_token="r" * 40,
            server_url=client_settings.server_url,
            subject="dev@mercadolibre.com",
            refresh_expires_at=10_000_000_000,
            issued_at=clock(),
            access_token="stale",
            access_expires_at=clock() - 10,
        )
    )

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/v1/auth/refresh"
        return httpx.Response(
            200,
            json={
                "access_token": "fresh-token",
                "token_type": "Bearer",
                "expires_in": 3600,
                "refresh_token": "n" * 40,
                "scope": "analyze",
            },
        )

    def fake_userinfo(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={
                "sub": "dev@mercadolibre.com",
                "email": "dev@mercadolibre.com",
                "provider": "local",
                "scopes": ["analyze"],
            },
        )

    def route(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/v1/userinfo":
            return fake_userinfo(request)
        return handler(request)

    with AuthClient(
        client_settings,
        transport=httpx.MockTransport(route),
        now=clock,
        cache=cache,
    ) as client:
        assert client.access_token() == "fresh-token"
