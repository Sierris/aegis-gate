"""GitHub upstream-token exchange and the client-side login loop.

The GitHub provider is the production path (the local provider is for the demo), so
its failure modes get explicit coverage:

* an unverified e-mail must never become an identity;
* a token without ``user:email`` must fail loudly, not fall back to the login name;
* a 401 from GitHub must be a clean ``None`` (credential rejected), not a 500;
* an unreachable API must surface as a transport error, not as "unauthorised".
"""

from __future__ import annotations

from dataclasses import replace
from typing import Any

import httpx
import pytest

from aegis.auth.client import AuthClient, CachedToken, TokenCache
from aegis.auth.provider import GithubIdentityProvider
from aegis.config import ClientSettings
from aegis.errors import AuthError, TransportError
from conftest import FakeClock

API = "https://api.github.test"


def _provider(handler: Any) -> GithubIdentityProvider:
    return GithubIdentityProvider(api_url=API, transport=httpx.MockTransport(handler))


def _ok_emails() -> list[dict[str, Any]]:
    return [
        {"email": "public@example.com", "primary": False, "verified": True},
        {"email": "Dev@MercadoLibre.com", "primary": True, "verified": True},
    ]


@pytest.mark.anyio
async def test_exchange_maps_to_a_normalised_identity() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.headers["Authorization"] == "Bearer good"
        if request.url.path == "/user":
            return httpx.Response(200, json={"id": 99, "login": "sierris", "name": None})
        return httpx.Response(200, json=_ok_emails())

    identity = await _provider(handler).verify_upstream_token(token="good")
    assert identity is not None
    assert identity.sub == "github:99"
    assert identity.email == "dev@mercadolibre.com", "e-mail must be lowercased"
    assert identity.name == "sierris", "falls back to login when the name is empty"
    assert identity.provider == "github"


@pytest.mark.anyio
async def test_unverified_primary_email_is_refused() -> None:
    """A user can add any address to their account; only a verified one is an identity."""

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/user":
            return httpx.Response(200, json={"id": 1, "login": "x"})
        return httpx.Response(
            200,
            json=[{"email": "ceo@mercadolibre.com", "primary": True, "verified": False}],
        )

    with pytest.raises(AuthError, match="no verified primary e-mail"):
        await _provider(handler).verify_upstream_token(token="t")


@pytest.mark.anyio
async def test_missing_email_scope_is_an_explicit_failure() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/user":
            return httpx.Response(200, json={"id": 1, "login": "x"})
        return httpx.Response(404, json={"message": "Not Found"})

    with pytest.raises(AuthError, match="user:email"):
        await _provider(handler).verify_upstream_token(token="t")


@pytest.mark.anyio
async def test_rejected_token_returns_none_not_an_error() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(401, json={"message": "Bad credentials"})

    assert await _provider(handler).verify_upstream_token(token="bad") is None


@pytest.mark.anyio
async def test_unreachable_api_is_a_transport_error() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("dns failure", request=request)

    with pytest.raises(TransportError, match="unreachable"):
        await _provider(handler).verify_upstream_token(token="t")


@pytest.mark.anyio
async def test_oversized_token_is_rejected_without_a_request() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise AssertionError(f"must not be called, got {request.url}")

    with pytest.raises(AuthError, match="invalid upstream token"):
        await _provider(handler).verify_upstream_token(token="x" * 2000)


@pytest.mark.anyio
async def test_password_login_is_not_available_for_github() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise AssertionError(f"not reachable: {request.url}")

    provider = _provider(handler)
    with pytest.raises(AuthError, match="does not accept passwords"):
        await provider.verify_password(email="a@b.com", password="x")


# --------------------------------------------------------------------------- #
# Client login loop
# --------------------------------------------------------------------------- #
def _device_server(
    *, polls_before_approval: int = 2, slow_down_once: bool = True
) -> tuple[httpx.MockTransport, dict[str, Any]]:
    """Stub of the AEGIS auth endpoints that behaves like a real device flow."""
    state: dict[str, Any] = {"polls": 0, "refreshes": 0}

    def handler(request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path == "/v1/auth/device":
            return httpx.Response(
                200,
                json={
                    "device_code": "device-secret-abc",
                    "user_code": "BCDF-GHJK",
                    "verification_uri": "http://aegis.test/device",
                    "verification_uri_complete": "http://aegis.test/device?user_code=BCDF-GHJK",
                    "expires_in": 600,
                    "interval": 1,
                },
            )
        if path == "/v1/auth/token":
            state["polls"] += 1
            if slow_down_once and state["polls"] == 1:
                return httpx.Response(
                    400,
                    json={
                        "error": "slow_down",
                        "error_description": "polling too frequently; use interval=6s",
                    },
                )
            if state["polls"] <= polls_before_approval:
                return httpx.Response(400, json={"error": "authorization_pending"})
            return httpx.Response(
                200,
                json={
                    "access_token": "access-1",
                    "token_type": "Bearer",
                    "expires_in": 3600,
                    "refresh_token": "refresh-1",
                    "scope": "analyze",
                },
            )
        if path == "/v1/userinfo":
            return httpx.Response(
                200,
                json={
                    "sub": "dev@mercadolibre.com",
                    "email": "dev@mercadolibre.com",
                    "provider": "local",
                    "scopes": ["analyze"],
                },
            )
        if path == "/v1/auth/refresh":
            state["refreshes"] += 1
            return httpx.Response(
                200,
                json={
                    "access_token": f"access-{state['refreshes'] + 1}",
                    "token_type": "Bearer",
                    "expires_in": 3600,
                    "refresh_token": "refresh-2",
                    "scope": "analyze",
                },
            )
        if path == "/v1/auth/revoke":
            return httpx.Response(204)
        raise AssertionError(f"unexpected path {path}")

    return httpx.MockTransport(handler), state


def test_login_loop_honours_slow_down_and_stores_the_token(
    client_settings: ClientSettings,
) -> None:
    transport, state = _device_server()
    prompts: list[str] = []
    slept: list[float] = []

    with AuthClient(client_settings, transport=transport) as client:
        subject = client.login(
            on_prompt=lambda msg, **_: prompts.append(msg),
            sleep=slept.append,
            open_browser=False,
        )

    assert subject == "dev@mercadolibre.com"
    assert any("Código: BCDF-GHJK" in p for p in prompts)
    # The first poll says slow_down with interval=6; the client must use 6, not 1.
    assert 6.0 in slept
    cached = client.cache.load()
    assert cached is not None
    assert cached.refresh_token == "refresh-1"
    assert state["polls"] >= 3


def test_logout_revokes_server_side_then_wipes_the_cache(
    client_settings: ClientSettings,
) -> None:
    transport, _ = _device_server()
    with AuthClient(client_settings, transport=transport) as client:
        client.login(on_prompt=None, sleep=lambda _s: None, open_browser=False)
        assert client.cache.load() is not None
        assert client.logout() is True
        assert client.cache.load() is None


def test_logout_without_a_cache_is_safe(client_settings: ClientSettings) -> None:
    transport, _ = _device_server()
    with AuthClient(client_settings, transport=transport) as client:
        assert client.logout() is False


def test_stale_cached_access_token_triggers_a_single_refresh(
    client_settings: ClientSettings,
) -> None:
    """Second scenario for the cache: the access token is present but expired."""
    transport, state = _device_server()
    cache = TokenCache(client_settings.token_cache, server_url=client_settings.server_url, use_keyring=False)
    with AuthClient(client_settings, transport=transport, cache=cache) as client:
        client.login(on_prompt=None, sleep=lambda _s: None, open_browser=False)
        # Simulate a new process an hour later: the access token is stale, the
        # refresh token is not.
        cached = cache.load()
        assert cached is not None
        cache.save(replace(cached, access_expires_at=0.0))
        client._access_token = None
        client._access_expires_at = 0.0

        token = client.access_token()

    assert token.startswith("access-")
    assert state["refreshes"] == 1
    assert cache.load() is not None


def test_keyring_backend_is_preferred_when_available(
    client_settings: ClientSettings, monkeypatch: pytest.MonkeyPatch
) -> None:
    """If a keyring backend exists, no secret file is written at all."""
    store: dict[tuple[str, str], str] = {}

    class FakeKeyring:
        @staticmethod
        def get_password(service: str, account: str) -> str | None:
            return store.get((service, account))

        @staticmethod
        def set_password(service: str, account: str, value: str) -> None:
            store[(service, account)] = value

        @staticmethod
        def delete_password(service: str, account: str) -> None:
            store.pop((service, account), None)

    monkeypatch.setattr("aegis.auth.client._import_keyring", lambda: FakeKeyring)
    cache = TokenCache(client_settings.token_cache, server_url=client_settings.server_url, use_keyring=True)
    assert cache.backend == "keyring"
    cache.save(
        CachedToken(
            refresh_token="r" * 40,
            server_url=client_settings.server_url,
            subject="s",
            refresh_expires_at=10_000_000_000,
            issued_at=0,
        )
    )
    assert not client_settings.token_cache.exists(), "no plaintext file when a keyring exists"
    loaded = cache.load()
    assert loaded is not None and loaded.refresh_token == "r" * 40


def test_transport_failure_is_reported_as_transport_error(
    client_settings: ClientSettings,
) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("connection refused", request=request)

    with AuthClient(client_settings, transport=httpx.MockTransport(handler)) as client:
        with pytest.raises(TransportError) as exc:
            client.start_device_flow()
    assert exc.value.exit_code == 4
    assert "aegis serve" in (exc.value.hint or "")


def test_server_side_auth_error_is_surfaced_verbatim(
    client_settings: ClientSettings,
) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(400, json={"error": "invalid_scope", "error_description": "none issuable"})

    with AuthClient(client_settings, transport=httpx.MockTransport(handler)) as client:
        with pytest.raises(AuthError, match="invalid_scope"):
            client.login(on_prompt=None, sleep=lambda _s: None, open_browser=False)


def test_login_times_out(clock: FakeClock, client_settings: ClientSettings) -> None:
    transport, _ = _device_server(polls_before_approval=10_000, slow_down_once=False)
    with AuthClient(client_settings, transport=transport, now=clock) as client:
        with pytest.raises(AuthError, match="timed out"):
            client.login(
                on_prompt=None,
                sleep=clock.advance,
                open_browser=False,
                max_wait_seconds=30,
            )
