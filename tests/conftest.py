"""Shared fixtures for the auth test suite.

Everything is deterministic: a fake clock drives token/device expiries, SQLite is
per-test in ``tmp_path``, and HTTP is stubbed with ``httpx.MockTransport``. No
test sleeps and no test touches the network.
"""

from __future__ import annotations

import time
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import httpx
import pytest

from aegis.auth import provider as provider_mod
from aegis.auth.keys import SigningKey
from aegis.auth.provider import Identity, LocalIdentityProvider
from aegis.auth.service import AuthService
from aegis.auth.store import AuthStore
from aegis.config import ClientSettings, ServerSettings


class FakeClock:
    """Monotonic-ish clock under test control."""

    def __init__(self, start: float = 1_700_000_000.0) -> None:
        self._now = start

    def __call__(self) -> float:
        return self._now

    def advance(self, seconds: float) -> None:
        self._now += seconds


@pytest.fixture
def clock() -> FakeClock:
    return FakeClock()


@pytest.fixture
def server_settings(tmp_path: Path) -> ServerSettings:
    return ServerSettings(
        env="local",
        public_url="http://aegis.test",
        issuer="http://aegis.test",
        db_path=tmp_path / "aegis.db",
        signing_key_path=tmp_path / "keys" / "aegis.pem",
        access_token_ttl_seconds=3600,
        refresh_token_ttl_seconds=86_400,
        device_code_ttl_seconds=600,
        device_interval_seconds=5,
        auth_provider="local",
        granted_scopes_default=("analyze",),
        granted_scopes_max=("analyze", "analyze:any"),
    )


@pytest.fixture
def store(server_settings: ServerSettings, clock: FakeClock) -> Iterator[AuthStore]:
    s = AuthStore(server_settings.db_path, clock=clock)
    try:
        yield s
    finally:
        s.close()


@pytest.fixture
def key() -> SigningKey:
    return SigningKey.generate()


@pytest.fixture
def local_provider(store: AuthStore) -> LocalIdentityProvider:
    p = LocalIdentityProvider(store)
    p.create_user(email="dev@mercadolibre.com", name="Dev", password="correct horse battery")
    p.create_user(email="other@mercadolibre.com", name="Other", password="another long password")
    return p


@pytest.fixture
def service(
    store: AuthStore,
    key: SigningKey,
    server_settings: ServerSettings,
    local_provider: LocalIdentityProvider,
    clock: FakeClock,
) -> AuthService:
    return AuthService(
        store=store,
        key=key,
        settings=server_settings,
        provider=local_provider,
        now=clock,
    )


@pytest.fixture
def client_settings(tmp_path: Path) -> ClientSettings:
    return ClientSettings(
        server_url="http://aegis.test",
        token_cache=tmp_path / "config" / "token.json",
        timeout_seconds=5,
        fail_mode="closed",
        allow_env_token=True,
    )


@dataclass
class StubGithub:
    """Configurable GitHub API double."""

    user: dict[str, Any] = field(
        default_factory=lambda: {"id": 42, "login": "sierris", "name": "Juan Sierra"}
    )
    emails: list[dict[str, Any]] = field(
        default_factory=lambda: [
            {"email": "noreply@mercadolibre.com", "primary": False, "verified": True},
            {"email": "Dev@MercadoLibre.com", "primary": True, "verified": True},
        ]
    )
    token: str = "gho_valid_token"
    emails_status: int = 200

    def transport(self) -> httpx.MockTransport:
        def handler(request: httpx.Request) -> httpx.Response:
            assert request.headers.get("Authorization") == f"Bearer {self.token}"
            if request.url.path == "/user":
                return httpx.Response(200, json=self.user)
            if request.url.path == "/user/emails":
                return httpx.Response(self.emails_status, json=self.emails)
            raise AssertionError(f"unexpected path {request.url.path}")

        return httpx.MockTransport(handler)

    def provider(self) -> provider_mod.GithubIdentityProvider:
        return provider_mod.GithubIdentityProvider(
            api_url="https://api.github.test", transport=self.transport()
        )


@pytest.fixture
def github() -> StubGithub:
    return StubGithub()


def make_identity(email: str = "dev@mercadolibre.com") -> Identity:
    return Identity(sub=email, email=email, name="Dev", provider="local")


@pytest.fixture(autouse=True)
def _no_env_token(monkeypatch: pytest.MonkeyPatch) -> None:
    """Keep AEGIS_TOKEN from the developer's shell out of the tests."""
    monkeypatch.delenv("AEGIS_TOKEN", raising=False)
    monkeypatch.delenv("AEGIS_OAUTH_CLIENT_ID", raising=False)


def epoch(**overrides: float) -> float:
    base = time.time()
    return base + sum(overrides.values())
