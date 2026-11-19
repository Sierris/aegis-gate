"""Typed, validated configuration for both sides of AEGIS.

Two settings classes share the ``AEGIS_`` prefix but are loaded independently:
the server reads infra/provider secrets, the client reads endpoint/cache paths.
A single machine running both simply has both sets in its ``.env``.

Design notes
------------
* **No magic defaults for secrets.** Anything sensitive is ``SecretStr`` or
  ``Optional`` with no value; the server refuses to start in ``prod`` if it is
  missing, instead of silently falling back to something insecure.
* **Paths are materialised and permissioned by the consumer** (``auth.keys``),
  not here: this module stays side-effect free, which keeps it safe to import
  from a hook that must never write outside its sandbox.
* **``extra="ignore"``** so a client machine can carry server-only variables in
  the same ``.env`` without exploding.
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Literal

from pydantic import Field, SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

Environment = Literal["local", "ci", "prod"]
ProviderName = Literal["local", "github"]

#: Default port. Chosen to avoid collisions with the usual suspects (3000, 8000,
#: 8080 is often Burp; 8088 is free in a typical dev box).
DEFAULT_PORT = 8088


class _BaseSettings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="AEGIS_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False,
    )


class ServerSettings(_BaseSettings):
    """Server-side configuration (analysis API, auth, signing)."""

    env: Environment = "local"

    # --- Network ----------------------------------------------------------
    listen: str = f"127.0.0.1:{DEFAULT_PORT}"
    #: Public base URL. Used as JWT ``iss`` and to build the device-flow
    #: ``verification_uri``, so it must be the URL a *user* can reach — not the
    #: bind address. Behind a proxy these differ; hence two fields.
    public_url: str = f"http://127.0.0.1:{DEFAULT_PORT}"
    issuer: str | None = None
    cors_origins: tuple[str, ...] = ()

    # --- Storage ----------------------------------------------------------
    db_path: Path = Path(".aegis/aegis.db")

    # --- Signing ----------------------------------------------------------
    #: Ed25519 private key (PKCS#8 PEM). Signs access tokens now and attestations
    #: from step 5. Created on first boot with 0600 if absent.
    signing_key_path: Path = Path(".aegis/keys/aegis_ed25519.pem")

    # --- Token lifetimes --------------------------------------------------
    access_token_ttl_seconds: int = Field(default=3600, ge=60, le=86400)
    refresh_token_ttl_seconds: int = Field(default=30 * 24 * 3600, ge=3600)
    device_code_ttl_seconds: int = Field(default=600, ge=60, le=3600)
    device_interval_seconds: int = Field(default=5, ge=1, le=60)
    #: Clock skew tolerated when verifying tokens issued by us. Small on purpose:
    #: both ends are usually the same fleet, and a large skew window widens the
    #: replay window of an expired token.
    clock_skew_seconds: int = Field(default=30, ge=0, le=300)

    # --- OAuth / identity -------------------------------------------------
    auth_provider: ProviderName = "local"
    oauth_client_id: str = "aegis-cli"
    #: GitHub OAuth App used for the upstream-token exchange flow.
    github_client_id: str | None = None
    github_client_secret: SecretStr | None = None
    github_api_url: str = "https://api.github.com"

    # --- Policy -----------------------------------------------------------
    #: Scopes a client may request in the device flow. ``override`` is excluded
    #: by default: it must be granted explicitly, not self-requested.
    granted_scopes_default: tuple[str, ...] = ("analyze",)
    granted_scopes_max: tuple[str, ...] = ("analyze", "analyze:any")
    #: Empty tuple means "any repository". Populate it in prod to stop a token
    #: minted for repo A from producing attestations for repo B.
    allowed_repos: tuple[str, ...] = ()

    # --- LLM (Command Code Provider API) ----------------------------------
    llm_provider: Literal["commandcode", "fake"] = "commandcode"
    #: Model id as published by ``GET /provider/v1/models``. ``gpt-6-luna`` is a
    #: deliberate default: it is included in the base plan, supports structured
    #: output, and is strong at data-flow reasoning. Claude models require a Pro
    #: plan and answer on the Anthropic Messages wire (supported, untested here).
    llm_model: str = "gpt-6-luna"
    llm_base_url: str = "https://api.commandcode.ai/provider/v1"
    #: Explicit key. If empty, ``COMMAND_CODE_API_KEY`` and the CLI/provider auth
    #: files are tried, in that order (see ``llm.commandcode.resolve_api_key``).
    llm_api_key: SecretStr | None = None
    #: ``auto`` | ``chat`` | ``messages``. ``auto`` asks the catalog.
    llm_wire: Literal["auto", "chat", "messages"] = "auto"
    llm_timeout_seconds: float = Field(default=60.0, gt=0, le=300)
    #: Reasoning models spend this budget on their reasoning channel before they
    #: emit a single answer token; too small a value yields an empty answer.
    llm_max_output_tokens: int = Field(default=4000, ge=256, le=32768)
    llm_temperature: float = Field(default=0.0, ge=0.0, le=2.0)
    #: Send ``x-cmd-zdr: 1`` so the provider does not retain the reviewed code.
    #: On by default: the payload is a company's unreleased source code.
    llm_zdr: bool = True

    # --- Analysis engine --------------------------------------------------
    prompt_dir: Path = Path("prompts")
    prompt_file: str = "analyze.v1.md"
    #: Cache of verdicts by (payload, prompt version, model, policy). Disable in
    #: environments where the model output must never be reused.
    analysis_cache_enabled: bool = True
    analysis_cache_ttl_seconds: int = Field(default=7 * 24 * 3600, ge=0)
    #: When the model reports nothing but the deterministic floor found a blocking
    #: pattern, refuse to allow. This is the anti-prompt-injection backstop; only
    #: disable it to investigate a specific false positive.
    strict_cross_check: bool = True

    # --- Anti-abuse -------------------------------------------------------
    #: Failed user_code submissions per client IP before the flow is locked.
    device_code_attempt_limit: int = Field(default=10, ge=1, le=1000)
    device_code_attempt_window_seconds: int = Field(default=300, ge=10)

    @field_validator("public_url", "issuer")
    @classmethod
    def _strip_slash(cls, v: str | None) -> str | None:
        return v.rstrip("/") if isinstance(v, str) else v

    @model_validator(mode="after")
    def _issuer_defaults_to_public_url(self) -> ServerSettings:
        """``iss`` must be stable: it is part of every token the fleet verifies."""
        if self.issuer is None:
            object.__setattr__(self, "issuer", self.public_url)
        return self

    @model_validator(mode="after")
    def _prod_hardening(self) -> ServerSettings:
        if self.env != "prod":
            return self
        problems: list[str] = []
        if not self.public_url.startswith("https://"):
            problems.append("AEGIS_PUBLIC_URL must be https in prod")
        if self.auth_provider == "github" and not self.github_client_id:
            problems.append("AEGIS_GITHUB_CLIENT_ID is required when AEGIS_AUTH_PROVIDER=github")
        if self.llm_provider == "fake":
            problems.append("AEGIS_LLM_PROVIDER=fake is not a production analyser")
        if not self.allowed_repos:
            problems.append("AEGIS_ALLOWED_REPOS must be set in prod (prevents cross-repo attestations)")
        if problems:
            raise ValueError("; ".join(problems))
        return self

    @property
    def llm_key(self) -> str:
        """Resolved API key (never logged). Empty when none is available."""
        explicit = self.llm_api_key.get_secret_value() if self.llm_api_key else None
        from aegis.llm.commandcode import resolve_api_key  # noqa: PLC0415 - avoids an import cycle

        return resolve_api_key(explicit)

    @property
    def verification_uri(self) -> str:
        return f"{self.public_url}/device"

    @property
    def jwks_uri(self) -> str:
        return f"{self.public_url}/v1/keys"


class ClientSettings(_BaseSettings):
    """Hook / CLI configuration."""

    server_url: str = f"http://127.0.0.1:{DEFAULT_PORT}"
    #: Where the refresh token lives. Kept out of the repository and out of the
    #: environment on purpose (see ``auth.client.TokenCache``).
    token_cache: Path = Path("~/.config/aegis/token.json")
    timeout_seconds: float = Field(default=60.0, gt=0, le=600)
    connect_timeout_seconds: float = Field(default=5.0, gt=0, le=60)
    #: Behaviour when the analysis server is unreachable. ``closed`` blocks the
    #: commit; ``open`` allows it and leaves a loud warning. See ADR-005.
    fail_mode: Literal["closed", "open"] = "closed"
    verbose: bool = False
    #: Honour ``AEGIS_TOKEN`` from the environment (useful in CI, and the only
    #: supported mechanism there — no keyring, no cache file).
    allow_env_token: bool = True

    @field_validator("server_url")
    @classmethod
    def _strip_trailing_slash(cls, v: str) -> str:
        if not v.startswith(("http://", "https://")):
            raise ValueError("AEGIS_SERVER_URL must start with http:// or https://")
        return v.rstrip("/")

    @field_validator("token_cache")
    @classmethod
    def _expand(cls, v: Path) -> Path:
        return Path(v).expanduser()


@lru_cache(maxsize=1)
def get_server_settings() -> ServerSettings:
    """Cached accessor. Cached so a hook process reads ``.env`` exactly once."""
    return ServerSettings()


@lru_cache(maxsize=1)
def get_client_settings() -> ClientSettings:
    return ClientSettings()
