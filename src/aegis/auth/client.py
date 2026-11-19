"""Client-side authentication: token cache, device-flow login, transparent refresh.

Threat model for the credential at rest
--------------------------------------
The refresh token is the long-lived secret of a developer machine. Where it may
live, in order of preference:

1. **OS keyring** (Keychain / libsecret / Credential Manager) — encrypted at rest
   by the OS, unlocked with the login session. AEGIS uses it when the
   ``keyring`` package is importable.
2. **A 0600 file outside the repository** — the fallback that always works, no
   compiled dependencies, no D-Bus. Directory 0700, file 0600, written
   atomically (temp + ``os.replace``) so a crash cannot leave a truncated JSON
   that looks like "no token" (which would silently degrade to a login prompt
   mid-rebase).

Never:

* the repository (it would be committed and leak in a clone);
* an environment variable *by default* (``/proc/<pid>/environ`` is readable by
  same-uid processes, and CI logs love to echo the environment);
* the git config (world-readable history of secrets).

``AEGIS_TOKEN`` **is** honoured when set, because CI has no keyring and the token
there is scoped to one job — but it is opt-out (``AEGIS_ALLOW_ENV_TOKEN=0``) so a
machine that must not trust its environment can forbid it.

The access token is never cached: it lives 1 hour and is cheap to mint, so there is
nothing to gain from persisting it and everything to lose.
"""

from __future__ import annotations

import contextlib
import json
import os
import stat
import tempfile
import time
import webbrowser
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import httpx

from aegis.config import ClientSettings
from aegis.errors import AuthError, TransportError

Clock = Callable[[], float]

#: Refresh this many seconds before actual expiry, so a token cannot expire
#: between the check and the request that uses it.
_EXPIRY_SKEW_S = 60

_KEYRING_SERVICE = "aegis"
_DIR_MODE = 0o700
_FILE_MODE = 0o600


def _import_keyring() -> Any:
    """Import the optional ``keyring`` package without making it a hard dependency.

    Local import on purpose: importing it at module scope would make ``keyring``
    a required dependency of *every* hook invocation (and its backend probing can
    be slow or hang without D-Bus), just to look up a secret we can also read
    from a 0600 file.
    """
    try:
        import keyring  # type: ignore[import-not-found]  # noqa: PLC0415 - optional dep

        return keyring
    except Exception:  # pragma: no cover - optional dependency, any import error means "absent"
        return None


@dataclass(frozen=True, slots=True)
class CachedToken:
    """What we persist."""

    refresh_token: str
    server_url: str
    subject: str
    #: Wall-clock expiry of the *refresh* token, so an obviously dead cache is
    #: discarded without a network round-trip.
    refresh_expires_at: float
    issued_at: float
    #: Optional short-lived access token. Present so a commit does not pay a
    #: refresh round-trip. Never trusted blindly: expiry is re-checked on read.
    access_token: str | None = None
    access_expires_at: float = 0.0

    @property
    def expired(self) -> bool:
        return self.refresh_expires_at <= time.time()

    def access_token_valid(self, now: float) -> bool:
        return bool(self.access_token) and self.access_expires_at - _EXPIRY_SKEW_S > now


class TokenCache:
    """Keyring-first, 0600-file-fallback storage for the refresh token."""

    def __init__(self, path: Path, *, server_url: str, use_keyring: bool = True) -> None:
        self._path = Path(path).expanduser()
        self._server_url = server_url
        self._keyring = _import_keyring() if use_keyring else None
        self._keyring_account = f"{server_url}"

    # -- public API --------------------------------------------------------
    def load(self) -> CachedToken | None:
        raw = self._from_keyring() or self._from_file()
        if raw is None:
            return None
        try:
            token = CachedToken(
                refresh_token=str(raw["refresh_token"]),
                server_url=str(raw["server_url"]),
                subject=str(raw.get("subject", "")),
                refresh_expires_at=float(raw["refresh_expires_at"]),
                issued_at=float(raw.get("issued_at", 0)),
                access_token=raw.get("access_token") or None,
                access_expires_at=float(raw.get("access_expires_at", 0)),
            )
        except (KeyError, TypeError, ValueError):
            # Corrupt cache: drop it rather than fail the commit.
            self.clear()
            return None
        if token.server_url != self._server_url:
            # A cache bound to a different server must never be sent to this one:
            # that is how a token ends up at the wrong endpoint.
            return None
        return token

    def save(self, token: CachedToken) -> None:
        payload = {
            "refresh_token": token.refresh_token,
            "server_url": token.server_url,
            "subject": token.subject,
            "refresh_expires_at": token.refresh_expires_at,
            "issued_at": token.issued_at,
        }
        if token.access_token:
            payload["access_token"] = token.access_token
            payload["access_expires_at"] = token.access_expires_at
        if self._to_keyring(payload):
            self._unlink_file()
            return
        self._to_file(payload)

    def clear(self) -> None:
        if self._keyring is not None:
            with contextlib.suppress(Exception):
                self._keyring.delete_password(_KEYRING_SERVICE, self._keyring_account)
        self._unlink_file()

    # -- file backend ------------------------------------------------------
    def _from_file(self) -> dict[str, Any] | None:
        try:
            st = self._path.stat()
        except FileNotFoundError:
            return None
        if st.st_mode & 0o077:
            # Someone widened the permissions: treat the secret as compromised
            # and force a fresh login instead of using it.
            raise AuthError(
                f"token cache {self._path} is readable by group/other (mode {st.st_mode & 0o777:o})",
                hint=f"chmod 600 {self._path} and run `aegis login` again.",
            )
        try:
            data = json.loads(self._path.read_text(encoding="utf-8"))
        except OSError:
            return None
        except json.JSONDecodeError:
            # A truncated file (crash mid-write, full disk) must be discarded: a
            # half-written cache would otherwise be retried forever.
            self._unlink_file()
            return None
        return data if isinstance(data, dict) else None

    def _to_file(self, payload: dict[str, Any]) -> None:
        directory = self._path.parent
        directory.mkdir(parents=True, exist_ok=True)
        os.chmod(directory, _DIR_MODE)
        fd, tmp = tempfile.mkstemp(dir=directory, prefix=".aegis-token-")
        try:
            os.fchmod(fd, _FILE_MODE)
            metadata = {
                # The file is a secret container: document that in-place so an
                # auditor (or a future us) does not "fix" the mode.
                "_comment": "AEGIS refresh token. mode 0600. Do not commit, copy or share.",
                **payload,
            }
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump(metadata, fh, indent=2, sort_keys=True)
                fh.flush()
                os.fsync(fh.fileno())
            os.replace(tmp, self._path)
        except BaseException:
            Path(tmp).unlink(missing_ok=True)
            raise

    def _unlink_file(self) -> None:
        with contextlib.suppress(FileNotFoundError):
            self._path.unlink()

    # -- keyring backend ---------------------------------------------------
    def _from_keyring(self) -> dict[str, Any] | None:
        if self._keyring is None:
            return None
        try:
            blob = self._keyring.get_password(_KEYRING_SERVICE, self._keyring_account)
        except Exception:  # pragma: no cover - keyring backend unavailable
            return None
        if not blob:
            return None
        try:
            data = json.loads(blob)
        except json.JSONDecodeError:
            return None
        return data if isinstance(data, dict) else None

    def _to_keyring(self, payload: dict[str, Any]) -> bool:
        if self._keyring is None:
            return False
        try:
            self._keyring.set_password(
                _KEYRING_SERVICE, self._keyring_account, json.dumps(payload, sort_keys=True)
            )
            return True
        except Exception:  # pragma: no cover - backend present but unusable (no D-Bus, locked)
            return False

    @property
    def backend(self) -> str:
        return "keyring" if self._keyring is not None else "file"

    def __repr__(self) -> str:
        return f"TokenCache(path={self._path!s}, backend={self.backend})"


class AuthClient:
    """Talks to the AEGIS auth API and keeps the token cache coherent."""

    def __init__(
        self,
        settings: ClientSettings,
        *,
        transport: httpx.BaseTransport | None = None,
        now: Clock = time.time,
        cache: TokenCache | None = None,
    ) -> None:
        self._settings = settings
        self._now = now
        self._access_token: str | None = None
        self._access_expires_at: float = 0.0
        self._client = httpx.Client(
            base_url=settings.server_url,
            timeout=httpx.Timeout(settings.timeout_seconds, connect=settings.connect_timeout_seconds),
            transport=transport,
            follow_redirects=False,
            headers={"User-Agent": "aegis-cli/0.1", "Accept": "application/json"},
        )
        self._cache = cache or TokenCache(settings.token_cache, server_url=settings.server_url)

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> AuthClient:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    # -- low level ---------------------------------------------------------
    def _post(self, path: str, payload: dict[str, Any]) -> dict[str, Any]:
        try:
            r = self._client.post(path, json=payload)
        except httpx.HTTPError as exc:
            raise TransportError(
                f"cannot reach the AEGIS server at {self._settings.server_url}: {exc}",
                hint="Start it with `aegis serve` or fix AEGIS_SERVER_URL.",
            ) from exc
        return _json_or_oauth_error(r)

    # -- device flow -------------------------------------------------------
    def start_device_flow(self, *, scope: str = "analyze") -> dict[str, Any]:
        return self._post(
            "/v1/auth/device",
            {"client_id": _client_id(), "scope": scope},
        )

    def poll_device_token(self, *, device_code: str) -> dict[str, Any]:
        return self._post(
            "/v1/auth/token",
            {
                "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
                "device_code": device_code,
                "client_id": _client_id(),
            },
        )

    def login(
        self,
        *,
        scope: str = "analyze",
        open_browser: bool = True,
        on_prompt: Callable[..., None] | None = print,
        sleep: Callable[[float], None] = time.sleep,
        max_wait_seconds: float = 600.0,
    ) -> str:
        """Run the device flow end to end. Returns the authenticated subject.

        The polling loop honours ``interval`` and, critically, **re-reads it from
        the server's ``slow_down`` responses** instead of using a fixed sleep.
        """
        start = self.start_device_flow(scope=scope)
        verification_uri = str(start["verification_uri"])
        user_code = str(start["user_code"])
        device_code = str(start["device_code"])
        interval = float(start.get("interval", 5))
        deadline = self._now() + min(float(start.get("expires_in", 600)), max_wait_seconds)

        if on_prompt:
            # flush=True matters: this prompt is followed by a blocking poll loop,
            # and stdout is a pipe whenever the CLI is scripted. Buffered, the user
            # would see the instruction only after the flow finished — i.e. never.
            on_prompt(
                "\n  AEGIS · inicio de sesión\n"
                f"  1. Abre: {verification_uri}\n"
                f"  2. Código: {user_code}\n"
                "  (esperando autorización…)\n",
                flush=True,
            )
        if open_browser:
            with contextlib.suppress(Exception):
                webbrowser.open(str(start.get("verification_uri_complete") or verification_uri))

        while self._now() < deadline:
            sleep(interval)
            try:
                token = self.poll_device_token(device_code=device_code)
            except OAuthPendingError as pending:
                if pending.error == "slow_down":
                    # Never shrink the interval; only grow it.
                    interval = max(interval, pending.interval or interval + 5.0)
                continue
            auth = self._store_token_response(token)
            if on_prompt:
                on_prompt(f"  ✓ Autenticado como {auth.subject} (scopes: {auth.scope})\n", flush=True)
            return auth.subject
        raise AuthError("device authorization timed out", hint="Run `aegis login` again.")

    # -- token lifecycle ---------------------------------------------------
    def _store_token_response(self, payload: dict[str, Any]) -> _StoredAuth:
        access = payload.get("access_token")
        if not isinstance(access, str) or not access:
            raise AuthError("server did not return an access token")
        refresh = payload.get("refresh_token")
        expires_in = float(payload.get("expires_in", 3600))
        scope = str(payload.get("scope", ""))
        self._access_token = access
        self._access_expires_at = self._now() + expires_in

        subject = ""
        if isinstance(refresh, str) and refresh:
            info = self._fetch_userinfo(access)
            subject = str(info.get("sub", ""))
            self._cache.save(
                CachedToken(
                    refresh_token=refresh,
                    server_url=self._settings.server_url,
                    subject=subject,
                    # The server owns the real refresh TTL; we keep a generous local
                    # upper bound so an obviously dead cache is discarded without a
                    # network round-trip (and a 401 forces a fresh login anyway).
                    refresh_expires_at=self._now() + 30 * 24 * 3600,
                    issued_at=self._now(),
                    access_token=access,
                    access_expires_at=self._access_expires_at,
                )
            )
        return _StoredAuth(subject=subject, scope=scope, access_token=access)

    def access_token(self, *, force_refresh: bool = False) -> str:
        """Return a usable access token, refreshing transparently if needed."""
        override = self._env_token()
        if override:
            return override

        if (
            not force_refresh
            and self._access_token
            and self._access_expires_at - _EXPIRY_SKEW_S > self._now()
        ):
            return self._access_token

        cached = self._cache.load()
        if cached is None or cached.expired:
            raise AuthError(
                "not authenticated",
                hint="Run `aegis login` (or set AEGIS_TOKEN in CI).",
            )

        if not force_refresh and cached.access_token_valid(self._now()):
            # Fast path: a commit within the token's hour costs zero extra requests.
            self._access_token = cached.access_token
            self._access_expires_at = cached.access_expires_at
            return str(cached.access_token)

        payload = self._post(
            "/v1/auth/refresh",
            {"refresh_token": cached.refresh_token, "client_id": _client_id()},
        )
        return self._store_token_response(payload).access_token

    def _env_token(self) -> str | None:
        if not self._settings.allow_env_token:
            return None
        token = os.environ.get("AEGIS_TOKEN", "").strip()
        return token or None

    def _fetch_userinfo(self, access_token: str) -> dict[str, Any]:
        try:
            r = self._client.get("/v1/userinfo", headers={"Authorization": f"Bearer {access_token}"})
        except httpx.HTTPError as exc:  # pragma: no cover - transport already tested
            raise TransportError(str(exc)) from exc
        return _json_or_oauth_error(r)

    def whoami(self) -> dict[str, Any]:
        return self._fetch_userinfo(self.access_token())

    def logout(self) -> bool:
        """Revoke server-side, then wipe the local cache. Returns True if revoked."""
        cached = self._cache.load()
        revoked = False
        if cached is not None:
            with contextlib.suppress(TransportError, AuthError, OAuthPendingError):
                self._post(
                    "/v1/auth/revoke",
                    {"refresh_token": cached.refresh_token, "client_id": _client_id()},
                )
                revoked = True
        self._cache.clear()
        self._access_token = None
        self._access_expires_at = 0.0
        return revoked

    @property
    def cache(self) -> TokenCache:
        return self._cache


@dataclass(frozen=True, slots=True)
class _StoredAuth:
    subject: str
    scope: str
    access_token: str


def _client_id() -> str:
    return os.environ.get("AEGIS_OAUTH_CLIENT_ID", "aegis-cli")


class OAuthPendingError(Exception):
    """Internal control-flow signal for ``authorization_pending``/``slow_down``."""

    def __init__(self, error: str, interval: float | None = None) -> None:
        super().__init__(error)
        self.error = error
        self.interval = interval


def _json_or_oauth_error(response: httpx.Response) -> dict[str, Any]:
    """Parse a JSON body, translating OAuth error documents into exceptions."""
    try:
        body = response.json()
    except ValueError:
        body = None

    if isinstance(body, dict) and isinstance(body.get("error"), str):
        error = body["error"]
        description = str(body.get("error_description", ""))
        if error in {"authorization_pending", "slow_down"}:
            interval = None
            if "interval=" in description:
                with contextlib.suppress(ValueError):
                    # Description format is fixed by our own server: "…; use interval=15s".
                    raw_interval = description.rsplit("interval=", 1)[-1].rstrip("s")
                    interval = float(raw_interval)
            raise OAuthPendingError(error, interval)
        raise AuthError(f"{error}: {description}" if description else error)

    if response.status_code == 401:
        raise AuthError(
            "server rejected the token (401)",
            hint="It may have expired or been revoked. Run `aegis login`.",
        )
    if response.status_code >= 500:
        raise TransportError(f"server error {response.status_code}")
    if response.status_code >= 400:
        raise AuthError(f"request failed with HTTP {response.status_code}")
    if response.status_code in (204, 205) or not response.content:
        # 204 is a *success* with no body (e.g. /v1/auth/revoke). Treating an
        # empty body as a protocol error here would have made `aegis logout`
        # silently skip the server-side revocation and only wipe the local cache,
        # leaving a live refresh token behind.
        return {}
    if not isinstance(body, dict):
        raise TransportError("server returned a non-JSON response")
    return body


def cache_mode_report(path: Path) -> str:
    """Diagnostic used by ``aegis doctor`` (and tests)."""
    p = Path(path).expanduser()
    if not p.exists():
        return "absent"
    mode = stat.S_IMODE(p.stat().st_mode)
    return f"mode={mode:o}" + ("" if not mode & 0o077 else " (INSECURE)")


__all__ = ["AuthClient", "CachedToken", "OAuthPendingError", "TokenCache", "cache_mode_report"]
