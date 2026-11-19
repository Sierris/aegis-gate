"""OAuth 2.0 Device Authorization Grant (RFC 8628) + token lifecycle.

State machine
-------------
::

    POST /v1/auth/device ──► device_code (secret, client keeps it)
                             user_code   (short, human types it)
                                        │
                        user opens verification_uri in a browser
                                        │
                                        ▼
                             POST /device  ── approved / denied
                                        │
    client polls POST /v1/auth/token ───┤ authorization_pending
                                        │ slow_down            (interval grows)
                                        │ expired_token
                                        │ access_denied
                                        ▼
                                    access_token + refresh_token

Security properties implemented here
-----------------------------------
* **Secrets are compared by hash.** ``device_code`` and refresh tokens are stored
  as digests; the plaintext exists only in the response body.
* **Single use.** A device code is consumed the moment it yields tokens, so a
  replayed poll cannot mint a second session.
* **``slow_down`` accumulates.** Per RFC 8628 §3.5 the interval grows by 5 s and
  the growth is *persisted*, so ignoring the hint is progressively more expensive.
* **Refresh rotation with reuse detection.** Every refresh mints a new token and
  links it to its predecessor. Presenting an already-rotated token proves the
  token leaked (the legitimate client has the successor), so the entire family is
  revoked — the OAuth 2.0 Security BCP's recommended response.
* **Downscope, never upscope.** Requested scopes are intersected with what the
  server is willing to issue; the downgrade is recorded both on the device row
  and in the audit log so repeated attempts are visible.
* **Every terminal event is audited**, with the actor. An analysis is only
  attributable if the token that authorised it can be traced back to a login.

Clock is injected (``now``) so tests are deterministic and never sleep.
"""

from __future__ import annotations

import enum
import secrets
import time
import uuid
from collections.abc import Callable, Iterable
from dataclasses import dataclass

from aegis.auth import jwt as jwt_mod
from aegis.auth import scopes as scopes_mod
from aegis.auth.keys import SigningKey
from aegis.auth.provider import Identity, IdentityProvider
from aegis.auth.store import AuthStore, normalize_user_code
from aegis.config import ServerSettings
from aegis.contracts import (
    AuditAction,
    DeviceAuthorizationResponse,
    TokenResponse,
    UserInfo,
)
from aegis.errors import AuthError

Clock = Callable[[], float]

#: RFC 8628 §6.1 recommends a user-code alphabet with high confusion resistance.
#: Vowels are excluded (no accidental words in a screenshot), as are 0/O and
#: 1/I/L (unreadable in proportionally-spaced fonts). 27 symbols ⇒ 8 chars ≈
#: 38 bits, which combined with the approval rate limit makes guessing a pending
#: code impractical.
_USER_CODE_ALPHABET = "23456789BCDFGHJKMNPQRSTVWXZ"
_USER_CODE_LEN = 8
_USER_CODE_GROUP = 4

#: Bytes of entropy in a device code / refresh token (urlsafe base64 ~= 43 chars).
_SECRET_BYTES = 32

#: RFC 8628 §3.5: how much the interval grows on ``slow_down``.
_SLOW_DOWN_INCREMENT_S = 5

#: Hard cap so a ``slow_down`` loop cannot push a client into multi-hour sleeps.
_MAX_INTERVAL_S = 60


class OAuthErrorCode(enum.StrEnum):
    """RFC 6749 §5.2 / RFC 8628 §3.5 error codes. Closed set: a typo would
    silently turn a rejection into a client misparse."""

    INVALID_REQUEST = "invalid_request"
    INVALID_CLIENT = "invalid_client"
    INVALID_GRANT = "invalid_grant"
    INVALID_SCOPE = "invalid_scope"
    UNAUTHORIZED_CLIENT = "unauthorized_client"
    ACCESS_DENIED = "access_denied"
    AUTHORIZATION_PENDING = "authorization_pending"
    SLOW_DOWN = "slow_down"
    EXPIRED_TOKEN = "expired_token"  # noqa: S105 - RFC 8628 error code, not a secret
    UNSUPPORTED_GRANT_TYPE = "unsupported_grant_type"
    SERVER_ERROR = "server_error"


class OAuthError(Exception):
    """Carries the machine-readable error code the client switches on."""

    def __init__(self, code: OAuthErrorCode, description: str = "") -> None:
        super().__init__(f"{code.value}: {description}" if description else code.value)
        self.code = code
        self.description = description

    @property
    def http_status(self) -> int:
        # RFC 8628 §3.5 uses 400 for pending/slow_down; this is not a success path
        # and must not be treated as one by an HTTP-status-only client.
        return 400


@dataclass(frozen=True, slots=True)
class IssuedTokens:
    """Internal result: the public response plus what the audit log needs."""

    response: TokenResponse
    identity: Identity
    scopes: frozenset[scopes_mod.Scope]
    family_id: str
    jti: str
    event: AuditAction


def generate_user_code() -> str:
    """``XXXX-XXXX`` using rejection-free ``secrets.choice``."""
    chars = "".join(secrets.choice(_USER_CODE_ALPHABET) for _ in range(_USER_CODE_LEN))
    return f"{chars[:_USER_CODE_GROUP]}-{chars[_USER_CODE_GROUP:]}"


def generate_secret() -> str:
    return secrets.token_urlsafe(_SECRET_BYTES)


class AuthService:
    """Provider-agnostic device flow and token lifecycle."""

    def __init__(
        self,
        *,
        store: AuthStore,
        key: SigningKey,
        settings: ServerSettings,
        provider: IdentityProvider,
        now: Clock = time.time,
        audit_key: bytes | None = None,
    ) -> None:
        self._store = store
        self._key = key
        self._settings = settings
        self._provider = provider
        self._now = now
        self._audit_key = audit_key
        self._issuable = scopes_mod.parse_scopes(
            " ".join(settings.granted_scopes_default + settings.granted_scopes_max)
        )

    # -- helpers -----------------------------------------------------------
    @property
    def store(self) -> AuthStore:
        return self._store

    @property
    def key(self) -> SigningKey:
        return self._key

    @property
    def issuer(self) -> str:
        assert self._settings.issuer is not None  # noqa: S101 - set by the validator
        return self._settings.issuer

    def _audit(self, action: AuditAction, actor: str, **detail: object) -> None:
        self._store.append_audit(action=action, actor=actor, detail=dict(detail), key=self._audit_key)

    # -- 1. device authorization request ----------------------------------
    def start_device_authorization(
        self, *, client_id: str, requested_scope: str = ""
    ) -> DeviceAuthorizationResponse:
        """Create a pending device code. No identity is involved yet."""
        if client_id != self._settings.oauth_client_id:
            raise OAuthError(OAuthErrorCode.UNAUTHORIZED_CLIENT, "unknown client_id")

        requested = (
            scopes_mod.parse_scopes(requested_scope)
            if requested_scope
            else scopes_mod.parse_scopes(" ".join(self._settings.granted_scopes_default))
        )
        if not requested:
            raise OAuthError(OAuthErrorCode.INVALID_SCOPE, "empty scope")

        granted = scopes_mod.clamp_requested(requested, self._issuable)
        if not granted:
            # Asking only for things we will never issue (e.g. ``admin``) is not a
            # downscope, it is a refused request: better to say so immediately.
            raise OAuthError(
                OAuthErrorCode.INVALID_SCOPE,
                f"none of the requested scopes are issuable ({scopes_mod.format_scopes(requested)})",
            )
        downgraded = granted != requested

        device_code = generate_secret()
        user_code = generate_user_code()
        # Collision on the 38-bit user code is vanishingly unlikely, but a UNIQUE
        # constraint violation at scale would be an availability bug, so retry.
        for _ in range(5):
            try:
                self._store.create_device_code(
                    device_code=device_code,
                    user_code=user_code,
                    client_id=client_id,
                    requested_scope=scopes_mod.format_scopes(requested),
                    granted_scope=scopes_mod.format_scopes(granted),
                    scope_downgraded=downgraded,
                    interval_s=self._settings.device_interval_seconds,
                    ttl_s=self._settings.device_code_ttl_seconds,
                )
                break
            except Exception:  # sqlite3.IntegrityError, kept broad for driver variance
                user_code = generate_user_code()
        else:  # pragma: no cover - requires 5 consecutive collisions
            raise OAuthError(OAuthErrorCode.SERVER_ERROR, "could not allocate a user code")

        if downgraded:
            # Observable signal: someone is asking for more than the server gives.
            self._audit(
                AuditAction.POLICY_CHANGED,
                actor=client_id,
                event="scope_downgrade",
                requested=scopes_mod.format_scopes(requested),
                granted=scopes_mod.format_scopes(granted),
            )

        return DeviceAuthorizationResponse(
            device_code=device_code,
            user_code=user_code,
            verification_uri=self._settings.verification_uri,
            verification_uri_complete=f"{self._settings.verification_uri}?user_code={user_code}",
            expires_in=self._settings.device_code_ttl_seconds,
            interval=self._settings.device_interval_seconds,
        )

    # -- 2. user approves in the browser ----------------------------------
    async def approve_user_code(self, *, user_code: str, email: str, password: str) -> Identity:
        """Verify the human, then bind their identity to the pending device code."""
        row = self._store.get_device_by_user_code(user_code)
        if row is None:
            # Same error for "no such code" and "expired": no oracle for scanning.
            raise AuthError("invalid or expired user code")
        if row.status != "pending" or row.expires_at <= self._now():
            raise AuthError("invalid or expired user code")

        identity = await self._provider.verify_password(email=email, password=password)
        if identity is None:
            self._audit(
                AuditAction.TOKEN_REVOKED,
                actor=email.lower(),
                event="device_approval_failed",
                user_code=row.user_code,
            )
            raise AuthError("invalid credentials")

        ok = self._store.set_device_status(
            row.user_code,
            "approved",
            identity=(identity.sub, identity.email, identity.name, identity.provider),
        )
        if not ok:
            raise AuthError("invalid or expired user code")
        self._audit(
            AuditAction.TOKEN_ISSUED,
            actor=identity.email,
            event="device_approved",
            user_code=row.user_code,
            scope=row.granted_scope,
        )
        return identity

    def deny_user_code(self, *, user_code: str) -> None:
        if self._store.set_device_status(normalize_user_code(user_code), "denied"):
            self._audit(
                AuditAction.OVERRIDE_DENY, actor="anonymous", event="device_denied", user_code=user_code
            )

    # -- 3. client polls for the token ------------------------------------
    def poll_token(self, *, device_code: str, client_id: str) -> TokenResponse:
        """Exchange a device code for tokens, or raise the RFC 8628 error."""
        if client_id != self._settings.oauth_client_id:
            raise OAuthError(OAuthErrorCode.UNAUTHORIZED_CLIENT, "unknown client_id")

        row = self._store.get_device_by_code(device_code)
        if row is None:
            raise OAuthError(OAuthErrorCode.INVALID_GRANT, "unknown device code")

        if row.expires_at <= self._now():
            raise OAuthError(OAuthErrorCode.EXPIRED_TOKEN, "device code expired")
        if row.status == "denied":
            raise OAuthError(OAuthErrorCode.ACCESS_DENIED, "the user denied the request")
        if row.status == "consumed":
            # A second successful poll would mean the code was reusable.
            raise OAuthError(OAuthErrorCode.INVALID_GRANT, "device code already used")

        if row.status != "approved":
            # RFC 8628 §3.5: a client polling faster than the advertised interval
            # gets ``slow_down`` and the server *increases* the interval, storing
            # the new value. Comparing against ``last_polled_at`` rather than a
            # timestamp derived from the poll count means a client that stops
            # polling (browser open, user away) is not penalised on return.
            if row.last_polled_at is not None and (self._now() - row.last_polled_at) < row.interval_s:
                new_interval = min(row.interval_s + _SLOW_DOWN_INCREMENT_S, _MAX_INTERVAL_S)
                self._store.record_poll(device_code, interval_s=new_interval)
                raise OAuthError(
                    OAuthErrorCode.SLOW_DOWN,
                    f"polling too frequently; use interval={new_interval}s",
                )
            self._store.record_poll(device_code, interval_s=row.interval_s)
            raise OAuthError(OAuthErrorCode.AUTHORIZATION_PENDING, "waiting for user approval")

        # Approved: consume first, then mint. Consuming before issuing means a
        # crash in between loses a login instead of duplicating a session.
        if not self._store.consume_device_code(device_code):
            raise OAuthError(OAuthErrorCode.INVALID_GRANT, "device code already used")

        identity = Identity(
            sub=row.sub or "",
            email=row.email or "",
            name=row.name,
            provider=row.provider or self._provider.name,
        )
        granted = scopes_mod.parse_scopes(row.granted_scope)
        issued = self._issue_tokens(
            identity=identity,
            scopes=granted,
            client_id=client_id,
            family_id=uuid.uuid4().hex,
            event=AuditAction.TOKEN_ISSUED,
            context={"flow": "device_code", "user_code": row.user_code},
        )
        return issued.response

    # -- 4. refresh with rotation + reuse detection ------------------------
    def refresh(self, *, refresh_token: str, client_id: str) -> TokenResponse:
        row = self._store.get_refresh_token(refresh_token)
        if row is None:
            raise OAuthError(OAuthErrorCode.INVALID_GRANT, "unknown refresh token")
        if row.client_id != client_id:
            raise OAuthError(OAuthErrorCode.INVALID_GRANT, "refresh token was issued to another client")

        if row.rotated_to is not None:
            # Reuse of a rotated token ⇒ two parties hold the same secret.
            revoked = self._store.revoke_family(row.family_id, "refresh_token_reuse")
            self._audit(
                AuditAction.TOKEN_REVOKED,
                actor=row.email,
                event="refresh_reuse_detected",
                family_id=row.family_id,
                tokens_revoked=revoked,
            )
            raise OAuthError(
                OAuthErrorCode.INVALID_GRANT,
                "refresh token already used; the session family has been revoked",
            )
        if row.revoked:
            raise OAuthError(OAuthErrorCode.INVALID_GRANT, f"refresh token revoked ({row.revoked_reason})")
        if row.expires_at <= self._now():
            raise OAuthError(OAuthErrorCode.INVALID_GRANT, "refresh token expired")

        identity = Identity(sub=row.sub, email=row.email, name=row.name, provider=row.provider)
        granted = scopes_mod.parse_scopes(row.scope)
        issued = self._issue_tokens(
            identity=identity,
            scopes=granted,
            client_id=client_id,
            family_id=row.family_id,
            event=AuditAction.TOKEN_ISSUED,
            context={"flow": "refresh", "family_id": row.family_id},
        )
        # Link old -> new only *after* the successor exists. The reverse order
        # (mark rotated, then issue) would let a crash leave a token that looks
        # already-used to its legitimate holder, triggering a false theft alarm
        # and revoking a healthy family.
        new_token = issued.response.refresh_token
        if not new_token:  # pragma: no cover - _issue_tokens always mints one
            raise OAuthError(OAuthErrorCode.SERVER_ERROR, "refresh token was not issued")
        self._store.mark_refresh_rotated(refresh_token, new_token)
        return issued.response

    # -- 5. revocation -----------------------------------------------------
    def revoke(self, *, refresh_token: str, client_id: str) -> None:
        row = self._store.get_refresh_token(refresh_token)
        if row is None or row.client_id != client_id:
            # RFC 7009 §2.2: revoking an unknown token is a success, to avoid an
            # oracle that tells an attacker whether a stolen token is valid.
            return
        self._store.revoke_family(row.family_id, "user_revoked")
        self._audit(AuditAction.TOKEN_REVOKED, actor=row.email, event="logout", family_id=row.family_id)

    # -- 6. verification ---------------------------------------------------
    def verify_access_token(self, token: str) -> jwt_mod.AccessTokenClaims:
        return jwt_mod.decode_access_token(
            token,
            public_key=self._key,
            issuer=self.issuer,
            now=self._now,
            leeway_seconds=self._settings.clock_skew_seconds,
        )

    def userinfo(self, claims: jwt_mod.AccessTokenClaims) -> UserInfo:
        return UserInfo(
            sub=claims.sub,
            email=claims.email,
            name=claims.name,
            provider=claims.provider,
            scopes=tuple(sorted(s.value for s in claims.scopes)),
        )

    # -- internal ----------------------------------------------------------
    def _issue_tokens(
        self,
        *,
        identity: Identity,
        scopes: frozenset[scopes_mod.Scope],
        client_id: str,
        family_id: str,
        event: AuditAction,
        context: dict[str, object],
    ) -> IssuedTokens:
        if not scopes:
            raise OAuthError(OAuthErrorCode.INVALID_SCOPE, "empty scope")
        jti = uuid.uuid4().hex
        access_token = jwt_mod.encode_access_token(
            key=self._key,
            issuer=self.issuer,
            subject=identity.sub,
            email=identity.email,
            name=identity.name,
            provider=identity.provider,
            scopes=scopes,
            ttl_seconds=self._settings.access_token_ttl_seconds,
            jti=jti,
            now=self._now,
        )
        refresh_token = generate_secret()
        self._store.create_refresh_token(
            token=refresh_token,
            family_id=family_id,
            sub=identity.sub,
            email=identity.email,
            name=identity.name,
            provider=identity.provider,
            scope=scopes_mod.format_scopes(scopes),
            client_id=client_id,
            ttl_s=self._settings.refresh_token_ttl_seconds,
        )
        self._audit(
            event,
            actor=identity.email,
            jti=jti,
            sub=identity.sub,
            scope=scopes_mod.format_scopes(scopes),
            provider=identity.provider,
            **context,
        )
        return IssuedTokens(
            response=TokenResponse(
                access_token=access_token,
                expires_in=self._settings.access_token_ttl_seconds,
                refresh_token=refresh_token,
                scope=scopes_mod.format_scopes(scopes),
            ),
            identity=identity,
            scopes=scopes,
            family_id=family_id,
            jti=jti,
            event=event,
        )

    # -- upstream token exchange ------------------------------------------
    async def exchange_upstream_token(
        self, *, upstream_token: str, client_id: str, requested_scope: str = ""
    ) -> TokenResponse:
        """Trade an IdP token (e.g. GitHub) for an AEGIS access token."""
        if client_id != self._settings.oauth_client_id:
            raise OAuthError(OAuthErrorCode.UNAUTHORIZED_CLIENT, "unknown client_id")

        identity = await self._provider.verify_upstream_token(token=upstream_token)
        if identity is None:
            raise AuthError("upstream token rejected by the identity provider")

        requested = (
            scopes_mod.parse_scopes(requested_scope)
            if requested_scope
            else scopes_mod.parse_scopes(" ".join(self._settings.granted_scopes_default))
        )
        granted = scopes_mod.clamp_requested(requested, self._issuable)
        if not granted:
            raise OAuthError(OAuthErrorCode.INVALID_SCOPE, "no issuable scope requested")

        issued = self._issue_tokens(
            identity=identity,
            scopes=granted,
            client_id=client_id,
            family_id=uuid.uuid4().hex,
            event=AuditAction.TOKEN_ISSUED,
            context={"flow": "upstream_exchange", "upstream": identity.provider},
        )
        return issued.response


def scopes_from_list(values: Iterable[str]) -> frozenset[scopes_mod.Scope]:
    """Convenience for callers holding a list of scope strings."""
    return scopes_mod.parse_scopes(" ".join(values))


__all__ = [
    "AuthService",
    "IssuedTokens",
    "OAuthError",
    "OAuthErrorCode",
    "generate_secret",
    "generate_user_code",
    "scopes_from_list",
]
