"""Identity providers.

AEGIS supports two ways of establishing *who* is committing, behind one
protocol:

``local``
    Email + password verified against the server's own user table. Zero external
    dependencies, fully demonstrable offline, and the only mode the test suite
    and CI use. Passwords are stored with scrypt (memory-hard, stdlib, no native
    build step) in a self-describing format so parameters can be upgraded later
    without a schema migration.

``github``
    *Upstream token exchange*: the client performs GitHub's own OAuth 2.0 Device
    Flow (RFC 8628) and hands us the resulting token. We verify it **server-side**
    by calling GitHub's API for the authenticated user and their verified primary
    e-mail, then issue our own short-lived AEGIS token. The upstream token is
    never stored.

Why not a full browser redirect flow for GitHub: it would require a
``redirect_uri``, a session store and CSRF state handling on our side, adding a
web-login attack surface — for a CLI hook. The token exchange keeps the web
surface to the local device page and puts the credential verification where it
belongs (server-side, against the IdP).

The ``provider`` field of an identity is carried into tokens and attestations so
that "who approved this" is answerable years later even if a provider is
decommissioned.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import secrets
from dataclasses import dataclass
from typing import Protocol

import httpx

from aegis.auth.store import AuthStore
from aegis.errors import AuthError, TransportError

# --- scrypt parameters -------------------------------------------------------
#: n=2**14 (16 MiB), r=8, p=1. Matches the OWASP recommendation for interactive
#: logins while staying under ~100 ms on a laptop. Encoded in the stored string
#: so a future increase does not invalidate existing hashes.
_SCRYPT_N = 2**14
_SCRYPT_R = 8
_SCRYPT_P = 1
_SCRYPT_DKLEN = 32
_SALT_BYTES = 16


@dataclass(frozen=True, slots=True)
class Identity:
    """Authenticated subject. ``sub`` is the stable, provider-scoped identifier."""

    sub: str
    email: str
    name: str | None
    provider: str

    def __post_init__(self) -> None:
        if not self.sub or not self.email:
            raise AuthError("identity requires both sub and email")


class IdentityProvider(Protocol):
    """Uniform interface so the auth service never branches on provider name."""

    name: str

    async def verify_password(self, *, email: str, password: str) -> Identity | None:
        """Return the identity, or ``None`` when credentials are wrong."""
        ...

    async def verify_upstream_token(self, *, token: str) -> Identity | None:
        """Verify a token minted by an external IdP."""
        ...


# --------------------------------------------------------------------------- #
# Password hashing
# --------------------------------------------------------------------------- #
def hash_password(password: str, *, salt: bytes | None = None) -> str:
    """Return ``scrypt$n$r$p$salt_b64$dk_b64``.

    Self-describing on purpose: verification reads the parameters from the stored
    value, so raising the cost factor in a future release only affects new
    passwords and never locks anyone out.
    """
    if not password:
        raise AuthError("password must not be empty")
    salt = salt or secrets.token_bytes(_SALT_BYTES)
    dk = hashlib.scrypt(
        password.encode("utf-8"),
        salt=salt,
        n=_SCRYPT_N,
        r=_SCRYPT_R,
        p=_SCRYPT_P,
        dklen=_SCRYPT_DKLEN,
    )
    return "$".join(
        (
            "scrypt",
            str(_SCRYPT_N),
            str(_SCRYPT_R),
            str(_SCRYPT_P),
            base64.b64encode(salt).decode("ascii"),
            base64.b64encode(dk).decode("ascii"),
        )
    )


def verify_password_hash(password: str, stored: str) -> bool:
    """Constant-time verification. Never raises on malformed input."""
    try:
        scheme, n_s, r_s, p_s, salt_b64, dk_b64 = stored.split("$")
        if scheme != "scrypt":
            return False
        salt = base64.b64decode(salt_b64)
        expected = base64.b64decode(dk_b64)
        candidate = hashlib.scrypt(
            password.encode("utf-8"),
            salt=salt,
            n=int(n_s),
            r=int(r_s),
            p=int(p_s),
            dklen=len(expected),
        )
    except (ValueError, TypeError):
        return False
    return hmac.compare_digest(candidate, expected)


#: Verified against when the e-mail is unknown, so that "user does not exist" and
#: "wrong password" take the same time. Generated once at import.
_DUMMY_HASH = hash_password(secrets.token_urlsafe(24))


# --------------------------------------------------------------------------- #
# Local provider
# --------------------------------------------------------------------------- #
class LocalIdentityProvider:
    """Email/password against the AEGIS user table."""

    name = "local"

    def __init__(self, store: AuthStore) -> None:
        self._store = store

    async def verify_password(self, *, email: str, password: str) -> Identity | None:
        # scrypt is deliberately CPU-hard: run it off the event loop so one login
        # cannot stall concurrent analyses.
        return await asyncio.to_thread(self._verify_sync, email, password)

    def _verify_sync(self, email: str, password: str) -> Identity | None:
        user = self._store.get_user(email)
        if user is None or not user.password_hash:
            verify_password_hash(password, _DUMMY_HASH)  # equalise timing
            return None
        if not verify_password_hash(password, user.password_hash):
            return None
        if user.disabled:
            raise AuthError(f"account disabled: {user.email}")
        return Identity(sub=user.email, email=user.email, name=user.name, provider=self.name)

    async def verify_upstream_token(self, *, token: str) -> Identity | None:
        del token  # the local provider has no upstream tokens at all
        raise AuthError("the local provider does not accept upstream tokens")

    def create_user(self, *, email: str, name: str, password: str) -> Identity:
        email = email.strip().lower()
        if "@" not in email:
            raise AuthError(f"invalid e-mail: {email!r}")
        self._store.upsert_user(email=email, name=name, password_hash=hash_password(password))
        return Identity(sub=email, email=email, name=name, provider=self.name)

    def set_password(self, *, email: str, password: str) -> None:
        user = self._store.get_user(email)
        if user is None:
            raise AuthError(f"unknown user: {email}")
        self._store.upsert_user(
            email=user.email, name=user.name, password_hash=hash_password(password), provider="local"
        )


# --------------------------------------------------------------------------- #
# GitHub provider (upstream token exchange)
# --------------------------------------------------------------------------- #
class GithubIdentityProvider:
    """Verify a GitHub token by asking GitHub who it belongs to.

    Two calls, both required:

    * ``GET /user`` — stable numeric id (the ``sub``) and login/name.
    * ``GET /user/emails`` — we take the **verified primary** address only. A
      non-verified e-mail must never become an identity: it is attacker-controlled
      data (any user can add ``ceo@company.com`` to their account) and it is
      exactly what the commit author binding relies on.
    """

    name = "github"

    def __init__(
        self,
        *,
        api_url: str = "https://api.github.com",
        timeout: float = 10.0,
        transport: httpx.AsyncBaseTransport | None = None,
    ) -> None:
        self._api_url = api_url.rstrip("/")
        self._timeout = timeout
        self._transport = transport

    async def verify_password(self, *, email: str, password: str) -> Identity | None:
        del email, password  # passwords are handled by GitHub, never by us
        raise AuthError(
            "the github provider does not accept passwords; "
            "use `aegis login --provider github` to obtain an upstream token"
        )

    async def verify_upstream_token(self, *, token: str) -> Identity | None:
        if not token or len(token) > 1024:
            raise AuthError("invalid upstream token")
        headers = {
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        try:
            async with httpx.AsyncClient(
                timeout=self._timeout, transport=self._transport, follow_redirects=False
            ) as client:
                user_r = await client.get(f"{self._api_url}/user", headers=headers)
                if user_r.status_code in (401, 403):
                    return None
                if user_r.status_code != 200:
                    raise TransportError(f"github /user returned {user_r.status_code}")
                user = user_r.json()

                emails_r = await client.get(f"{self._api_url}/user/emails", headers=headers)
                if emails_r.status_code != 200:
                    # The token lacks `user:email`. Refuse: without a verified
                    # e-mail we cannot bind the identity to a commit author.
                    raise AuthError(
                        "cannot read GitHub e-mails (missing user:email scope)",
                        hint="Re-authorise the token with the user:email scope.",
                    )
                emails = emails_r.json()
        except httpx.HTTPError as exc:
            raise TransportError(f"github api unreachable: {exc}") from exc

        primary = next(
            (
                e
                for e in emails
                if isinstance(e, dict)
                and e.get("primary")
                and e.get("verified")
                and isinstance(e.get("email"), str)
            ),
            None,
        )
        if primary is None:
            raise AuthError("no verified primary e-mail on the GitHub account")
        login = user.get("login")
        return Identity(
            sub=f"github:{user['id']}",
            email=primary["email"].lower(),
            name=user.get("name") or login,
            provider=self.name,
        )


def build_provider(
    provider: str,
    *,
    store: AuthStore,
    github_api_url: str = "https://api.github.com",
    transport: httpx.AsyncBaseTransport | None = None,
) -> IdentityProvider:
    if provider == "local":
        return LocalIdentityProvider(store)
    if provider == "github":
        return GithubIdentityProvider(api_url=github_api_url, transport=transport)
    raise AuthError(f"unsupported auth provider: {provider!r}")


__all__ = [
    "GithubIdentityProvider",
    "Identity",
    "IdentityProvider",
    "LocalIdentityProvider",
    "build_provider",
    "hash_password",
    "verify_password_hash",
]
