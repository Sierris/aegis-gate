"""Signing key material for AEGIS.

One Ed25519 keypair signs both short-lived access tokens (step 2) and, from step
5, commit attestations. Sharing the key is deliberate:

* one key to rotate, one key to revoke, one JWKS document to publish;
* a verifier that trusts ``/v1/keys`` for attestations automatically trusts it
  for tokens, so CI needs no separate trust anchor.

Rotation is by **key id** (``kid``), which is the SHA-256 of the raw public key:
two different keys can never collide on ``kid``, and a holder of the public key
can recompute it locally — no registry lookup needed to know which key signed
what.

The private key never leaves this module as anything but PKCS#8 PEM bytes with
mode 0600, and its ``repr`` is redacted so it cannot leak through a log line or a
traceback that dumps locals.
"""

from __future__ import annotations

import base64
import hashlib
import os
import stat
import tempfile
from datetime import UTC, datetime
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from aegis.contracts import JwkPublicKey
from aegis.errors import ConfigError

#: PEM file mode: owner read/write only.
_PRIVATE_MODE = 0o600
_DIR_MODE = 0o700


def b64url(data: bytes) -> str:
    """Base64url without padding (RFC 7515 §2)."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64url_decode(text: str) -> bytes:
    """Inverse of :func:`b64url`, tolerating missing padding."""
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def key_id_from_raw_public(raw_public: bytes) -> str:
    """Derive a stable, collision-free ``kid`` from the raw Ed25519 point.

    Truncated to 16 base64url chars (96 bits) to keep JWT headers small; the
    birthday bound is far beyond any plausible number of rotations.
    """
    return b64url(hashlib.sha256(raw_public).digest())[:16]


class SigningKey:
    """Ed25519 keypair wrapper: generation, persistence, JWKS export."""

    __slots__ = ("_created_at", "_kid", "_private")

    def __init__(self, private_key: Ed25519PrivateKey, kid: str | None = None) -> None:
        self._private = private_key
        self._kid = kid or key_id_from_raw_public(self.raw_public)
        self._created_at = datetime.now(UTC)

    # -- properties --------------------------------------------------------
    @property
    def kid(self) -> str:
        return self._kid

    @property
    def created_at(self) -> datetime:
        return self._created_at

    @property
    def private_key(self) -> Ed25519PrivateKey:
        """Handed to the JWT/JWS signer. Never serialised outside this module."""
        return self._private

    @property
    def public_key(self) -> Ed25519PublicKey:
        return self._private.public_key()

    @property
    def raw_public(self) -> bytes:
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )

    # -- construction ------------------------------------------------------
    @classmethod
    def generate(cls) -> SigningKey:
        return cls(Ed25519PrivateKey.generate())

    @classmethod
    def from_pem(cls, pem: bytes) -> SigningKey:
        try:
            key = serialization.load_pem_private_key(pem, password=None)
        except (ValueError, TypeError) as exc:  # pragma: no cover - corrupt file
            raise ConfigError(f"cannot parse signing key: {exc}") from exc
        if not isinstance(key, Ed25519PrivateKey):
            raise ConfigError("signing key is not Ed25519 (refusing to continue)")
        return cls(key)

    @classmethod
    def load_or_create(cls, path: Path) -> SigningKey:
        """Load the key at ``path``, generating it on first use.

        The file is created with an atomic write (temp file + ``os.replace``) so
        that two concurrent boots cannot leave a half-written key, and the file
        mode is forced to 0600 *before* the key bytes are written — there is no
        window where the private key exists world-readable.
        """
        path = path.expanduser()
        if path.exists():
            mode = stat.S_IMODE(path.stat().st_mode)
            if mode & 0o077:
                # Refuse rather than silently chmod: someone may have copied the
                # key somewhere else already, and that is an incident, not a bug.
                raise ConfigError(
                    f"signing key {path} is readable by group/other (mode {mode:o}); "
                    f"fix with: chmod 600 {path}",
                    hint="A leaked private key can forge attestations.",
                )
            return cls.from_pem(path.read_bytes())

        path.parent.mkdir(parents=True, exist_ok=True)
        os.chmod(path.parent, _DIR_MODE)

        key = cls.generate()
        pem = key.to_pem()
        fd, tmp_name = tempfile.mkstemp(dir=path.parent, prefix=".aegis-key-")
        try:
            os.fchmod(fd, _PRIVATE_MODE)
            with os.fdopen(fd, "wb") as fh:
                fh.write(pem)
                fh.flush()
                os.fsync(fh.fileno())
            os.replace(tmp_name, path)
        except BaseException:
            Path(tmp_name).unlink(missing_ok=True)
            raise
        return key

    def to_pem(self) -> bytes:
        return self._private.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )

    # -- verification helpers ---------------------------------------------
    def public_jwk(self) -> JwkPublicKey:
        """JWKS entry. ``x`` is the raw public key, base64url, unpadded."""
        return JwkPublicKey(kid=self._kid, x=b64url(self.raw_public))

    def __repr__(self) -> str:
        return f"SigningKey(kid={self._kid!r}, alg=EdDSA)"

    __str__ = __repr__


def verify_public_of(key: SigningKey | Ed25519PublicKey | bytes) -> Ed25519PublicKey:
    """Accept a private wrapper, a public key object or raw 32-byte public key."""
    if isinstance(key, SigningKey):
        return key.public_key
    if isinstance(key, bytes):
        if len(key) != 32:
            raise ConfigError("raw Ed25519 public key must be 32 bytes")
        return Ed25519PublicKey.from_public_bytes(key)
    return key
