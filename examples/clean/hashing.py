"""Hash de contraseñas con KDF, verificación real y secreto fuera del código.

Corrige las cuatro fallas de `examples/vulnerable/session.py`:
  1. `md5` -> `scrypt` (KDF memoria-dura, con parámetros explícitos)
  2. secreto hardcodeado -> variable de entorno del gestor de secretos
  3. `random.random()` -> `secrets.token_urlsafe` (CSPRNG)
  4. el login NO emitía token sin verificar la contraseña -> verificación real
"""

import hashlib
import hmac
import os
import secrets

from flask import Flask, request

app = Flask(__name__)

# Secreto de pepper desde el entorno. Si falta, el arranque falla (fail-fast):
# un valor por defecto silencioso sería la misma vulnerabilidad de antes.
_PEPPER = os.environ["PASSWORD_PEPPER"].encode()

# Un *hash* no es un secreto: puede estar en el código.
# scrypt$n$r$p$salt$derived_key  (parámetros autodescriptivos, ver `hash_password`)
_STORED = "scrypt$16384$8$1$00112233445566778899aabbccddeeff$" + "00" * 32


def hash_password(password: str, *, salt: bytes | None = None) -> str:
    salt = salt or secrets.token_bytes(16)
    derived = hashlib.scrypt(password.encode() + _PEPPER, salt=salt, n=2**14, r=8, p=1, dklen=32)
    return f"scrypt$16384$8$1${salt.hex()}${derived.hex()}"


def verify_password(password: str, stored: str) -> bool:
    """Comparación en tiempo constante, con los parámetros leídos del propio hash."""
    try:
        scheme, n, r, p, salt_hex, dk_hex = stored.split("$")
        if scheme != "scrypt":
            return False
        expected = bytes.fromhex(dk_hex)
        candidate = hashlib.scrypt(
            password.encode() + _PEPPER,
            salt=bytes.fromhex(salt_hex),
            n=int(n),
            r=int(r),
            p=int(p),
            dklen=len(expected),
        )
    except (ValueError, TypeError):
        return False
    return hmac.compare_digest(candidate, expected)


def new_session_token() -> str:
    return secrets.token_urlsafe(32)


@app.route("/login")
def login() -> tuple[dict[str, str], int]:
    password = request.args.get("password", "")
    if len(password) < 12:
        # No se filtra si el usuario existe ni si la contraseña era corta.
        return {"error": "invalid credentials"}, 401
    if not verify_password(password, _STORED):
        return {"error": "invalid credentials"}, 401
    return {"token": new_session_token()}, 200
