"""Versión corregida del ejemplo del enunciado.

El comando NO se construye con el input: se ejecuta un binario con una lista de
argumentos y `shell=False`, y el valor se valida contra un allowlist antes de usarse.
"""

import ipaddress
import subprocess

from flask import Flask, request

app = Flask(__name__)

# Allowlist explícita: solo hosts internos conocidos.
ALLOWED_HOSTS = frozenset({"web-1.internal", "web-2.internal", "db-1.internal"})


def _resolve_host(raw: str) -> str:
    """Acepta solo IPs públicas o hosts del allowlist; nunca nombres arbitrarios."""
    candidate = raw.strip().lower()
    if candidate in ALLOWED_HOSTS:
        return candidate
    try:
        ip = ipaddress.ip_address(candidate)
    except ValueError as exc:
        raise ValueError("host no permitido") from exc
    if ip.is_private or ip.is_loopback or ip.is_link_local:
        raise ValueError("host no permitido")
    return str(ip)


@app.route("/ping")
def ping() -> tuple[dict[str, str], int]:
    try:
        host = _resolve_host(request.args.get("host", ""))
    except ValueError:
        return {"error": "invalid host"}, 400

    # Lista de argumentos + shell=False: el input no puede convertirse en sintaxis.
    result = subprocess.run(
        ["ping", "-c", "1", "-W", "2", host],
        capture_output=True,
        text=True,
        check=False,
        timeout=5,
    )
    return {"output": result.stdout[:200]}, 200


if __name__ == "__main__":
    app.run()
