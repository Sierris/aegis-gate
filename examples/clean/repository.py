"""Consulta parametrizada y control de acceso por objeto — A03 y A01 corregidos."""

import sqlite3

from flask import Flask, request, session

app = Flask(__name__)


@app.route("/user")
def user() -> tuple[dict[str, object], int]:
    # La identidad sale de la sesión autenticada, no de un parámetro.
    viewer = session.get("user_id")
    if viewer is None:
        return {"error": "unauthorized"}, 401

    try:
        uid = int(request.args["id"])
    except (KeyError, TypeError, ValueError):
        return {"error": "invalid id"}, 400

    db = sqlite3.connect("app.db")
    # Consulta parametrizada: el valor viaja como dato y jamás como sintaxis.
    row = db.execute(
        "SELECT id, email FROM users WHERE id = ? AND tenant_id = ?",
        (uid, session.get("tenant_id")),
    ).fetchone()
    if row is None:
        return {"error": "not found"}, 404
    return {"user": {"id": row[0], "email": row[1]}}, 200
