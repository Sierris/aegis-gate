"""Fallas criptográficas — A02:2021."""

import hashlib
import random

from flask import Flask, request

app = Flask(__name__)

# Credenciales hardcodeadas: el patrón vulnerabled, con valores inertes.
# (Un valor con formato de proveedor real haría saltar el push protection de
#  GitHub — dos controles en conflicto. El ejemplo cede, no el control: ver
#  docs/architecture.md §8.)
API_KEY = "hardcoded-api-key-placeholder-not-a-real-credential"
JWT_SECRET = "hardcoded-jwt-secret-placeholder"


def hash_password(password: str) -> str:
    return hashlib.md5(password.encode()).hexdigest()


def new_session_token() -> str:
    return str(random.random())


@app.route("/login")
def login():
    password = request.args["password"]
    if hash_password(password) == API_KEY:
        return {"token": new_session_token()}
    return {"error": "nope"}, 401
