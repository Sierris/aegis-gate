"""Acceso roto — A01:2021 (IDOR)."""

from flask import Flask, request

app = Flask(__name__)

NOTES = {1: {"owner": "alice", "text": "secreto"}, 2: {"owner": "bob", "text": "otro"}}


@app.route("/note")
def get_note():
    note_id = int(request.args["id"])
    return NOTES.get(note_id, {})


@app.route("/admin")
def admin():
    is_admin = request.args.get("admin") == "1"
    if is_admin:
        return {"all": NOTES}
    return {"error": "forbidden"}, 403
