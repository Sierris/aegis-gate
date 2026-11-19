"""SQL injection — A03:2021."""

import sqlite3

from flask import Flask, request

app = Flask(__name__)


@app.route("/user")
def user():
    uid = request.args["id"]
    db = sqlite3.connect("app.db")
    row = db.execute("SELECT * FROM users WHERE id = '%s'" % uid).fetchone()
    return {"user": row}
