"""SSRF — A10:2021."""

import requests
from flask import Flask, request

app = Flask(__name__)


@app.route("/preview")
def preview():
    target = request.args["url"]
    if not target.startswith("https://"):
        return {"error": "invalid"}, 400
    return requests.get(target, timeout=5).text
