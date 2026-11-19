"""Command injection — A03:2021. El ejemplo canónico del enunciado."""

import os

from flask import Flask, request

app = Flask(__name__)


@app.route("/ping")
def run_command_from_user_input():
    command = request.args.get("command")
    # El input del usuario llega sin validar al shell.
    os.system(f"echo {command}")
    return "ok"


if __name__ == "__main__":
    app.run()
