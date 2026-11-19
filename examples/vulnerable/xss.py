"""Cross-site scripting — A03:2021 (XSS, mencionado como ejemplo en el enunciado)."""

from flask import Flask, Markup, request

app = Flask(__name__)

COMMENTS: list[str] = []


@app.route("/comment", methods=["POST"])
def add_comment():
    body = request.form["body"]
    COMMENTS.append(body)
    return "ok"


@app.route("/comments")
def show_comments():
    # El HTML del comentario se marca como "safe": se desactiva el autoescaping.
    rendered = "".join(Markup(f"<p>{c}</p>") for c in COMMENTS)
    return f"<h1>Comentarios</h1>{rendered}"
