import os

from flask import Flask, jsonify, render_template, request

import scanner

app = Flask(__name__)


@app.get("/")
def index():
    return render_template("index.html")


@app.get("/api/hello")
def hello():
    return jsonify(message="Hello, World!")


@app.post("/api/scan")
def scan():
    body = request.get_json(silent=True) or {}
    try:
        result = scanner.scan(body.get("repo", ""), include_tests=bool(body.get("include_tests")))
    except scanner.ScanError as e:
        return jsonify(error=str(e)), 400
    return jsonify(result)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
