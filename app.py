import os

from flask import Flask, jsonify

app = Flask(__name__)

PAGE = """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Hello World</title>
  <style>
    body { margin: 0; min-height: 100vh; display: grid; place-items: center;
           font-family: system-ui, sans-serif; background: #f6f6f4; color: #222; }
    @media (prefers-color-scheme: dark) { body { background: #181818; color: #eee; } }
    h1 { font-size: clamp(2rem, 8vw, 4rem); margin: 0; }
  </style>
</head>
<body>
  <h1 id="msg">Loading…</h1>
  <script>
    fetch("/api/hello")
      .then(r => r.json())
      .then(d => { document.getElementById("msg").textContent = d.message; })
      .catch(() => { document.getElementById("msg").textContent = "Backend unreachable"; });
  </script>
</body>
</html>"""


@app.get("/")
def index():
    return PAGE


@app.get("/api/hello")
def hello():
    return jsonify(message="Hello, World!")


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
