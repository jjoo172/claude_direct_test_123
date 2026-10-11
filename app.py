import os
import threading
import time
import uuid

from flask import Flask, jsonify, render_template, request

import scanner

app = Flask(__name__)

# Scans run in background threads so the page can poll for progress instead
# of holding one long request open. Jobs live in memory, which works because
# the app runs as a single process (see render.yaml); results are kept for
# JOB_TTL seconds after finishing.
JOB_TTL = 15 * 60
MAX_RUNNING = 2
_jobs = {}
_lock = threading.Lock()


def _prune():
    now = time.time()
    for jid in [j for j, v in _jobs.items() if v.get("finished") and now - v["finished"] > JOB_TTL]:
        del _jobs[jid]


def _run(jid, repo, include_tests):
    def report(**fields):
        with _lock:
            _jobs[jid].update(fields)

    try:
        result = scanner.scan(repo, include_tests=include_tests, report=report)
        report(phase="done", result=result)
    except scanner.ScanError as e:
        report(phase="error", error=str(e))
    except Exception:
        app.logger.exception("scan failed")
        report(phase="error", error="The scan hit an unexpected error. Try again, or try a smaller repo.")
    finally:
        report(finished=time.time())


@app.get("/")
def index():
    return render_template("index.html")


@app.get("/api/hello")
def hello():
    return jsonify(message="Hello, World!")


@app.post("/api/scan")
def start_scan():
    body = request.get_json(silent=True) or {}
    repo = body.get("repo", "")
    try:
        scanner.parse_repo(repo)   # reject bad input before starting a job
    except scanner.ScanError as e:
        return jsonify(error=str(e)), 400

    with _lock:
        _prune()
        running = sum(1 for v in _jobs.values() if not v.get("finished"))
        if running >= MAX_RUNNING:
            return jsonify(error="The scanner is busy with other repos. Try again in a minute."), 429
        jid = uuid.uuid4().hex
        _jobs[jid] = {"phase": "queued", "repo": repo, "started": time.time()}

    threading.Thread(target=_run, args=(jid, repo, bool(body.get("include_tests"))), daemon=True).start()
    return jsonify(job=jid), 202


@app.get("/api/scan/<jid>")
def scan_status(jid):
    with _lock:
        job = _jobs.get(jid)
        if not job:
            return jsonify(error="This scan has expired. Start it again."), 404
        out = {k: v for k, v in job.items() if k not in ("finished",)}
        out["elapsed"] = round(time.time() - job["started"], 1)
    return jsonify(out)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)), threaded=True)
