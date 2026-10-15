"""
SentinelIDS live dashboard.

Reads logs/incidents.jsonl (written by ids/sentinel.py) and serves a
self-refreshing web page with charts of detected attacks.

    python dashboard/app.py        ->  http://127.0.0.1:8050
"""
import json
import pathlib
from collections import Counter

from flask import Flask, jsonify, render_template

ROOT = pathlib.Path(__file__).resolve().parent.parent
INCIDENTS = ROOT / "logs" / "incidents.jsonl"

app = Flask(__name__)


def load_incidents():
    if not INCIDENTS.exists():
        return []
    rows = []
    with INCIDENTS.open(encoding="utf-8") as f:
        for line in f:
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError:
                continue          # a line still being written
    return rows


def summarise(rows):
    category = Counter(r["signature"].split()[1] for r in rows)   # RECON, WEB, ...
    timeline = Counter((r["time"] or "")[11:19] for r in rows)    # per second
    blocked = {}
    for r in rows:
        for act in r["actions"]:
            if act in ("blocked", "would_block"):
                blocked[r["offender"]] = {"ip": r["offender"], "mode": act,
                                          "reason": r["signature"], "time": r["time"]}
    return {
        "total": len(rows),
        "by_priority": {p: sum(1 for r in rows if r["priority"] == p) for p in (1, 2, 3)},
        "rules_fired": len({r["sid"] for r in rows}),
        "by_category": category.most_common(),
        "top_signatures": Counter(r["signature"].replace("SENTINEL ", "")
                                  for r in rows).most_common(8),
        "top_sources": Counter(r.get("src_ip") for r in rows).most_common(6),
        "timeline": sorted(timeline.items())[-60:],
        "blocked": list(blocked.values()),
        "recent": rows[-25:][::-1],
    }


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/summary")
def api_summary():
    return jsonify(summarise(load_incidents()))


@app.after_request
def no_cache(resp):
    resp.headers["Cache-Control"] = "no-store"
    return resp


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=8050, debug=False)
