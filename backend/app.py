from __future__ import annotations

import json
import os
from pathlib import Path

from flask import Flask, jsonify, request, send_from_directory

import network_graph as ng
import ui_adapter as ui

BASE_DIR = Path(__file__).resolve().parent
FRONTEND_DIR = BASE_DIR.parent / "frontend"
TOPOLOGY_PATH = BASE_DIR / "topologies" / "default.json"

app = Flask(__name__)


def load_default_topology():
    if TOPOLOGY_PATH.exists():
        return json.loads(TOPOLOGY_PATH.read_text(encoding="utf-8"))
    return ng.sample_topology()


def _payload():
    return request.get_json(silent=True) or {}


def _topology_from_payload(payload):
    return payload.get("topology") or load_default_topology()


def _state_and_endpoints(payload):
    topology = _topology_from_payload(payload)
    state = ui.to_py_state(topology)
    source = payload.get("source") or topology.get("source") or "C1"
    destination = payload.get("destination") or topology.get("destination") or "SV1"
    return state, source, destination


def _error(message, status=400):
    return jsonify({"ok": False, "error": message}), status


@app.get("/health")
def health():
    return jsonify({
        "status": "ok",
        "service": "cybershield-flow-analyzer",
        "engine": "networkx",
    })


@app.get("/api/topology")
def get_topology():
    return jsonify(load_default_topology())


@app.post("/api/maxflow")
def api_maxflow():
    payload = _payload()
    try:
        state, source, destination = _state_and_endpoints(payload)
        opts = payload.get("opts") or {}
        result = ui.max_flow_analysis(
            state,
            source,
            destination,
            skip_node=opts.get("skipNode") or opts.get("skip_node"),
            skip_edge=opts.get("skipEdge") or opts.get("skip_edge"),
        )
    except Exception as error:
        return _error(str(error))
    return jsonify(result)


@app.post("/api/shortest")
def api_shortest():
    payload = _payload()
    try:
        state, source, destination = _state_and_endpoints(payload)
        max_paths = int(payload.get("maxPaths", payload.get("k", 4)))
        result = ui.shortest_paths(state, source, destination, max_paths=max_paths)
    except Exception as error:
        return _error(str(error))
    return jsonify(result)


@app.post("/api/analyze")
def api_analyze():
    payload = _payload()
    try:
        state, source, destination = _state_and_endpoints(payload)
        threshold = float(payload.get("threshold", 75))
        result = ui.analyze(state, source, destination, threshold)
    except Exception as error:
        return _error(str(error))
    return jsonify(result)


@app.post("/api/resilience")
def api_resilience():
    payload = _payload()
    try:
        state, source, destination = _state_and_endpoints(payload)
        result = ui.resilience_score(state, source, destination)
    except Exception as error:
        return _error(str(error))
    return jsonify(result)


@app.post("/api/standard")
def api_standard():
    payload = _payload()
    try:
        state, source, destination = _state_and_endpoints(payload)
        threshold = float(payload.get("threshold", 75))
        result = ui.run_standard_scenarios(
            state,
            source,
            destination,
            threshold,
            targets=payload.get("targets") or None,
        )
    except Exception as error:
        return _error(str(error))
    return jsonify(result)


@app.route("/", defaults={"path": "index.html"})
@app.route("/<path:path>")
def serve_frontend(path: str):
    if path == "":
        path = "index.html"
    safe_path = (FRONTEND_DIR / path).resolve()
    try:
        safe_path.relative_to(FRONTEND_DIR.resolve())
    except ValueError:
        return send_from_directory(str(FRONTEND_DIR), "index.html")
    if safe_path.is_file():
        return send_from_directory(str(FRONTEND_DIR), path)
    return send_from_directory(str(FRONTEND_DIR), "index.html")


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "5000"))
    app.run(host="0.0.0.0", port=port, debug=False)
