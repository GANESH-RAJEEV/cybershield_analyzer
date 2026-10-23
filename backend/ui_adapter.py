"""Compatibility layer between the browser UI and the NetworkX engine.

The browser was originally written against a JavaScript engine.  This module
converts the browser topology format into the Python/NetworkX format and
returns analysis objects with the same field names the UI already expects.

All authoritative analysis is performed here by ``network_graph.py``.
"""
from __future__ import annotations

import copy
import math

import network_graph as ng

TOL = 1e-6

NODE_TYPE_TO_PY = {
    "Computer": "C",
    "Router": "R",
    "Switch": "S",
    "Server": "SV",
    "Phone": "P",
    "Mobile Phone": "P",
    "Firewall": "F",
    "AP": "AP",
    "Wireless Access Point": "AP",
    "VPN Gateway": "V",
}

LINK_TYPE_TO_PY = {
    "Ethernet": "ethernet",
    "Fiber": "fiber",
    "Wi-Fi": "wifi",
    "WiFi": "wifi",
    "VPN": "vpn",
    "Other": "other",
}


def _num(value, default=0.0):
    try:
        number = float(value)
    except (TypeError, ValueError):
        return default
    if math.isnan(number) or math.isinf(number):
        return default
    return number


def _sanitize(value):
    """Replace non-finite floats with None so Flask emits valid JSON."""
    if isinstance(value, float):
        if math.isnan(value) or math.isinf(value):
            return None
        return value
    if isinstance(value, dict):
        return {key: _sanitize(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_sanitize(item) for item in value]
    return value


def to_py_state(js_state):
    """Convert the browser's topology object to the NetworkX engine format."""
    js_state = js_state or {}
    nodes = []
    for index, node in enumerate(js_state.get("nodes", [])):
        fwd = node.get("fwdCap")
        nodes.append({
            "id": str(node.get("id", "")),
            "name": str(node.get("name") or node.get("id") or ""),
            "type": NODE_TYPE_TO_PY.get(node.get("type"), "C"),
            "status": node.get("status") or "Active",
            "risk": _num(node.get("risk"), 0),
            "segment": str(node.get("segment") or ""),
            "fwdCap": None if fwd is None or fwd == "" else _num(fwd, 0),
            "degradation": _num(node.get("degradation"), 50),
            "extra": str(node.get("extra") or ""),
            "x": _num(node.get("x"), 100 + (index % 5) * 160),
            "y": _num(node.get("y"), 100 + (index // 5) * 140),
        })

    edges = []
    for edge in js_state.get("edges", []):
        edges.append({
            "id": str(edge.get("id", "")),
            "source": str(edge.get("source", "")),
            "target": str(edge.get("target", "")),
            "type": LINK_TYPE_TO_PY.get(edge.get("type"), "ethernet"),
            "capacity": _num(edge.get("capacity"), 0),
            "latency": _num(edge.get("latency"), 0),
            "risk": _num(edge.get("risk"), 0),
            "status": edge.get("status") or "Active",
            "reduction": _num(edge.get("reduction"), 0),
            # The browser calls this field "background"; the Python engine
            # calls it "saturation".  They represent the same reservation.
            "saturation": _num(edge.get("background", edge.get("saturation")), 0),
            "extra": str(edge.get("extra") or ""),
        })

    return ng.normalize_topology({"nodes": nodes, "edges": edges})


def _edge_map(state):
    return {edge["id"]: edge for edge in state.get("edges", [])}


def _cut_to_js(mf, state):
    cut = mf.get("cut")
    if not cut:
        return None
    edges_by_id = _edge_map(state)
    edges = []
    for item in cut.get("edges", []):
        edge = edges_by_id.get(item.get("id"), {})
        edges.append({
            "id": item.get("id"),
            "source": edge.get("source", ""),
            "target": edge.get("target", ""),
            "capacity": item.get("cap", 0),
        })
    nodes = [
        {"id": item.get("id"), "capacity": item.get("cap", 0)}
        for item in cut.get("nodes", [])
    ]
    capacity = cut.get("capacity", 0)
    return {
        "sSide": cut.get("sSide", []),
        "tSide": cut.get("tSide", []),
        "edges": edges,
        "nodes": nodes,
        "capacity": capacity,
        "verified": abs(capacity - mf.get("flow", 0)) <= TOL,
    }


def max_flow_to_js(mf, state, source, destination):
    """Convert the Python max-flow result to the browser's field names."""
    edge_flow = dict(mf.get("edge_flow", {}))
    node_flow = dict(mf.get("node_flow", {}))
    # The JS engine reports the source and sink as carrying the full flow.
    if mf.get("ok"):
        node_flow[source] = mf.get("flow", 0)
        node_flow[destination] = mf.get("flow", 0)
    paths = [
        {"nodes": path.get("nodes", []), "bottleneck": path.get("bn", 0)}
        for path in mf.get("paths", [])
    ]
    return {
        "ok": bool(mf.get("ok")),
        "flow": mf.get("flow", 0),
        "msg": mf.get("msg", ""),
        "edge_flow": edge_flow,
        "node_flow": node_flow,
        "paths": paths,
        "cut": _cut_to_js(mf, state),
    }


def max_flow_analysis(state, source, destination, skip_node=None, skip_edge=None):
    mf = ng.compute_max_flow(state, source, destination, skip_node=skip_node, skip_edge=skip_edge)
    return _sanitize(max_flow_to_js(mf, state, source, destination))


def shortest_paths(state, source, destination, max_paths=4):
    result = ng.shortest_paths(state, source, destination, k=max_paths)
    return _sanitize(result)


def _bottleneck_to_js(bn, state, base_flow):
    edges_by_id = _edge_map(state)
    rows = []
    for row in bn.get("rows", []):
        edge = edges_by_id.get(row.get("id"), {})
        rows.append({
            "id": row.get("id"),
            "source": row.get("source"),
            "target": row.get("target"),
            "type": edge.get("type", ""),
            "capacity": edge.get("capacity", 0),
            "flow": row.get("flow", 0),
            "available": row.get("avail", 0),
            "background": row.get("bg", 0),
            "effective": row.get("eff", 0),
            "util": row.get("util"),
            "congested": bool(row.get("congested")),
            "saturated": bool(row.get("saturated")),
            "critical": bool(row.get("critical")),
            "drop": row.get("drop", 0),
            "dropPct": row.get("dropPct", 0),
            "cls": row.get("cls", "-"),
            "after": max(0, base_flow - row.get("drop", 0)),
        })
    node_rows = []
    for row in bn.get("nodeRows", []):
        node_rows.append({
            "id": row.get("id"),
            "name": row.get("name"),
            "drop": row.get("drop", 0),
            "dropPct": row.get("dropPct", 0),
            "critical": bool(row.get("critical")),
            "after": max(0, base_flow - row.get("drop", 0)),
        })
    return {
        "rows": rows,
        "byEdge": {row["id"]: row for row in rows},
        "nodeRows": node_rows,
        "threshold": bn.get("threshold", 75),
        "congested": [row for row in rows if row["congested"]],
        "saturated": [row for row in rows if row["saturated"]],
        "critical": [row for row in rows if row["critical"]],
        "critNodes": [row for row in node_rows if row["critical"]],
    }


def _recommendations(state, analysis, source, destination):
    out = []
    mf = analysis["mf"]
    if not mf.get("ok"):
        return [{"severity": "high", "text": mf.get("msg", "Analysis failed.")}]

    for row in analysis["bn"]["critical"]:
        if row.get("dropPct", 0) > 30:
            out.append({
                "severity": "high",
                "text": "Link %s (%s -> %s) is critical: removing it drops Fmax by %s%% (%s Mbps). Add a backup link or a disjoint path." % (
                    row["id"], row["source"], row["target"],
                    ng.fmt(row["dropPct"]), ng.fmt(row["drop"]),
                ),
            })

    for row in analysis["bn"]["congested"]:
        if not row.get("critical"):
            out.append({
                "severity": "medium",
                "text": "Link %s (%s -> %s) is congested at %s%% but is not critical. Increase capacity or apply QoS/queue management." % (
                    row["id"], row["source"], row["target"], ng.fmt(row["util"]),
                ),
            })

    for node in analysis["bn"]["critNodes"]:
        out.append({
            "severity": "high",
            "text": "Device %s (%s) is critical: removing it drops Fmax by %s%% (%s Mbps). Add a redundant path through another device." % (
                node["id"], node["name"], ng.fmt(node["dropPct"]), ng.fmt(node["drop"]),
            ),
        })

    by_id = ng.node_map(state)
    primary = analysis["sp"]["paths"][0]["nodes"] if analysis["sp"].get("paths") else []
    for node_id in primary:
        node = by_id.get(node_id)
        if node and node.get("risk", 0) >= 75 and node_id not in (source, destination):
            out.append({
                "severity": "high",
                "text": "Device %s has %s risk and lies on the primary route. Segment it, monitor it and restrict management access." % (
                    node_id, ng.risk_level(node["risk"]),
                ),
            })

    for node in state.get("nodes", []):
        if node.get("status") == "Compromised":
            out.append({
                "severity": "high",
                "text": "Device %s is compromised. Contain it, restore it from a trusted image and rotate credentials." % node["id"],
            })

    cut = mf.get("cut")
    if cut and len(cut.get("edges", [])) == 1 and not cut.get("nodes"):
        out.append({
            "severity": "high",
            "text": "The minimum cut is the single link %s; this is a single point of failure. Add a second disjoint route." % cut["edges"][0]["id"],
        })

    for row in analysis["bn"]["rows"]:
        if row.get("type") == "vpn" and row.get("saturated"):
            out.append({
                "severity": "medium",
                "text": "VPN link %s is saturated. Inspect encryption overhead and consider a second tunnel or a higher-capacity link." % row["id"],
            })

    boundary = {}
    for edge in state.get("edges", []):
        if edge.get("status") != "Active":
            continue
        a = by_id.get(edge["source"])
        b = by_id.get(edge["target"])
        if not a or not b or not a.get("segment") or not b.get("segment") or a["segment"] == b["segment"]:
            continue
        for segment in (a["segment"], b["segment"]):
            boundary.setdefault(segment, []).append(edge["id"])
    for segment, edge_ids in boundary.items():
        if len(edge_ids) == 1:
            out.append({
                "severity": "medium",
                "text": "Segment %s has only one boundary link (%s). Add a second boundary path so the segment cannot be isolated by one failure." % (
                    segment, edge_ids[0],
                ),
            })

    if not out:
        out.append({
            "severity": "low",
            "text": "No immediate structural recommendations. The network still has spare capacity and redundant paths.",
        })

    seen = set()
    unique = []
    for item in out:
        if item["text"] not in seen:
            seen.add(item["text"])
            unique.append(item)
    return unique[:10]


def analyze(state, source, destination, threshold=75):
    mf = ng.compute_max_flow(state, source, destination)
    sp = ng.shortest_paths(state, source, destination, k=4)
    reach = ng.reachability(state, source)
    bn = ng.bottlenecks(state, source, destination, mf, threshold)
    js_mf = max_flow_to_js(mf, state, source, destination)
    js_sp = sp
    js_reach = sorted(reach)
    js_bn = _bottleneck_to_js(bn, state, mf.get("flow", 0))
    analysis = {
        "source": source,
        "destination": destination,
        "threshold": threshold,
        "mf": js_mf,
        "sp": js_sp,
        "reach": js_reach,
        "bn": js_bn,
    }
    analysis["recommendations"] = _recommendations(state, analysis, source, destination)
    return _sanitize(analysis)


def resilience_score(state, source, destination):
    base = ng.compute_max_flow(state, source, destination)
    if not base.get("ok") or base.get("flow", 0) <= ng.EPS:
        return {
            "ok": False,
            "score": None,
            "base": base.get("flow", 0),
            "msg": base.get("msg") or "Baseline flow is zero; resilience is undefined (n/a).",
            "failures": [],
            "worst": [],
        }

    active = ng.active_graph(state)
    failures = []
    for edge in active["edges"]:
        after = ng.compute_max_flow(state, source, destination, skip_edge=edge["id"])
        flow_after = after.get("flow", 0) if after.get("ok") else 0
        failures.append({
            "kind": "link",
            "id": edge["id"],
            "after": flow_after,
            "ratio": flow_after / base["flow"] * 100,
        })
    for node in active["nodes"]:
        if node["id"] in (source, destination):
            continue
        after = ng.compute_max_flow(state, source, destination, skip_node=node["id"])
        flow_after = after.get("flow", 0) if after.get("ok") else 0
        failures.append({
            "kind": "device",
            "id": node["id"],
            "after": flow_after,
            "ratio": flow_after / base["flow"] * 100,
        })

    score = sum(item["ratio"] for item in failures) / len(failures) if failures else 100.0
    worst = sorted(failures, key=lambda item: (item["ratio"], item["id"]))[:5]
    return _sanitize({
        "ok": True,
        "score": score,
        "base": base["flow"],
        "failures": failures,
        "worst": worst,
        "msg": "",
    })


def _degree_of(state, node_id):
    return sum(
        1 for edge in state.get("edges", [])
        if edge.get("status") == "Active" and node_id in (edge.get("source"), edge.get("target"))
    )


def _standard_row(name, target, base_flow, base_latency, after_flow, after_latency, note):
    loss = max(0, base_flow - after_flow)
    reduction = loss / base_flow * 100 if base_flow > ng.EPS else None
    if math.isfinite(base_latency) and math.isfinite(after_latency):
        shift = after_latency - base_latency
    elif math.isinf(base_latency) and math.isinf(after_latency):
        shift = 0
    elif math.isfinite(base_latency) and math.isinf(after_latency):
        shift = math.inf
    else:
        shift = None

    if note == "baseline":
        result = "Baseline"
    elif after_flow <= ng.EPS:
        result = "Disconnected (Fmax = 0)"
    elif loss <= ng.EPS and (shift is None or shift <= ng.EPS):
        result = "No impact"
    else:
        result = "Degraded"
        if loss > ng.EPS:
            result += " (-%s%% flow)" % ng.fmt(reduction)
        if shift is not None and shift > ng.EPS:
            result += " (+%s ms)" % ng.fmt(shift)

    return {
        "scenario": name,
        "target": target or "-",
        "beforeFlow": base_flow,
        "afterFlow": after_flow,
        "loss": loss,
        "reduction": reduction,
        "beforeLatency": base_latency,
        "afterLatency": after_latency,
        "latencyShift": shift,
        "result": result,
    }


def run_standard_scenarios(state, source, destination, threshold=75, targets=None):
    base_mf = ng.compute_max_flow(state, source, destination)
    base_path = ng.shortest_paths(state, source, destination, k=1)
    base_flow = base_mf.get("flow", 0) if base_mf.get("ok") else 0
    base_latency = base_path.get("best", math.inf) if base_path.get("ok") and base_path.get("paths") else math.inf
    full = analyze(state, source, destination, threshold)
    active = ng.active_graph(state)

    primary_edge_ids = set()
    if full["sp"].get("paths"):
        for edge in full["sp"]["paths"][0].get("edges", []):
            primary_edge_ids.add(edge["id"])

    alternate = sorted(
        [edge for edge in active["edges"] if edge["id"] not in primary_edge_ids],
        key=lambda edge: (-edge.get("capacity", 0), edge["id"]),
    )
    saturated = sorted(
        full["bn"]["rows"],
        key=lambda row: (-(row["util"] if row.get("util") is not None else -1), -row.get("capacity", 0), row["id"]),
    )
    critical_node = full["bn"]["critNodes"][0] if full["bn"]["critNodes"] else None
    interior = [node for node in active["nodes"] if node["id"] not in (source, destination)]
    by_degree = sorted(interior, key=lambda node: (-_degree_of(state, node["id"]), node["id"]))
    non_critical = [node for node in by_degree if not critical_node or node["id"] != critical_node["id"]]
    ordinary_node = non_critical[0] if non_critical else (by_degree[0] if by_degree else None)
    destination_node = ng.node_map(state).get(destination)
    segment = destination_node.get("segment", "") if destination_node else ""

    chosen = {
        "alternateLink": alternate[0]["id"] if alternate else None,
        "saturatedLink": saturated[0]["id"] if saturated else None,
        "device": ordinary_node["id"] if ordinary_node else None,
        "criticalDevice": critical_node["id"] if critical_node else None,
        "segment": segment,
    }
    if targets:
        for key, value in targets.items():
            if value is not None and value != "":
                chosen[key] = value

    rows = [_standard_row("Normal", "-", base_flow, base_latency, base_flow, base_latency, "baseline")]

    def run_case(name, key, target, param):
        if not target:
            rows.append({
                "scenario": name, "target": "n/a", "beforeFlow": base_flow, "afterFlow": base_flow,
                "loss": 0, "reduction": 0 if base_flow > ng.EPS else None,
                "beforeLatency": base_latency, "afterLatency": base_latency,
                "latencyShift": 0, "result": "Not available (no valid target)",
            })
            return
        trial = copy.deepcopy(state)
        try:
            ng.apply_scenario(trial, key, target, param)
        except Exception as error:  # invalid target after an edit
            rows.append({
                "scenario": name, "target": target, "beforeFlow": base_flow, "afterFlow": base_flow,
                "loss": 0, "reduction": 0 if base_flow > ng.EPS else None,
                "beforeLatency": base_latency, "afterLatency": base_latency,
                "latencyShift": 0, "result": "Not available: %s" % error,
            })
            return
        mf = ng.compute_max_flow(trial, source, destination)
        sp = ng.shortest_paths(trial, source, destination, k=1)
        after_flow = mf.get("flow", 0) if mf.get("ok") else 0
        after_latency = sp.get("best", math.inf) if sp.get("ok") and sp.get("paths") else math.inf
        rows.append(_standard_row(name, target, base_flow, base_latency, after_flow, after_latency, "scenario"))

    run_case("Alternate link disabled", "link", chosen["alternateLink"], None)
    run_case("Link saturated", "sat", chosen["saturatedLink"], 80)
    run_case("Device failed", "hw", chosen["device"], None)
    run_case("Critical device failed", "hw", chosen["criticalDevice"], None)
    run_case("Segment isolated", "iso", chosen["segment"], None)

    return _sanitize({
        "base": {"flow": base_flow, "latency": base_latency},
        "rows": rows,
        "targets": chosen,
    })
