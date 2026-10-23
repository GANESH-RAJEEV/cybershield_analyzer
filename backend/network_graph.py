
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import networkx as nx
from networkx.algorithms.flow import edmonds_karp

EPS = 1e-9
BIG = 1e15


class NodeType:
    def __init__(self, name, extra_label=""):
        self.name = name
        self.extra_label = extra_label


class LinkType:
    def __init__(self, name, extra_label="", width=2.5):
        self.name = name
        self.extra_label = extra_label
        self.width = width


NODE_TYPES = {
    "C": NodeType("Computer"),
    "R": NodeType("Router"),
    "S": NodeType("Switch"),
    "SV": NodeType("Server", "Host services"),
    "P": NodeType("Mobile Phone", "Wireless bandwidth (Mbps)"),
    "F": NodeType("Firewall", "Inspection overhead (ms)"),
    "AP": NodeType("Wireless Access Point", "Max wireless channels"),
    "V": NodeType("VPN Gateway", "Encryption overhead (ms)"),
}

LINK_TYPES = {
    "ethernet": LinkType("Ethernet Connection", "Reliability (%)", 2.5),
    "wifi": LinkType("Wi-Fi Link", "Signal strength (dBm)", 2.5),
    "vpn": LinkType("VPN Tunnel", "Encryption risk", 3.0),
    "fiber": LinkType("Fiber-Optic Connection", "Physical security", 4.5),
    "other": LinkType("Other Connection", "Notes", 2.5),
}

NODE_STATUSES = ["Active", "Failed", "Compromised", "Disabled"]
LINK_STATUSES = ["Active", "Disabled", "Blocked"]

APP_THEME = {
    "bg": "#020b16",
    "panel": "#0b1323",
    "panel_alt": "#101b2b",
    "border": "#1d2a3d",
    "text": "#e2e8f0",
    "muted": "#93a4bc",
    "blue": "#3b82f6",
    "cyan": "#22d3ee",
    "green": "#22c55e",
    "amber": "#f59e0b",
    "orange": "#f97316",
    "red": "#ef4444",
    "purple": "#a855f7",
    "gray": "#64748b",
}

SEVERITY = {
    "green": APP_THEME["green"],
    "yellow": APP_THEME["amber"],
    "orange": APP_THEME["orange"],
    "red": APP_THEME["red"],
    "blue": APP_THEME["blue"],
    "gray": APP_THEME["gray"],
}


def fmt(x, d=1):
    if x == float("inf"):
        return "inf"
    if x == float("-inf"):
        return "-inf"
    return str(round(x, d))


def risk_level(r):
    if r >= 75:
        return "Critical"
    if r >= 50:
        return "High"
    if r >= 25:
        return "Medium"
    return "Low"


def clone(obj):
    return json.loads(json.dumps(obj))


def next_id(prefix, used):
    k = 1
    while "%s%d" % (prefix, k) in used:
        k += 1
    return "%s%d" % (prefix, k)


def node_map(state):
    return {n["id"]: n for n in state["nodes"]}


def is_up(node):
    return bool(node) and node.get("status") in ("Active", "Compromised")


def edge_params(edge, nm):
    src = nm.get(edge["source"])
    avail = edge["capacity"] * (1 - edge.get("reduction", 0) / 100.0)
    if src and src.get("status") == "Compromised":
        avail *= 1 - src.get("degradation", 0) / 100.0
    bg = edge["capacity"] * edge.get("saturation", 0) / 100.0
    return {"avail": avail, "bg": bg, "eff": max(0.0, avail - bg)}


def sample_topology():
    def N(i, name, t, x, y, seg, risk, extra="", fwd=0):
        return {"id": i, "name": name, "type": t, "status": "Active", "risk": risk,
                "segment": seg, "fwdCap": fwd, "degradation": 50, "extra": str(extra), "x": x, "y": y}

    def E(i, u, v, t, cap, lat, risk, extra=""):
        return {"id": i, "source": u, "target": v, "type": t, "capacity": cap, "latency": lat,
                "risk": risk, "status": "Active", "reduction": 0, "saturation": 0, "extra": str(extra)}

    return {
        "nodes": [
            N("C1", "Workstation", "C", 60, 240, "Access", 20),
            N("S1", "Access Switch", "S", 260, 130, "Access", 25),
            N("AP1", "Wi-Fi Access Point", "AP", 260, 350, "Access", 45, 8),
            N("R1", "Core Router A", "R", 480, 70, "Core", 35, "", 1000),
            N("R2", "Core Router B", "R", 480, 310, "Core", 55, "", 1000),
            N("F1", "Edge Firewall", "F", 710, 100, "Edge", 30, 2),
            N("V1", "VPN Gateway", "V", 710, 360, "Edge", 60, 3),
            N("SV1", "Application Server", "SV", 930, 230, "Server", 40, "HTTPS, DB"),
        ],
        "edges": [
            E("L1", "C1", "S1", "ethernet", 1000, 1, 10, 99.9),
            E("L2", "C1", "AP1", "wifi", 300, 5, 45, -52),
            E("L3", "S1", "R1", "fiber", 600, 2, 15, "Physically secured"),
            E("L4", "S1", "R2", "ethernet", 300, 4, 25, 99.5),
            E("L5", "AP1", "R2", "ethernet", 200, 3, 30, 99.7),
            E("L6", "R1", "F1", "fiber", 500, 2, 15, "Physically secured"),
            E("L7", "R1", "V1", "ethernet", 250, 3, 30, 99.8),
            E("L8", "R2", "F1", "ethernet", 300, 5, 25, 99.6),
            E("L9", "R2", "V1", "ethernet", 150, 4, 35, 99.4),
            E("L10", "V1", "SV1", "vpn", 200, 12, 55, "Medium"),
            E("L11", "F1", "SV1", "fiber", 400, 3, 10, "Physically secured"),
        ],
    }


def _num_ok(value, lo, hi=None):
    try:
        v = float(value)
    except (TypeError, ValueError):
        return False
    if v != v or v in (float("inf"), float("-inf")):
        return False
    return v >= lo and (hi is None or v <= hi)


def validate_topology(obj):
    if not obj or not isinstance(obj.get("nodes"), list) or not isinstance(obj.get("edges"), list):
        return 'File must contain "nodes" and "edges" arrays.'
    ids, eids = set(), set()
    import re
    pat = re.compile(r"^[A-Za-z][A-Za-z0-9_-]{0,11}$")
    for n in obj["nodes"]:
        if not isinstance(n, dict) or not isinstance(n.get("id"), str) or not pat.match(n["id"]):
            return "Invalid device id: %s" % (n.get("id") if isinstance(n, dict) else n)
        if n["id"] in ids:
            return "Duplicate device id: " + n["id"]
        ids.add(n["id"])
        if n.get("type") not in NODE_TYPES:
            return "Unknown device type on " + n["id"]
        if n.get("risk") is not None and not _num_ok(n["risk"], 0, 100):
            return "Risk of %s must be 0-100." % n["id"]
    for e in obj["edges"]:
        if not isinstance(e, dict) or not e.get("id"):
            return "Every link needs an id."
        if e["id"] in eids:
            return "Duplicate link id: " + e["id"]
        eids.add(e["id"])
        if e.get("source") not in ids or e.get("target") not in ids:
            return "Link %s references an unknown device." % e["id"]
        if e["source"] == e["target"]:
            return "Link %s is a self-loop (u -> u), which is not allowed." % e["id"]
        if e.get("type") not in LINK_TYPES:
            return "Unknown link type on " + e["id"]
        if not _num_ok(e.get("capacity"), 0):
            return "Capacity of %s must be a non-negative number." % e["id"]
        if not _num_ok(e.get("latency"), 0):
            return "Latency of %s must be a non-negative number." % e["id"]
        if e.get("risk") is not None and not _num_ok(e["risk"], 0, 100):
            return "Risk of %s must be 0-100." % e["id"]
    return None


def normalize_topology(obj):
    nodes = []
    for i, n in enumerate(obj["nodes"]):
        nodes.append({
            "id": n["id"],
            "name": str(n.get("name") or n["id"]),
            "type": n["type"],
            "status": n.get("status") if n.get("status") in NODE_STATUSES else "Active",
            "risk": float(n.get("risk") or 0),
            "segment": str(n.get("segment") or ""),
            "fwdCap": None if n.get("fwdCap") is None or n.get("fwdCap") == "" else float(n.get("fwdCap")),
            "degradation": float(n["degradation"]) if n.get("degradation") is not None else 50.0,
            "extra": "" if n.get("extra") is None else str(n.get("extra")),
            "x": n["x"] if isinstance(n.get("x"), (int, float)) else 100 + (i % 5) * 160,
            "y": n["y"] if isinstance(n.get("y"), (int, float)) else 100 + (i // 5) * 140,
        })
    edges = []
    for e in obj["edges"]:
        edges.append({
            "id": e["id"],
            "source": e["source"],
            "target": e["target"],
            "type": e["type"],
            "capacity": float(e.get("capacity")),
            "latency": float(e.get("latency")),
            "risk": float(e.get("risk") or 0),
            "status": e.get("status") if e.get("status") in LINK_STATUSES else "Active",
            "reduction": float(e.get("reduction") or 0),
            "saturation": float(e.get("saturation") or 0),
            "extra": "" if e.get("extra") is None else str(e.get("extra")),
        })
    return {"nodes": nodes, "edges": edges}


def active_graph(state, skip_node=None, skip_edge=None):
    nm = node_map(state)
    nodes = [n for n in state["nodes"] if is_up(n) and n["id"] != skip_node]
    ids = {n["id"] for n in nodes}
    edges = [e for e in state["edges"]
             if e["status"] == "Active" and e["source"] in ids and e["target"] in ids and e["id"] != skip_edge]
    return {"nodes": nodes, "edges": edges, "ids": ids, "nm": nm}


def _out(graph, node_id, split):
    return ("%s|out" % node_id) if split.get(node_id) else node_id


def _in(graph, node_id, split):
    return ("%s|in" % node_id) if split.get(node_id) else node_id


def build_graph(state, s=None, t=None, skip_node=None, skip_edge=None):
    g = active_graph(state, skip_node, skip_edge)
    G = nx.DiGraph()
    split = {}
    for n in g["nodes"]:
        interior = n["id"] != s and n["id"] != t
        if interior and n["type"] == "R" and n.get("fwdCap") is not None and n["fwdCap"] >= 0:
            split[n["id"]] = True
            G.add_node("%s|in" % n["id"])
            G.add_node("%s|out" % n["id"])
            G.add_edge("%s|in" % n["id"], "%s|out" % n["id"], capacity=float(n["fwdCap"]),
                       kind="node", nid=n["id"])
        else:
            split[n["id"]] = False
            G.add_node(n["id"])
    group = {}
    for e in g["edges"]:
        u = _out(G, e["source"], split)
        v = _in(G, e["target"], split)
        cap = edge_params(e, g["nm"])["eff"]
        group.setdefault((u, v), []).append(e)
    pair_group = {}
    for (u, v), edges in group.items():
        total = sum(edge_params(e, g["nm"])["eff"] for e in edges)
        pair_group[(u, v)] = edges
        G.add_edge(u, v, capacity=total, kind="edge")
    return G, split, pair_group, g


def _decompose_flow(G, flow, s, t):
    work = {}
    for u in G.nodes:
        for v in G[u]:
            f = flow.get(u, {}).get(v, 0)
            if f > EPS:
                work.setdefault(u, {}).setdefault(v, 0.0)
                work[u][v] += f
    paths = []
    guard = 0
    while True:
        guard += 1
        if guard > 10000:
            break
        par = {s: None}
        q = [s]
        h = 0
        found = False
        while h < len(q) and not found:
            u = q[h]
            h += 1
            for v, f in work.get(u, {}).items():
                if f > EPS and v not in par:
                    par[v] = u
                    q.append(v)
                    if v == t:
                        found = True
                        break
        if not found:
            break
        b = float("inf")
        node = t
        while par[node] is not None:
            u = par[node]
            b = min(b, work[u][node])
            node = u
        node = t
        seq = [t]
        while par[node] is not None:
            u = par[node]
            work[u][node] -= b
            seq.append(u)
            node = u
        seq.reverse()
        names = []
        for nm in seq:
            nid = nm.split("|")[0]
            if not names or names[-1] != nid:
                names.append(nid)
        paths.append({"nodes": names, "bn": b})
    return paths


def max_flow_analysis(state, s, t, skip_node=None, skip_edge=None):
    fail = lambda msg: {"ok": False, "flow": 0.0, "msg": msg, "edge_flow": {}, "node_flow": {},
                        "paths": [], "cut": None}
    if not s or not t:
        return fail("Select a source and a destination device.")
    if s == t:
        return fail("Source and destination must be different devices.")
    o = {"skip_node": skip_node, "skip_edge": skip_edge}
    if o["skip_node"] in (s, t):
        o["skip_node"] = None
    full_nm = node_map(state)
    if s not in full_nm or t not in full_nm:
        return fail("Source or destination does not exist.")
    g = active_graph(state, o["skip_node"], o["skip_edge"])
    if s not in g["ids"]:
        return fail("Source %s is %s - no flow can originate." % (s, full_nm[s]["status"]))
    if t not in g["ids"]:
        return fail("Destination %s is %s - no flow can arrive." % (t, full_nm[t]["status"]))

    G, split, group, ag = build_graph(state, s, t, o["skip_node"], o["skip_edge"])
    s_node = _out(G, s, split)
    t_node = _in(G, t, split)
    value, flow = nx.maximum_flow(G, s_node, t_node, capacity="capacity", flow_func=edmonds_karp)
    if value == float("inf"):
        value = float("inf")

    edge_flow = {e["id"]: 0.0 for e in ag["edges"]}
    for (u, v), lst in group.items():
        total = flow.get(u, {}).get(v, 0.0)
        remaining = total
        for e in lst:
            take = min(remaining, edge_params(e, ag["nm"])["eff"])
            edge_flow[e["id"]] = take
            remaining -= take
    node_flow = {}
    inflow = {n["id"]: 0.0 for n in ag["nodes"]}
    outflow = {n["id"]: 0.0 for n in ag["nodes"]}
    for e in ag["edges"]:
        outflow[e["source"]] += edge_flow[e["id"]]
        inflow[e["target"]] += edge_flow[e["id"]]
    for n in ag["nodes"]:
        if split.get(n["id"]):
            node_flow[n["id"]] = flow.get("%s|in" % n["id"], {}).get("%s|out" % n["id"], 0.0)
        else:
            node_flow[n["id"]] = min(inflow[n["id"]], outflow[n["id"]])

    residual_fwd = {}
    for u in G.nodes:
        for v in G[u]:
            f = flow.get(u, {}).get(v, 0.0)
            residual_fwd[(u, v)] = G[u][v]["capacity"] - f
    reach = set()
    stack = [s_node]
    reach.add(s_node)
    while stack:
        u = stack.pop()
        for v in G[u]:
            if residual_fwd[(u, v)] > EPS and v not in reach:
                reach.add(v)
                stack.append(v)
        for w in G.predecessors(u):
            if flow.get(w, {}).get(u, 0.0) > EPS and w not in reach:
                reach.add(w)
                stack.append(w)

    cut_edges, cut_nodes, cap_sum = [], [], 0.0
    for u in G.nodes:
        for v in G[u]:
            if u in reach and v not in reach:
                attr = G[u][v]
                cap = attr["capacity"]
                if cap < BIG and cap > EPS:
                    cap_sum += cap
                    if attr.get("kind") == "node":
                        cut_nodes.append({"id": attr["nid"], "cap": cap})
                    else:
                        cut_edges.append({"id": None, "cap": cap, "pair": (u, v)})
    for c in cut_edges:
        c["id"] = _edge_id_for_pair(c["pair"], group)
        c.pop("pair", None)

    s_side = [n["id"] for n in ag["nodes"] if _in(G, n["id"], split) in reach]
    t_side = [n["id"] for n in ag["nodes"] if _in(G, n["id"], split) not in reach]

    return {
        "ok": True,
        "flow": value,
        "msg": "" if value > EPS else "No capacity-carrying route exists between %s and %s." % (s, t),
        "edge_flow": edge_flow,
        "node_flow": node_flow,
        "paths": _decompose_flow(G, flow, s_node, t_node),
        "cut": {"sSide": s_side, "tSide": t_side, "edges": cut_edges, "nodes": cut_nodes,
                "capacity": cap_sum},
    }


def _edge_id_for_pair(pair, group):
    u, v = pair
    lst = group.get((u, v))
    return lst[0]["id"] if lst else None


def compute_max_flow(state, s, t, skip_node=None, skip_edge=None):
    return max_flow_analysis(state, s, t, skip_node, skip_edge)


def dijkstra_graph(state, s=None, t=None):
    ag = active_graph(state)
    G = nx.DiGraph()
    by_pair = {}
    for n in ag["nodes"]:
        G.add_node(n["id"])
    for e in ag["edges"]:
        u, v = e["source"], e["target"]
        key = (u, v)
        if key not in by_pair or e["latency"] < G[u][v]["latency"]:
            G.add_edge(u, v, latency=e["latency"], eid=e["id"])
            by_pair[key] = e
    return G, ag


def shortest_paths(state, s, t, k=4):
    none = lambda msg: {"ok": False, "msg": msg, "paths": [], "best": float("inf")}
    if not s or not t:
        return none("Select a source and a destination device.")
    if s == t:
        return none("Source and destination must be different devices.")
    G, ag = dijkstra_graph(state)
    if s not in ag["ids"]:
        return none("Source %s is not operational." % s)
    if t not in ag["ids"]:
        return none("Destination %s is not operational." % t)
    if s not in G or t not in G or not nx.has_path(G, s, t):
        return {"ok": True, "msg": "Destination unreachable", "paths": [], "best": float("inf")}
    paths = []
    seen = set()
    for nodes in nx.shortest_simple_paths(G, s, t, weight="latency"):
        key = tuple(nodes)
        if key in seen:
            continue
        seen.add(key)
        edges = []
        for a, b in zip(nodes, nodes[1:]):
            e = G[a][b]
            edges.append({"id": e["eid"], "source": a, "target": b, "latency": e["latency"]})
        lat = sum(e["latency"] for e in edges)
        paths.append({"nodes": list(nodes), "edges": edges, "latency": lat})
        if len(paths) >= (k or 1):
            break
    return {"ok": True, "msg": "", "paths": paths, "best": paths[0]["latency"] if paths else float("inf")}


def reachability(state, s):
    ag = active_graph(state)
    if not s or s not in ag["ids"]:
        return set()
    G = nx.DiGraph()
    for n in ag["nodes"]:
        G.add_node(n["id"])
    for e in ag["edges"]:
        if edge_params(e, ag["nm"])["eff"] > EPS:
            G.add_edge(e["source"], e["target"])
    return nx.descendants(G, s) | {s}


def bottlenecks(state, s, t, mf, thr):
    ag = active_graph(state)
    nm = ag["nm"]
    rows, by_edge, node_rows = [], {}, []
    base = mf["flow"] if mf["ok"] else 0.0
    can = mf["ok"] and base > EPS
    for e in ag["edges"]:
        p = edge_params(e, nm)
        flow = mf["edge_flow"].get(e["id"], 0.0) if mf["ok"] else 0.0
        util = None if p["avail"] <= EPS else (flow + p["bg"]) / p["avail"] * 100.0
        drop = 0.0
        if can:
            drop = base - compute_max_flow(state, s, t, skip_edge=e["id"])["flow"]
        congested = util is not None and util > thr
        saturated = util is not None and util >= 99.99
        critical = drop > EPS
        cls = ("Congested + Critical" if congested and critical else
               "Congested only" if congested else "Critical only" if critical else "-")
        row = {"id": e["id"], "source": e["source"], "target": e["target"], "flow": flow,
               "avail": p["avail"], "eff": p["eff"], "bg": p["bg"], "util": util, "drop": drop,
               "dropPct": drop / base * 100.0 if base > EPS else 0.0, "congested": congested,
               "saturated": saturated, "critical": critical, "cls": cls}
        rows.append(row)
        by_edge[e["id"]] = row
    for n in ag["nodes"]:
        if n["id"] in (s, t):
            continue
        drop = 0.0
        if can:
            drop = base - compute_max_flow(state, s, t, skip_node=n["id"])["flow"]
        node_rows.append({"id": n["id"], "name": n["name"], "drop": drop,
                          "dropPct": drop / base * 100.0 if base > EPS else 0.0, "critical": drop > EPS})
    rows.sort(key=lambda r: -1 if r["util"] is None else r["util"], reverse=True)
    node_rows.sort(key=lambda r: -r["drop"])
    return {"rows": rows, "byEdge": by_edge, "nodeRows": node_rows, "threshold": thr,
            "congested": [r for r in rows if r["congested"]],
            "saturated": [r for r in rows if r["saturated"] and r["flow"] > EPS],
            "critical": [r for r in rows if r["critical"]],
            "critNodes": [r for r in node_rows if r["critical"]]}


def analyze(state, s, t, thr=75):
    mf = compute_max_flow(state, s, t)
    return {"mf": mf, "sp": shortest_paths(state, s, t, 4), "reach": reachability(state, s),
            "bn": bottlenecks(state, s, t, mf, thr)}


def quick_metrics(state, s, t):
    mf = compute_max_flow(state, s, t)
    sp = shortest_paths(state, s, t, 1)
    return {"fmax": mf["flow"], "lat": sp["best"]}


SCENARIOS = {
    "hw": {"label": "Hardware failure (device)", "kind": "node",
           "filter": lambda n: n["type"] in ("R", "S", "SV", "F", "AP", "V")},
    "link": {"label": "Link failure (disable link)", "kind": "link"},
    "bw": {"label": "Bandwidth reduction (%)", "kind": "link", "param": "Capacity reduction %", "def": 50},
    "sat": {"label": "Link saturation (background %)", "kind": "link",
            "param": "Background traffic % of capacity", "def": 60},
    "block": {"label": "Communication blocking (link)", "kind": "link"},
    "comp": {"label": "Router compromise (degrade)", "kind": "node",
             "filter": lambda n: n["type"] == "R", "param": "Forwarding degradation %", "def": 60},
    "vpn": {"label": "VPN disruption (tunnel)", "kind": "link", "filter": lambda e: e["type"] == "vpn"},
    "ap": {"label": "Wireless AP failure / jamming", "kind": "node", "filter": lambda n: n["type"] == "AP"},
    "iso": {"label": "Network-segment isolation", "kind": "segment"},
}


def apply_scenario(state, key, target, param=None):
    sc = SCENARIOS[key]
    nm = node_map(state)
    label = sc["label"].split(" (")[0]
    if key == "iso":
        cross = [x for x in state["edges"]
                 if (nm[x["source"]]["segment"] == target) != (nm[x["target"]]["segment"] == target)
                 and x["status"] == "Active"]
        for x in cross:
            x["status"] = "Disabled"
        return {"action": label, "target": "segment %s (%d links)" % (target, len(cross)),
                "count": len(cross)}
    if sc["kind"] == "node":
        n = nm[target]
        if key == "hw":
            n["status"] = "Failed"
        elif key == "comp":
            n["status"] = "Compromised"
            n["degradation"] = param
        elif key == "ap":
            n["status"] = "Failed"
            for x in state["edges"]:
                if x["type"] == "wifi" and target in (x["source"], x["target"]):
                    x["status"] = "Disabled"
    else:
        e = next(x for x in state["edges"] if x["id"] == target)
        if key in ("link", "vpn"):
            e["status"] = "Disabled"
        elif key == "bw":
            e["reduction"] = param
        elif key == "sat":
            e["saturation"] = param
        elif key == "block":
            e["status"] = "Blocked"
    return {"action": label, "target": target + ("" if param is None else " @ %s%%" % fmt(param, 0)),
            "count": 1}


def mk_net(ids, es):
    nodes = [{"id": i, "name": i, "type": "S", "status": "Active", "risk": 0, "segment": "",
              "fwdCap": 0, "degradation": 50, "extra": "", "x": 0, "y": 0} for i in ids]
    edges = [{"id": "e%d" % i, "source": a[0], "target": a[1], "type": "ethernet",
              "capacity": a[2], "latency": (a[3] if len(a) > 3 else 1), "risk": 0, "status": "Active",
              "reduction": 0, "saturation": 0, "extra": ""} for i, a in enumerate(es)]
    return {"nodes": nodes, "edges": edges}


def run_self_tests():
    out = []
    near = lambda a, b: abs(a - b) < 1e-6
    T = lambda group, name, theory, actual, ok: out.append(
        {"group": group, "name": name, "theory": theory, "actual": actual, "pass": bool(ok)})

    def flow_test(group, name, st, s, t, theory):
        r = compute_max_flow(st, s, t)
        actual = "Fmax = %s Mbps; cut = %s Mbps" % (
            fmt(r["flow"]), fmt(r["cut"]["capacity"]) if r["cut"] else "-")
        ok = near(r["flow"], theory) and (not r["cut"] or near(r["cut"]["capacity"], r["flow"]))
        T(group, name, "Fmax = %s Mbps" % theory, actual, ok)

    flow_test("Max-flow / min-cut", "CLRS Fig. 26.1 network",
              mk_net(["s", "v1", "v2", "v3", "v4", "t"],
                     [["s", "v1", 16], ["s", "v2", 13], ["v1", "v3", 12], ["v2", "v1", 4],
                      ["v2", "v4", 14], ["v3", "v2", 9], ["v3", "t", 20], ["v4", "v3", 7], ["v4", "t", 4]]),
              "s", "t", 23)
    flow_test("Max-flow / min-cut", "Single link 50 Mbps",
              mk_net(["s", "t"], [["s", "t", 50]]), "s", "t", 50)
    flow_test("Max-flow / min-cut", "Parallel diamond: min(10,4)+min(5,8)",
              mk_net(["s", "a", "b", "t"], [["s", "a", 10], ["s", "b", 5], ["a", "t", 4], ["b", "t", 8]]),
              "s", "t", 9)
    flow_test("Edge cases", "Zero-capacity link blocks flow",
              mk_net(["s", "a", "t"], [["s", "a", 0], ["a", "t", 10]]), "s", "t", 0)
    flow_test("Edge cases", "Disconnected destination",
              mk_net(["s", "a", "t"], [["s", "a", 10]]), "s", "t", 0)
    n = mk_net(["s", "a", "t"], [["s", "a", 10], ["a", "t", 10]])
    n["nodes"][2]["status"] = "Failed"
    flow_test("Edge cases", "Failed destination endpoint", n, "s", "t", 0)
    n = mk_net(["s", "a", "t"], [["s", "a", 10], ["a", "t", 10]])
    n["nodes"][0]["status"] = "Disabled"
    flow_test("Edge cases", "Disabled source endpoint", n, "s", "t", 0)

    r = shortest_paths(mk_net(["s", "a", "t"], [["s", "a", 9, 1], ["a", "t", 9, 1], ["s", "t", 9, 5]]), "s", "t", 1)
    T("Shortest path", "Prefers 2-hop 2 ms over direct 5 ms", "d(t) = 2 ms",
      "d(t) = %s ms" % fmt(r["best"]), r["best"] == 2)
    r = shortest_paths(mk_net(["s", "a", "b", "t"],
                              [["s", "t", 1, 10], ["s", "a", 1, 2], ["a", "b", 1, 2], ["b", "t", 1, 2]]), "s", "t", 1)
    T("Shortest path", "Latency beats hop count (3 hops = 6 ms < 1 hop = 10 ms)", "d(t) = 6 ms",
      "d(t) = %s ms" % fmt(r["best"]), r["best"] == 6)
    r = shortest_paths(mk_net(["a", "b"], []), "a", "b", 1)
    T("Shortest path", "Disconnected target", "d(t) = inf", "d(t) = %s" % fmt(r["best"]), r["best"] == float("inf"))
    r = shortest_paths(mk_net(["s", "a", "b", "t"],
                              [["s", "a", 1, 1], ["a", "t", 1, 1], ["s", "b", 1, 2], ["b", "t", 1, 2], ["s", "t", 1, 5]]),
                       "s", "t", 4)
    l = ", ".join(fmt(p["latency"]) for p in r["paths"])
    T("Shortest path", "Yen k-shortest alternatives", "2, 4, 5 ms", l + " ms", l == "2, 4, 5")

    G = "Sample topology C1 -> SV1"
    def mod(fn):
        st = sample_topology()
        fn(st)
        return st
    eg = lambda st, i: next(e for e in st["edges"] if e["id"] == i)
    ng = lambda st, i: next(n for n in st["nodes"] if n["id"] == i)

    flow_test(G, "Baseline (cut {L10, L11} = 200 + 400)", sample_topology(), "C1", "SV1", 600)
    sp = shortest_paths(sample_topology(), "C1", "SV1", 4)
    T(G, "Dijkstra best path", "8 ms via C1,S1,R1,F1,SV1",
      "%s ms via %s" % (fmt(sp["best"]), ",".join(sp["paths"][0]["nodes"])),
      sp["best"] == 8 and ",".join(sp["paths"][0]["nodes"]) == "C1,S1,R1,F1,SV1")
    l = ", ".join(fmt(p["latency"]) for p in sp["paths"])
    T(G, "k-shortest alternatives (k=4)", "8, 13, 16, 18 ms", l + " ms", l == "8, 13, 16, 18")
    flow_test(G, "Link failure L3 (S1->R1 fiber)",
              mod(lambda st: eg(st, "L3").__setitem__("status", "Disabled")), "C1", "SV1", 450)
    flow_test(G, "Device failure R1",
              mod(lambda st: ng(st, "R1").__setitem__("status", "Failed")), "C1", "SV1", 450)
    flow_test(G, "Device failure F1 (only VPN path left)",
              mod(lambda st: ng(st, "F1").__setitem__("status", "Failed")), "C1", "SV1", 200)
    flow_test(G, "Device failure V1",
              mod(lambda st: ng(st, "V1").__setitem__("status", "Failed")), "C1", "SV1", 400)
    flow_test(G, "Bandwidth reduction 50% on L11",
              mod(lambda st: eg(st, "L11").__setitem__("reduction", 50)), "C1", "SV1", 400)
    flow_test(G, "Link saturation 80% on L3 (eff 120)",
              mod(lambda st: eg(st, "L3").__setitem__("saturation", 80)), "C1", "SV1", 570)
    flow_test(G, "Router R1 compromised, 90% degradation",
              mod(lambda st: (ng(st, "R1").__setitem__("status", "Compromised"),
                              ng(st, "R1").__setitem__("degradation", 90))), "C1", "SV1", 525)
    flow_test(G, "Router forwarding capacity R1 = 100 Mbps (node cut)",
              mod(lambda st: ng(st, "R1").__setitem__("fwdCap", 100)), "C1", "SV1", 550)
    flow_test(G, "AP1 failure (redundant wired path remains)",
              mod(lambda st: ng(st, "AP1").__setitem__("status", "Failed")), "C1", "SV1", 600)
    flow_test(G, "Segment isolation: Server segment (L10, L11 off)",
              mod(lambda st: (eg(st, "L10").__setitem__("status", "Disabled"),
                              eg(st, "L11").__setitem__("status", "Disabled"))), "C1", "SV1", 0)
    st = mod(lambda st: eg(st, "L6").__setitem__("status", "Disabled"))
    r = shortest_paths(st, "C1", "SV1", 1)
    T(G, "Latency failover after L6 failure", "d(t) = 13 ms via R2",
      "d(t) = %s ms via %s" % (fmt(r["best"]), ",".join(r["paths"][0]["nodes"])),
      r["best"] == 13)
    mf = compute_max_flow(sample_topology(), "C1", "SV1")
    b = bottlenecks(sample_topology(), "C1", "SV1", mf, 75)
    l11, l10 = b["byEdge"]["L11"], b["byEdge"]["L10"]
    T(G, "Criticality: removing L11 loses 400 Mbps, L10 loses 200",
      "dFmax(L11)=400, dFmax(L10)=200",
      "dFmax(L11)=%s, dFmax(L10)=%s" % (fmt(l11["drop"]), fmt(l10["drop"])),
      near(l11["drop"], 400) and near(l10["drop"], 200))
    return out


def load_topology(path):
    with open(path, "r", encoding="utf-8") as fh:
        obj = json.load(fh)
    err = validate_topology(obj)
    if err:
        raise ValueError(err)
    return normalize_topology(obj), obj


def _print_selftests():
    results = run_self_tests()
    passed = sum(1 for r in results if r["pass"])
    width = max(len(r["name"]) for r in results)
    for r in results:
        print("%-4s %-*s | %-28s | %s" % ("PASS" if r["pass"] else "FAIL", width, r["name"],
                                          r["theory"], r["actual"]))
    print("\n%d / %d checks passed." % (passed, len(results)))
    return 0 if passed == len(results) else 1


def _print_analysis(state, s, t, thr, as_json):
    a = analyze(state, s, t, thr)
    if as_json:
        print(json.dumps({
            "source": s, "destination": t, "threshold": thr,
            "maxFlow": a["mf"]["flow"], "minCut": a["mf"]["cut"]["capacity"] if a["mf"]["cut"] else None,
            "shortestPath": None if a["sp"]["best"] == float("inf") else a["sp"]["best"],
            "augmentingPaths": a["mf"]["paths"],
            "bottlenecks": [r["id"] for r in a["bn"]["saturated"]],
            "criticalLinks": [r["id"] for r in a["bn"]["critical"]],
            "criticalDevices": [r["id"] for r in a["bn"]["critNodes"]],
        }, indent=2, default=str))
        return 0
    print("Source %s -> %s (threshold %s%%)" % (s, t, thr))
    print("Maximum flow : %s Mbps" % fmt(a["mf"]["flow"]))
    if a["mf"]["cut"]:
        print("Minimum cut  : %s Mbps  (cut links: %s)" % (
            fmt(a["mf"]["cut"]["capacity"]),
            ", ".join(c["id"] for c in a["mf"]["cut"]["edges"]) or "-"))
    print("Shortest path: %s" % ("unreachable" if a["sp"]["best"] == float("inf") else "%s ms via %s" % (
        fmt(a["sp"]["best"]), " -> ".join(a["sp"]["paths"][0]["nodes"]))))
    print("Saturated    : %s" % (", ".join(r["id"] for r in a["bn"]["saturated"]) or "none"))
    print("Critical links  : %s" % (", ".join(r["id"] for r in a["bn"]["critical"]) or "none"))
    print("Critical devices: %s" % (", ".join(r["id"] for r in a["bn"]["critNodes"]) or "none"))
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(description="CyberShield Flow Analyzer (NetworkX engine)")
    ap.add_argument("command", choices=["selftest", "analyze"], nargs="?", default="selftest")
    ap.add_argument("topology", nargs="?", default="topologies/default.json")
    ap.add_argument("--source", "-s")
    ap.add_argument("--destination", "-t")
    ap.add_argument("--threshold", type=float, default=75)
    ap.add_argument("--scenario", choices=sorted(SCENARIOS.keys()))
    ap.add_argument("--target")
    ap.add_argument("--param", type=float)
    ap.add_argument("--json", action="store_true")
    args = ap.parse_args(argv)

    if args.command == "selftest":
        return _print_selftests()

    path = Path(args.topology)
    if not path.exists():
        path = Path(__file__).parent / "topologies" / "default.json"
    state, raw = load_topology(path)
    s = args.source or raw.get("source") or state["nodes"][0]["id"]
    t = args.destination or raw.get("destination")
    if not t or t == s:
        t = next((n["id"] for n in state["nodes"] if n["id"] != s), None)
    if args.scenario:
        if not args.target:
            print("--scenario requires --target", file=sys.stderr)
            return 2
        apply_scenario(state, args.scenario, args.target, args.param)
    return _print_analysis(state, s, t, args.threshold, args.json)


if __name__ == "__main__":
    raise SystemExit(main())
