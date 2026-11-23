"""Dependency tree and statistics for display (no Streamlit imports; the UI renders the returned structures).

Two readable shapes of the same graph:

* top-down   "what does this service / package bring in"   (like ``npm ls``): each package is expanded once, later occurrences are shown as
             references ("shown above") so shared dependencies do not explode the tree
* bottom-up  "who pulls this package in"                    : the reverse tree from a package up to every service root

Depth is the length of the *shortest* path from a root (direct dependency = 1), matching the direct/transitive classification used everywhere else.
"""
from __future__ import annotations

import html
from collections import Counter, deque
from typing import Any, Optional

import networkx as nx

from graph.graph_builder import roots_of

SEV_COLOR = {"CRITICAL": "#b42318", "HIGH": "#e5601c", "MEDIUM": "#d4a72c", "LOW": "#4c8bf5", "UNKNOWN": "#8250df", "": "#7a8794"}
SEV_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "UNKNOWN": 0, "": -1}


def depths_from(g: nx.DiGraph, root: str) -> dict[str, int]:
    return dict(nx.single_source_shortest_path_length(g, root))


def vulnerable_ancestors(g: nx.DiGraph, vuln: dict[str, str]) -> set[str]:
    keep: set[str] = set()
    for n in vuln:
        if n in g:
            keep.add(n)
            keep |= nx.ancestors(g, n)
    return keep


def build_tree(g: nx.DiGraph, root: str, vuln: dict[str, str], info: dict[str, dict], max_depth: int = 12, max_nodes: int = 2500, only: Optional[set[str]] = None,
               hide_dev: bool = False) -> dict[str, Any]:
    """Top-down tree from ``root``. Returns {node: {...}, truncated: bool, shown: int}."""
    depth = depths_from(g, root)
    seen: set[str] = {root}
    counter = {"n": 0, "trunc": False}

    def child_sort(n: str):
        return (-SEV_RANK.get(vuln.get(n, ""), -1), g.nodes[n].get("label", n).lower())

    def make(n: str, d: int, via: Optional[str]) -> dict:
        counter["n"] += 1
        a = g.nodes[n]
        meta = info.get(n, {})
        node = {"id": n, "label": a.get("label", n), "depth": d, "vuln": vuln.get(n, ""), "kind": a.get("kind"), "scope": meta.get("scope"), "license": meta.get("license"),
                "install_script": bool(meta.get("install_script")), "resolution": meta.get("resolution"), "deprecated": bool(meta.get("deprecated")),
                "integrity": meta.get("integrity"), "ref": False, "children": [], "descendants": 0, "vuln_below": 0}
        kids = [k for k in g.successors(n) if (only is None or k in only) and not (hide_dev and info.get(k, {}).get("scope") == "dev")]
        for k in sorted(kids, key=child_sort):
            if counter["n"] >= max_nodes:
                counter["trunc"] = True
                break
            if k in seen:
                a2 = g.nodes[k]
                counter["n"] += 1
                node["children"].append({"id": k, "label": a2.get("label", k), "depth": d + 1, "vuln": vuln.get(k, ""), "ref": True, "children": [], "descendants": 0, "vuln_below": 0,
                                         "scope": info.get(k, {}).get("scope"), "license": None, "install_script": False, "resolution": None, "deprecated": False, "integrity": None, "kind": a2.get("kind")})
                continue
            if d + 1 > max_depth:
                node["more"] = node.get("more", 0) + 1
                continue
            seen.add(k)
            node["children"].append(make(k, d + 1, n))
        node["descendants"] = sum(1 + c["descendants"] for c in node["children"] if not c["ref"])
        node["vuln_below"] = sum((1 if c["vuln"] else 0) + c["vuln_below"] for c in node["children"] if not c["ref"])
        return node

    tree = make(root, 0, None)
    return {"tree": tree, "truncated": counter["trunc"], "shown": counter["n"], "max_depth_reached": max(depth.values()) if depth else 0}


def build_reverse_tree(g: nx.DiGraph, target: str, vuln: dict[str, str], info: dict[str, dict], max_nodes: int = 1500) -> dict[str, Any]:
    """Bottom-up: ``target`` and, below it, each parent chain up to the service roots (each package expanded once)."""
    seen: set[str] = {target}
    counter = {"n": 0}

    def make(n: str, d: int) -> dict:
        counter["n"] += 1
        a = g.nodes[n]
        node = {"id": n, "label": a.get("label", n), "depth": d, "vuln": vuln.get(n, ""), "kind": a.get("kind"), "scope": info.get(n, {}).get("scope"), "license": info.get(n, {}).get("license"),
                "install_script": False, "resolution": info.get(n, {}).get("resolution"), "deprecated": False, "integrity": None, "ref": False, "children": [], "descendants": 0, "vuln_below": 0}
        for p in sorted(g.predecessors(n), key=lambda x: (g.nodes[x].get("kind") != "root", g.nodes[x].get("label", x).lower())):
            if counter["n"] >= max_nodes:
                break
            if p in seen:
                counter["n"] += 1
                node["children"].append({"id": p, "label": g.nodes[p].get("label", p), "depth": d + 1, "vuln": vuln.get(p, ""), "ref": True, "children": [], "descendants": 0,
                                         "vuln_below": 0, "scope": None, "license": None, "install_script": False, "resolution": None, "deprecated": False, "integrity": None, "kind": g.nodes[p].get("kind")})
                continue
            seen.add(p)
            node["children"].append(make(p, d + 1))
        node["descendants"] = sum(1 + c["descendants"] for c in node["children"] if not c["ref"])
        return node

    return {"tree": make(target, 0), "truncated": counter["n"] >= max_nodes, "shown": counter["n"]}


def tree_html(tree: dict, open_levels: int = 1, reverse: bool = False) -> str:
    """Nested <details> markup (collapsible, no scripts). All text is escaped."""
    css = ("<style>.dt{font:13px/1.55 system-ui,Segoe UI,sans-serif}.dt details{margin-left:16px;border-left:1px solid rgba(128,128,128,.35);padding-left:8px}"
           ".dt summary{cursor:pointer;list-style:none;padding:1px 0}.dt summary::-webkit-details-marker{display:none}.dt summary:before{content:'\\25B8';display:inline-block;width:14px;opacity:.7}"
           ".dt details[open]>summary:before{content:'\\25BE'}.dt .leaf{margin-left:30px;padding:1px 0}.dt .b{font-size:11px;border-radius:9px;padding:0 6px;margin-left:5px;border:1px solid rgba(128,128,128,.5)}"
           ".dt .dot{display:inline-block;width:9px;height:9px;border-radius:50%;margin-right:6px}.dt .ref{opacity:.55;font-style:italic}.dt .num{opacity:.65;font-size:11px;margin-left:6px}</style>")

    def badges(n: dict) -> str:
        out = []
        if n.get("vuln"):
            out.append(f'<span class="b" style="color:{SEV_COLOR.get(n["vuln"], "#8250df")};border-color:{SEV_COLOR.get(n["vuln"], "#8250df")}">{html.escape(n["vuln"].title())}</span>')
        if n.get("scope") == "dev":
            out.append('<span class="b">dev</span>')
        elif n.get("scope") == "optional":
            out.append('<span class="b">optional</span>')
        if n.get("install_script"):
            out.append('<span class="b" style="color:#d4a72c;border-color:#d4a72c">install script</span>')
        if n.get("deprecated"):
            out.append('<span class="b" style="color:#e5601c;border-color:#e5601c">deprecated</span>')
        if n.get("integrity") == "mismatch":
            out.append('<span class="b" style="color:#b42318;border-color:#b42318">digest mismatch</span>')
        if n.get("resolution") == "registry-resolved":
            out.append('<span class="b" title="resolved by the registry, not pinned by a lockfile">registry-resolved</span>')
        if n.get("license"):
            out.append(f'<span class="b">{html.escape(str(n["license"])[:28])}</span>')
        return "".join(out)

    def label(n: dict) -> str:
        col = SEV_COLOR.get(n.get("vuln") or "", "#7a8794")
        shape = "border-radius:2px" if n.get("kind") == "root" else ""
        extra = ""
        if n.get("descendants"):
            extra += f'<span class="num">{n["descendants"]} below</span>'
        if n.get("vuln_below"):
            extra += f'<span class="num" style="color:#e5601c">{n["vuln_below"]} vulnerable below</span>'
        if n.get("more"):
            extra += f'<span class="num">+{n["more"]} deeper (depth limit)</span>'
        return f'<span class="dot" style="background:{col};{shape}"></span>{html.escape(n["label"])}{badges(n)}{extra}'

    def rec(n: dict, level: int) -> str:
        if n.get("ref"):
            return f'<div class="leaf ref"><span class="dot" style="background:{SEV_COLOR.get(n.get("vuln") or "", "#7a8794")}"></span>{html.escape(n["label"])} &#8618; shown above</div>'
        if not n["children"]:
            return f'<div class="leaf">{label(n)}</div>'
        op = " open" if level < open_levels else ""
        return f'<details{op}><summary>{label(n)}</summary>' + "".join(rec(c, level + 1) for c in n["children"]) + "</details>"

    return css + '<div class="dt">' + rec(tree, 0) + "</div>"


def graph_stats(g: nx.DiGraph, vuln: dict[str, str]) -> dict[str, Any]:
    """Shape of the transitive closure: depth histogram, longest chain, most shared packages, vulnerable depth."""
    comps = [n for n, a in g.nodes(data=True) if a.get("kind") == "component"]
    per_root = {}
    hist: Counter = Counter()
    best_depth: dict[str, int] = {}
    for r in roots_of(g):
        d = depths_from(g, r)
        per_root[g.nodes[r].get("label", r)] = {"packages": len(d) - 1, "max_depth": max(d.values()) if d else 0}
        for n, v in d.items():
            if n != r and g.nodes[n].get("kind") == "component":
                best_depth[n] = min(best_depth.get(n, 10**9), v)
    for n, v in best_depth.items():
        hist[v] += 1
    longest: list[str] = []
    try:
        dag = nx.DiGraph(g)
        if nx.is_directed_acyclic_graph(dag):
            longest = nx.dag_longest_path(dag)
        else:  # cycles: fall back to the longest shortest-path chain
            far = max(best_depth, key=best_depth.get) if best_depth else None
            if far:
                longest = min((nx.shortest_path(g, r, far) for r in roots_of(g) if nx.has_path(g, r, far)), key=len)
    except Exception:
        pass
    fan_in = sorted(((g.nodes[n].get("label", n), g.in_degree(n)) for n in comps), key=lambda x: -x[1])[:10]
    fan_out = sorted(((g.nodes[n].get("label", n), g.out_degree(n)) for n in comps), key=lambda x: -x[1])[:10]
    vuln_depth: Counter = Counter(best_depth[n] for n in vuln if n in best_depth)
    return {"components": len(comps), "edges": g.number_of_edges(), "depth_histogram": {int(k): v for k, v in sorted(hist.items())}, "max_depth": max(hist) if hist else 0,
            "longest_chain": [g.nodes[n].get("label", n) for n in longest], "most_shared": [x for x in fan_in if x[1] > 1], "biggest_fan_out": [x for x in fan_out if x[1] > 0],
            "vulnerable_by_depth": {int(k): v for k, v in sorted(vuln_depth.items())}, "per_root": per_root, "has_cycles": not nx.is_directed_acyclic_graph(nx.DiGraph(g))}
