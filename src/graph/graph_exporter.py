"""Graph export: JSON (node-link) and the compact payload for the interactive dependency explorer."""
from __future__ import annotations

import networkx as nx

from graph.graph_builder import roots_of


def graph_to_json(g: nx.DiGraph, validation: dict | None = None) -> dict:
    return {
        "directed": True, "semantics": "edge parent->child means parent depends on child",
        "nodes": [{"id": n, **{k: v for k, v in a.items()}} for n, a in g.nodes(data=True)],
        "edges": [{"source": u, "target": v, **a} for u, v, a in g.edges(data=True)],
        "roots": roots_of(g), "validation": validation or {},
    }


def _name(label: str, version: str | None) -> str:
    return label[: -len(version) - 1] if version and label.endswith("@" + version) else label


def dependency_payload(g: nx.DiGraph, rel: dict, vulnerable: dict[str, str], advisories: dict[str, list[str]], info: dict,
                       fixes: dict[str, str], cap: int = 1500) -> dict:
    """Compact node/edge lists for the interactive explorer. Nodes are ranked (vulnerable, direct, shared hubs, shallow) and capped;
    the browser filters/limits further, so no Streamlit rerun is needed. Every kept node keeps a path to a root."""
    roots = roots_of(g)
    depth: dict[str, int] = {}
    for r in roots:
        for n, d in nx.single_source_shortest_path_length(g, r).items():
            depth[n] = min(depth.get(n, d), d)
    sev_rank = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "UNKNOWN": 0}
    comps = [n for n, a in g.nodes(data=True) if a.get("kind") == "component" and n in depth]
    direct = {n for n in comps if any(v.startswith("direct") for v in rel.get(n, {}).values())}
    comps.sort(key=lambda n: (-(sev_rank[vulnerable[n]] + 1 if n in vulnerable else 0), n not in direct, -g.in_degree(n), depth[n]))
    keep = set(roots)
    for n in comps:
        if len(keep) >= cap:
            break
        keep.add(n)
        if depth[n] > 1:  # pull in the shortest chain to a root so the node is never orphaned
            keep |= set(nx.shortest_path(g, next(r for r in roots if nx.has_path(g, r, n)), n))
    nodes = []
    for n in keep:
        a = g.nodes[n]
        scope = info.get(n, {}).get("scope")
        nodes.append({"id": n, "label": _name(a.get("label", n), a.get("version")), "version": a.get("version") or "", "eco": a.get("ecosystem") or "",
                      "kind": "root" if n in roots else ("dev" if scope == "dev" else "prod"), "direct": n in direct, "depth": depth.get(n, 0),
                      "parents": g.in_degree(n), "desc": len(nx.descendants(g, n)), "vuln": vulnerable.get(n, ""),
                      "ids": advisories.get(n, [])[:4], "fix": fixes.get(n, "")})
    edges = [[u, v] for u, v in g.edges if u in keep and v in keep]
    return {"nodes": nodes, "edges": edges, "total": len(comps), "directs": len(direct), "truncated": len(comps) > len(keep) - len(roots)}


def graph_from_json(data: dict) -> nx.DiGraph:
    """Rebuild a DiGraph from ``graph_to_json`` output (used by the UI so scans can be reloaded from SQLite)."""
    g = nx.DiGraph()
    for n in data.get("nodes", []):
        n = dict(n)
        g.add_node(n.pop("id"), **n)
    for e in data.get("edges", []):
        e = dict(e)
        g.add_edge(e.pop("source"), e.pop("target"), **e)
    return g
