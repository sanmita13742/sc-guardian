"""Graph export: JSON (node-link) and Cytoscape element lists, with size-capped subgraph views."""
from __future__ import annotations

from typing import Iterable, Optional

import networkx as nx

from graph.graph_builder import roots_of


def graph_to_json(g: nx.DiGraph, validation: dict | None = None) -> dict:
    return {
        "directed": True, "semantics": "edge parent->child means parent depends on child",
        "nodes": [{"id": n, **{k: v for k, v in a.items()}} for n, a in g.nodes(data=True)],
        "edges": [{"source": u, "target": v, **a} for u, v, a in g.edges(data=True)],
        "roots": roots_of(g), "validation": validation or {},
    }


def subgraph_for(g: nx.DiGraph, mode: str = "overview", focus: Optional[Iterable[str]] = None, root: Optional[str] = None,
                 depth: int = 2, max_nodes: int = 300) -> nx.DiGraph:
    """Bounded views: overview (roots + direct deps), service, vulnerable (paths to focus nodes), neighborhood."""
    keep: set[str] = set()
    if mode == "overview":
        for r in roots_of(g):
            keep.add(r)
            keep |= set(g.successors(r))
    elif mode == "service" and root:
        keep = {root} | set(nx.single_source_shortest_path_length(g, root, cutoff=depth))
    elif mode == "vulnerable" and focus:
        for f in focus:
            if f in g:
                keep.add(f)
                keep |= nx.ancestors(g, f)
    elif mode == "neighborhood" and focus:
        for f in focus:
            if f in g:
                keep.add(f)
                keep |= set(nx.single_source_shortest_path_length(g, f, cutoff=depth))
                keep |= set(nx.single_source_shortest_path_length(g.reverse(copy=False), f, cutoff=depth))
    if len(keep) > max_nodes:
        # keep roots + focus first, then nearest nodes by BFS order
        ordered = [n for n in roots_of(g) if n in keep] + [f for f in (focus or []) if f in keep]
        rest = [n for n in keep if n not in ordered]
        keep = set((ordered + rest)[:max_nodes])
    return g.subgraph(keep).copy()


def to_cytoscape(g: nx.DiGraph, vulnerable: dict[str, str] | None = None, relationships: dict | None = None) -> list[dict]:
    """Cytoscape.js elements. ``vulnerable`` maps node id -> worst severity label."""
    vulnerable = vulnerable or {}
    els = []
    for n, a in g.nodes(data=True):
        els.append({"data": {"id": n, "label": a.get("label", n), "kind": a.get("kind"), "ecosystem": a.get("ecosystem") or "",
                             "version": a.get("version") or "", "purl": a.get("purl") or "",
                             "vuln": vulnerable.get(n, ""), "service": a.get("service_dir") or "",
                             "rel": ",".join(sorted(set((relationships or {}).get(n, {}).values())))}})
    for i, (u, v, a) in enumerate(g.edges(data=True)):
        els.append({"data": {"id": f"e{i}", "source": u, "target": v, "prov": a.get("provenance", "")}})
    return els


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
