"""Targeted dependency tracing: per-root classification and bounded path extraction.

Direct/transitive is ALWAYS relative to a root. Paths are produced lazily (shortest first, Yen's algorithm) on the
sub-graph of the target's ancestors only and capped, so large graphs never trigger all-simple-paths enumeration.
"""
from __future__ import annotations

from itertools import islice
from typing import Any

import networkx as nx

from graph.graph_builder import roots_of


def _label(g: nx.DiGraph, n: str) -> str:
    return g.nodes[n].get("label", n)


def trace_component(g: nx.DiGraph, target: str, max_paths: int = 25, max_depth: int = 40) -> dict[str, Any]:
    """Return per-root exposure for ``target``.

    {
      component, label, immediate_parents[], dependents_count,
      roots: [{root, root_label, relationship: direct|transitive|direct_inferred, depth, paths:[[labels...]],
               path_refs:[[ids...]], immediate_parents:[..], truncated}],
    }
    """
    if target not in g:
        return {"component": target, "label": target, "found": False, "roots": [], "immediate_parents": [],
                "dependents_count": 0}
    anc = nx.ancestors(g, target)
    sub = g.subgraph(anc | {target})
    parents = sorted(p for p in g.predecessors(target))
    out_roots = []
    for r in roots_of(g):
        if r not in anc:
            continue
        try:
            shortest = nx.shortest_path_length(sub, r, target)
        except nx.NetworkXNoPath:
            continue
        paths: list[list[str]] = []
        truncated = False
        try:
            gen = nx.shortest_simple_paths(sub, r, target)
            for p in islice(gen, max_paths + 1):
                if len(p) - 1 > max_depth:
                    break
                paths.append(p)
            if len(paths) > max_paths:
                truncated = True
                paths = paths[:max_paths]
        except nx.NetworkXNoPath:
            pass
        edge_prov = g.edges[paths[0][0], paths[0][1]].get("provenance", "") if paths and len(paths[0]) > 1 else ""
        if shortest == 1:
            rel = "direct_inferred" if edge_prov == "inferred-no-parent" else "direct"
        else:
            rel = "transitive"
        # immediate parents of the target that lie on a path from this root
        ip = sorted({p[-2] for p in paths if len(p) >= 2})
        out_roots.append({
            "root": r, "root_label": _label(g, r), "relationship": rel, "depth": shortest,
            "paths": [[_label(g, n) for n in p] for p in paths], "path_refs": paths,
            "immediate_parents": [_label(g, n) for n in ip], "truncated": truncated,
        })
    return {"component": target, "label": _label(g, target), "found": True,
            "immediate_parents": [_label(g, p) for p in parents if g.nodes[p].get("kind") != "root"],
            "dependents_count": len([a for a in anc if g.nodes[a].get("kind") == "component"]),
            "roots": out_roots}


def classify_all(g: nx.DiGraph) -> dict[str, dict[str, str]]:
    """component -> {root: relationship} via one BFS per root (cheap for the whole graph)."""
    res: dict[str, dict[str, str]] = {}
    for r in roots_of(g):
        for n, d in nx.single_source_shortest_path_length(g, r).items():
            if n == r or g.nodes[n].get("kind") != "component":
                continue
            if d == 1:
                inferred = g.edges[r, n].get("provenance") == "inferred-no-parent"
                res.setdefault(n, {})[r] = "direct_inferred" if inferred else "direct"
            else:
                res.setdefault(n, {})[r] = "transitive"
    return res
