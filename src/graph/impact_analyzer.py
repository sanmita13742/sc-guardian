"""Impact analysis: how widely a (vulnerable) component is used across roots."""
from __future__ import annotations

import networkx as nx

from graph.graph_builder import roots_of


def impact_of(g: nx.DiGraph, ref: str) -> dict:
    if ref not in g:
        return {"affected_roots": [], "root_count": 0, "dependents": 0, "direct_roots": [], "transitive_roots": [],
                "blast_radius_components": 0}
    anc = nx.ancestors(g, ref)
    roots = [r for r in roots_of(g) if r in anc]
    direct = [r for r in roots if g.has_edge(r, ref)]
    return {
        "affected_roots": [g.nodes[r].get("label", r) for r in roots],
        "root_count": len(roots),
        "direct_roots": [g.nodes[r].get("label", r) for r in direct],
        "transitive_roots": [g.nodes[r].get("label", r) for r in roots if r not in direct],
        "dependents": len([a for a in anc if g.nodes[a].get("kind") == "component"]),
        "blast_radius_components": len([d for d in nx.descendants(g, ref) if g.nodes[d].get("kind") == "component"]),
    }
