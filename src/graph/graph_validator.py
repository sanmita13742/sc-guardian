"""Graph validation: dangling references, duplicates, cycles, orphans, unresolved relationships."""
from __future__ import annotations

import networkx as nx

from graph.graph_builder import roots_of


def validate_graph(g: nx.DiGraph, build_info: dict) -> dict:
    roots = roots_of(g)
    comps = [n for n, a in g.nodes(data=True) if a.get("kind") == "component"]
    reachable: set[str] = set()
    for r in roots:
        reachable |= nx.descendants(g, r)
    unreachable = [n for n in comps if n not in reachable]
    sccs = [sorted(c) for c in nx.strongly_connected_components(g) if len(c) > 1]
    prov: dict[str, int] = {}
    for _, _, a in g.edges(data=True):
        p = a.get("provenance", "unknown").split(":")[0]
        prov[p] = prov.get(p, 0) + 1
    warnings = []
    if build_info["dangling_refs"]:
        warnings.append(f"{len(set(build_info['dangling_refs']))} dependency reference(s) point to components not present in the SBOM")
    if build_info["duplicate_refs"]:
        warnings.append(f"{len(build_info['duplicate_refs'])} duplicate bom-ref record(s) were ignored")
    if sccs:
        warnings.append(f"{len(sccs)} dependency cycle group(s) detected (handled safely)")
    if build_info["inferred_edges"]:
        warnings.append(f"{build_info['inferred_edges']} root->package edge(s) are inferred (package has no recorded parent); "
                        "direct/transitive status for those packages is 'direct (inferred)'")
    if unreachable:
        warnings.append(f"{len(unreachable)} component(s) are not reachable from any service root")
    if build_info["ambiguous_lockfile_edges"]:
        warnings.append(f"{len(build_info['ambiguous_lockfile_edges'])} lockfile relationship(s) were ambiguous and not added")
    if build_info["malformed"]:
        warnings.append(f"{len(build_info['malformed'])} malformed relationship record(s) skipped")
    return {
        "nodes": g.number_of_nodes(), "edges": g.number_of_edges(), "components": len(comps), "roots": roots,
        "is_acyclic": nx.is_directed_acyclic_graph(g), "cycle_groups": sccs[:20],
        "dangling_refs": sorted(set(build_info["dangling_refs"]))[:50],
        "duplicate_refs": sorted(set(build_info["duplicate_refs"]))[:50],
        "self_loops": build_info["self_loops"][:20], "malformed": build_info["malformed"][:20],
        "unreachable_components": unreachable[:100], "unreachable_count": len(unreachable),
        "edge_provenance": prov, "ambiguous_lockfile_edges": build_info["ambiguous_lockfile_edges"][:20],
        "warnings": warnings,
    }
