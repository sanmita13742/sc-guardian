from __future__ import annotations

from collections import Counter, deque
from typing import Any
from urllib.parse import unquote


GRAPH_FORMAT = "nodegoat-guardian-graph-v1"


def _display_from_ref(ref: str) -> tuple[str, str | None]:
    """Best-effort display text only. Never use this as verified metadata."""
    value = unquote(ref)
    if value.startswith("pkg:npm/"):
        tail = value[len("pkg:npm/") :].split("?", 1)[0].split("#", 1)[0]
        if "@" in tail:
            name, version = tail.rsplit("@", 1)
            return name, version or None
        return tail, None
    tail = value.rsplit("/", 1)[-1]
    if "@" in tail and not tail.startswith("@"):
        name, version = tail.rsplit("@", 1)
        return name or value, version or None
    return value, None


def build_graph(bom: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    if bom.get("bomFormat") != "CycloneDX":
        raise ValueError("Input is not a CycloneDX SBOM")

    components = bom.get("components") or []
    dependencies = bom.get("dependencies") or []
    metadata_component = (bom.get("metadata") or {}).get("component") or {}

    component_by_ref: dict[str, dict[str, Any]] = {}
    component_ref_counts: Counter[str] = Counter()
    for component in components:
        ref = component.get("bom-ref")
        if isinstance(ref, str) and ref:
            component_ref_counts[ref] += 1
            component_by_ref.setdefault(ref, component)

    root = metadata_component.get("bom-ref")
    if isinstance(root, str) and root:
        component_by_ref.setdefault(root, metadata_component)
    else:
        root = None

    all_refs: set[str] = set(component_by_ref)
    edge_set: set[tuple[str, str]] = set()
    duplicate_edge_count = 0
    invalid_dependency_records = 0
    for record in dependencies:
        parent = record.get("ref")
        if not isinstance(parent, str) or not parent:
            invalid_dependency_records += 1
            continue
        all_refs.add(parent)
        for child in record.get("dependsOn") or []:
            if not isinstance(child, str) or not child:
                invalid_dependency_records += 1
                continue
            all_refs.add(child)
            edge = (parent, child)
            if edge in edge_set:
                duplicate_edge_count += 1
            edge_set.add(edge)

    if root:
        all_refs.add(root)

    outgoing: dict[str, set[str]] = {ref: set() for ref in all_refs}
    incoming: dict[str, set[str]] = {ref: set() for ref in all_refs}
    for source, target in edge_set:
        outgoing[source].add(target)
        incoming[target].add(source)

    depths: dict[str, int] = {}
    if root:
        depths[root] = 0
        queue = deque([root])
        while queue:
            parent = queue.popleft()
            for child in sorted(outgoing[parent]):
                if child not in depths:
                    depths[child] = depths[parent] + 1
                    queue.append(child)

    nodes: list[dict[str, Any]] = []
    for ref in sorted(all_refs):
        component = component_by_ref.get(ref)
        verified = component is not None
        inferred_name, inferred_version = _display_from_ref(ref)
        name = component.get("name") if component else inferred_name
        version = component.get("version") if component else inferred_version
        scope = component.get("scope") if component else None
        depth = depths.get(ref)
        node = {
            "id": ref,
            "name": name or inferred_name,
            "version": version,
            "label": f"{name or inferred_name}{('@' + str(version)) if version else ''}",
            "hasComponent": verified,
            "metadata_status": "verified" if verified else "unresolved",
            "purl": component.get("purl") if component else None,
            "type": component.get("type") if component else None,
            "scope": scope,
            "development": scope == "excluded",
            "production": scope != "excluded" if verified else None,
            "depth": depth,
            "direct": depth == 1,
            "transitive": depth is not None and depth >= 2,
            "unreachable": depth is None,
            "leaf": len(outgoing[ref]) == 0,
            "sharedHub": len(incoming[ref]) > 1,
            "inDegree": len(incoming[ref]),
            "outDegree": len(outgoing[ref]),
            "parents": sorted(incoming[ref]),
            "children": sorted(outgoing[ref]),
        }
        nodes.append(node)

    reachable = set(depths)
    direct_connections = sum(1 for source, _ in edge_set if source == root)
    transitive_connections = sum(
        1 for source, _ in edge_set if source in reachable and source != root
    )
    other_connections = sum(1 for source, _ in edge_set if source not in reachable)
    unresolved = sorted(all_refs - set(component_by_ref))
    duplicate_ref_count = sum(max(0, count - 1) for count in component_ref_counts.values())

    stats = {
        "total_nodes": len(all_refs),
        "total_edges": len(edge_set),
        "direct_connections": direct_connections,
        "transitive_connections": transitive_connections,
        "other_connections": other_connections,
        "component_record_count": len(components),
        "dependency_record_count": len(dependencies),
        "metadata_backed_node_count": len(set(component_by_ref) & all_refs),
        "unresolved_node_count": len(unresolved),
        "leaf_node_count": sum(not outgoing[ref] for ref in all_refs),
        "direct_node_count": sum(depth == 1 for depth in depths.values()),
        "transitive_node_count": sum(depth >= 2 for depth in depths.values()),
        "unreachable_node_count": len(all_refs - reachable),
        "shared_hub_count": sum(len(incoming[ref]) > 1 for ref in all_refs),
        "duplicate_ref_count": duplicate_ref_count,
        "duplicate_edge_count": duplicate_edge_count,
        "invalid_dependency_record_count": invalid_dependency_records,
    }
    if stats["total_edges"] != direct_connections + transitive_connections + other_connections:
        raise AssertionError("edge classification invariant failed")

    warnings: list[str] = []
    if not root:
        warnings.append("metadata.component.bom-ref is missing; reachability is unavailable")
    if unresolved:
        warnings.append(f"{len(unresolved)} referenced nodes have no matching component metadata")
    if duplicate_ref_count:
        warnings.append(f"{duplicate_ref_count} duplicate component bom-ref records were reconciled")

    graph = {
        "format": GRAPH_FORMAT,
        "root": root,
        "nodes": nodes,
        "edges": [
            {"source": source, "target": target}
            for source, target in sorted(edge_set)
        ],
        "stats": stats,
        "info": {
            "bomFormat": bom.get("bomFormat"),
            "specVersion": bom.get("specVersion"),
            "serialNumber": bom.get("serialNumber"),
            "warnings": warnings,
        },
    }
    reconciliation = {
        "schema": "nodegoat-guardian-reconciliation-v1",
        "root_ref": root,
        "component_refs": len(component_by_ref),
        "dependency_parent_refs": len(
            {d.get("ref") for d in dependencies if isinstance(d.get("ref"), str)}
        ),
        "all_graph_refs": len(all_refs),
        "unique_edges": len(edge_set),
        "edge_invariant": stats["total_edges"]
        == direct_connections + transitive_connections + other_connections,
        "unresolved_refs": unresolved,
        "unresolved_ref_sample": unresolved[:25],
        "warnings": warnings,
        "stats": stats,
    }
    return graph, reconciliation

