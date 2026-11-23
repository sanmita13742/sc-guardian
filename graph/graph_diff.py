"""Scanner-independent graph identity, content hash and diff.

Node ids (bom-refs) differ between scanners and runs, so graphs are compared by *identity*: components by
``service | name@version`` and roots by ``root:service``; edges by the identities of their endpoints.
"""
from __future__ import annotations

import hashlib
from typing import Any


def node_key(n: dict) -> str:
    if n.get("kind") == "root":
        return f"root:{n.get('service_dir') if n.get('service_dir') is not None else n.get('id')}"
    return f"{n.get('service_dir') or '.'}|{n.get('name')}@{n.get('version') or ''}"


def canonical(graph: dict) -> dict[str, Any]:
    """{'nodes': {key: node}, 'edges': {(src_key, dst_key): provenance}} for a ``graph_to_json`` document."""
    by_id = {n["id"]: n for n in graph.get("nodes", [])}
    keys = {i: node_key(n) for i, n in by_id.items()}
    nodes = {keys[i]: {"label": n.get("label"), "kind": n.get("kind"), "ecosystem": n.get("ecosystem"), "service_dir": n.get("service_dir")} for i, n in by_id.items()}
    edges = {(keys[e["source"]], keys[e["target"]]): e.get("provenance", "") for e in graph.get("edges", []) if e["source"] in keys and e["target"] in keys}
    return {"nodes": nodes, "edges": edges}


def graph_hash(graph: dict) -> str:
    c = canonical(graph)
    h = hashlib.sha256()
    for k in sorted(c["nodes"]):
        h.update(k.encode() + b"\n")
    for (a, b) in sorted(c["edges"]):
        h.update(f"{a}->{b}\n".encode())
    return h.hexdigest()[:16]


def diff_graphs(old: dict, new: dict) -> dict[str, Any]:
    a, b = canonical(old), canonical(new)
    an, bn = set(a["nodes"]), set(b["nodes"])
    ae, be = set(a["edges"]), set(b["edges"])
    comp = lambda k: not k.startswith("root:")  # noqa: E731
    added = sorted(k for k in bn - an if comp(k))
    removed = sorted(k for k in an - bn if comp(k))
    # version changes: same service+name present on both sides with different versions
    def by_name(keys):
        out: dict[tuple, set] = {}
        for k in keys:
            svc, rest = k.split("|", 1)
            name, _, ver = rest.rpartition("@")
            out.setdefault((svc, name), set()).add(ver)
        return out
    oa, ob = by_name(k for k in an if comp(k)), by_name(k for k in bn if comp(k))
    changed = sorted(f"{s}|{n}: {', '.join(sorted(oa[(s, n)]))} -> {', '.join(sorted(ob[(s, n)]))}" for (s, n) in oa.keys() & ob.keys() if oa[(s, n)] != ob[(s, n)])
    return {"identical": not (added or removed or ae ^ be), "added_components": added, "removed_components": removed, "version_changes": changed,
            "added_edges": len(be - ae), "removed_edges": len(ae - be),
            "new_direct": sorted(f"{x[1]}" for x in be - ae if x[0].startswith("root:") and comp(x[1])),
            "totals": {"before": {"components": len([k for k in an if comp(k)]), "edges": len(ae)}, "after": {"components": len([k for k in bn if comp(k)]), "edges": len(be)}}}
