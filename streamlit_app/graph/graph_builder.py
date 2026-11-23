"""Build a directed NetworkX dependency graph (edge = parent -> child, "parent depends on child").

Nodes are keyed by CycloneDX ``bom-ref``. Service roots are synthetic nodes (``root:<service dir>``) because Syft
directory scans rarely emit a root dependency record. Every edge carries a ``provenance``:

* ``sbom``                 relationship reported by the CycloneDX ``dependencies`` section
* ``lockfile:<path>``      relationship recorded in a lockfile (only added where the SBOM has none for the parent)
* ``lockfile-direct``      service root -> package that the lockfile/manifest marks as a direct dependency
* ``inferred-no-parent``   service root -> package with no recorded parent (relationship NOT proven; flagged)
"""
from __future__ import annotations

from collections import defaultdict
from typing import Optional

import networkx as nx

from core.models import Component, LockDependency
from sbom.package_extractors.common import normalize_name

ROOT_PREFIX = "root:"


def root_id(service_dir: str) -> str:
    return f"{ROOT_PREFIX}{service_dir}"


def _key(eco: str, name: str, version: Optional[str]) -> tuple:
    return (eco, normalize_name(eco, name), version or "")


def build_graph(sbom_doc: dict, components: list[Component], lock_deps: list[LockDependency],
                services: list[str], repo_name: str = "repository") -> tuple[nx.DiGraph, dict]:
    """Return (graph, build_info). build_info collects malformed/unresolvable relationship data."""
    g = nx.DiGraph()
    info: dict = {"dangling_refs": [], "duplicate_refs": [], "self_loops": [], "malformed": [],
                  "ambiguous_lockfile_edges": [], "inferred_edges": 0, "lockfile_edges": 0, "sbom_edges": 0,
                  "meta_root": None}

    # ---- component nodes
    seen: dict[str, Component] = {}
    for c in components:
        if c.type == "file":
            continue
        if c.bom_ref in seen:
            info["duplicate_refs"].append(c.bom_ref)
            continue
        seen[c.bom_ref] = c
        g.add_node(c.bom_ref, kind="component", label=f"{c.name}@{c.version}" if c.version else c.name, name=c.name,
                   version=c.version, ecosystem=c.ecosystem, purl=c.purl, service_dir=c.service_dir)

    meta_root = ((sbom_doc.get("metadata") or {}).get("component") or {}).get("bom-ref")
    info["meta_root"] = meta_root

    # ---- SBOM relationships
    for d in sbom_doc.get("dependencies") or []:
        if not isinstance(d, dict) or not isinstance(d.get("ref"), str):
            info["malformed"].append(str(d)[:100])
            continue
        parent = d["ref"]
        targets = d.get("dependsOn") or []
        if not isinstance(targets, list):
            info["malformed"].append(f"dependsOn of {parent} is not a list")
            continue
        if parent not in seen and parent != meta_root:
            if targets:
                info["dangling_refs"].append(parent)
            continue
        for t in targets:
            if not isinstance(t, str):
                info["malformed"].append(f"non-string dependsOn entry under {parent}")
                continue
            if t not in seen:
                info["dangling_refs"].append(t)
                continue
            if t == parent:
                info["self_loops"].append(t)
                continue
            if parent == meta_root and parent not in g:
                g.add_node(parent, kind="root", label="SBOM root", service_dir=None)
            g.add_edge(parent, t, provenance="sbom")
            info["sbom_edges"] += 1

    # ---- service roots
    svc_set = sorted({c.service_dir for c in seen.values() if c.service_dir is not None})
    for s in svc_set:
        g.add_node(root_id(s), kind="root", service_dir=s, name=s if s != "." else repo_name,
                   label=(repo_name if s == "." else s) + " (service)", ecosystems=sorted({c.ecosystem for c in seen.values() if c.service_dir == s and c.ecosystem}))

    # index components by scope for lockfile mapping
    by_scope_key: dict[tuple, list[str]] = defaultdict(list)
    by_scope_name: dict[tuple, list[str]] = defaultdict(list)
    for ref, c in seen.items():
        if c.ecosystem and c.service_dir is not None:
            by_scope_key[(c.service_dir,) + _key(c.ecosystem, c.name, c.version)].append(ref)
            by_scope_name[(c.service_dir, c.ecosystem, normalize_name(c.ecosystem, c.name))].append(ref)

    def map_lock(d: LockDependency) -> list[str]:
        return by_scope_key.get((d.service_dir,) + _key(d.ecosystem, d.name, d.version), [])

    # ---- lockfile-derived edges, only for parents without SBOM-recorded children
    for d in lock_deps:
        if not d.requires or not d.version:
            continue
        for pref in map_lock(d):
            if g.out_degree(pref) > 0 and any(g.edges[pref, t].get("provenance") == "sbom" for t in g.successors(pref)):
                continue
            for req in d.requires:
                cands = by_scope_name.get((d.service_dir, d.ecosystem, normalize_name(d.ecosystem, req)), [])
                cands = [c for c in cands if c != pref]
                if len(cands) == 1:
                    if not g.has_edge(pref, cands[0]):
                        g.add_edge(pref, cands[0], provenance=f"lockfile:{d.lockfile}")
                        info["lockfile_edges"] += 1
                elif len(cands) > 1:
                    info["ambiguous_lockfile_edges"].append({"parent": g.nodes[pref]["label"], "requires": req, "candidates": len(cands)})

    # ---- root edges
    direct_refs: dict[str, set[str]] = defaultdict(set)
    scope_has_direct_info: set[tuple] = set()
    for d in lock_deps:
        if d.direct is not None:
            scope_has_direct_info.add((d.service_dir, d.ecosystem))
        if d.direct:
            for r in map_lock(d):
                direct_refs[d.service_dir].add(r)
    for s in svc_set:
        for r in direct_refs.get(s, ()):
            g.add_edge(root_id(s), r, provenance="lockfile-direct")
    # orphans: components with no parent and not known as non-direct by their lockfile
    non_direct_known = {r for d in lock_deps if d.direct is False for r in map_lock(d)}
    for ref, c in seen.items():
        if g.in_degree(ref) == 0 and c.service_dir is not None and ref not in non_direct_known:
            g.add_edge(root_id(c.service_dir), ref, provenance="inferred-no-parent")
            info["inferred_edges"] += 1
    # components still unreachable from every root (dependency cycles or parents that are themselves unrooted):
    # attach the *entry* components of each unreachable strongly-connected group, flagged as inferred.
    roots = roots_of(g)
    reachable = set()
    for r in roots:
        reachable |= nx.descendants(g, r)
    unreachable = [n for n in seen if n not in reachable]
    if unreachable:
        sub = g.subgraph(unreachable)
        cond = nx.condensation(sub)
        for cn in cond.nodes:
            if cond.in_degree(cn) == 0:
                for member in cond.nodes[cn]["members"]:
                    svc = g.nodes[member].get("service_dir")
                    if svc is not None and root_id(svc) in g:
                        g.add_edge(root_id(svc), member, provenance="inferred-no-parent")
                        info["inferred_edges"] += 1
    return g, info


def roots_of(g: nx.DiGraph) -> list[str]:
    return [n for n, a in g.nodes(data=True) if a.get("kind") == "root"]
