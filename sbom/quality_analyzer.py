"""SBOM quality assessment: compares lockfile evidence, Syft components and SBOM relationships.

Comparisons are scoped by (ecosystem, service directory); components from another scope are never called "missing".
The report never declares an SBOM *complete*; the best status is "consistent_with_lockfiles".
"""
from __future__ import annotations

from collections import Counter, defaultdict
from typing import Optional

from core.models import Component, InspectionResult, LockDependency
from sbom.package_extractors.common import normalize_name

EXAMPLE_LIMIT = 15


def key_of(eco: str, name: str, version: Optional[str]) -> tuple[str, str, str]:
    return (eco, normalize_name(eco, name), version or "")


def analyze_quality(components: list[Component], sbom_doc: dict, lock_deps: list[LockDependency],
                    inspection: InspectionResult, syft_ok: bool = True, lock_errors: list[dict] | None = None) -> dict:
    lock_errors = lock_errors or []
    limitations: list[str] = []
    pkgs = [c for c in components if c.type != "file" and not c.is_self]

    # ---- metadata gaps
    miss = {"version": [], "purl": [], "license": [], "supplier": [], "hashes": []}
    for c in pkgs:
        if not c.version:
            miss["version"].append(c.bom_ref)
        if not c.purl:
            miss["purl"].append(c.bom_ref)
        if not c.licenses:
            miss["license"].append(c.bom_ref)
        if not c.supplier:
            miss["supplier"].append(c.bom_ref)
        if not c.hashes:
            miss["hashes"].append(c.bom_ref)

    # ---- duplicates / conflicts
    ref_counts = Counter(c.bom_ref for c in components)
    dup_refs = [r for r, n in ref_counts.items() if n > 1]
    by_key: dict[tuple, list[Component]] = defaultdict(list)
    for c in pkgs:
        if c.ecosystem and c.version:
            by_key[key_of(c.ecosystem, c.name, c.version) + (c.service_dir or "?",)].append(c)
    dup_records = [{"package": f"{k[1]}@{k[2]}", "ecosystem": k[0], "service": k[3], "count": len(v),
                    "bom_refs": [x.bom_ref for x in v][:5]} for k, v in by_key.items() if len(v) > 1]
    multi_version: dict[tuple, set] = defaultdict(set)
    for c in pkgs:
        if c.ecosystem and c.version:
            multi_version[(c.ecosystem, normalize_name(c.ecosystem, c.name), c.service_dir)].add(c.version)
    multiple_versions = [{"package": k[1], "ecosystem": k[0], "service": k[2], "versions": sorted(v)}
                         for k, v in multi_version.items() if len(v) > 1]

    # ---- relationships
    deps = [d for d in (sbom_doc.get("dependencies") or []) if isinstance(d, dict)]
    with_edges = {d["ref"] for d in deps if d.get("dependsOn")}
    referenced = {t for d in deps for t in (d.get("dependsOn") or [])}
    in_graph = with_edges | referenced
    no_rel = [c.bom_ref for c in pkgs if c.bom_ref not in in_graph]
    edge_count = sum(len(d.get("dependsOn") or []) for d in deps)
    if not pkgs:
        rel_status = "none"
    elif not edge_count:
        rel_status = "absent"
    elif len(no_rel) / max(len(pkgs), 1) > 0.5:
        rel_status = "partial"
    else:
        rel_status = "mostly_present" if no_rel else "present"

    # ---- lockfile vs SBOM (same ecosystem + service scope only)
    lock_keys: dict[tuple, LockDependency] = {}
    unpinned: list[dict] = []
    for d in lock_deps:
        if not d.version:
            unpinned.append({"name": d.name, "ecosystem": d.ecosystem, "lockfile": d.lockfile})
            continue
        lock_keys.setdefault(key_of(d.ecosystem, d.name, d.version) + (d.service_dir,), d)
    sbom_by_scope: dict[tuple, set] = defaultdict(set)
    for c in pkgs:
        if c.ecosystem and c.version:
            sbom_by_scope[(c.ecosystem, c.service_dir)].add(key_of(c.ecosystem, c.name, c.version))
    sbom_global = {key_of(c.ecosystem, c.name, c.version) for c in pkgs if c.ecosystem and c.version}
    lock_scopes = {(d.ecosystem, d.service_dir) for d in lock_deps if d.version and d.lockfile.rsplit("/", 1)[-1] not in ("go.sum",)}

    missing_from_sbom = []
    for k, d in lock_keys.items():
        # go.sum lists modules that may legitimately be absent from the build list; do not call those missing
        if d.lockfile.endswith("go.sum"):
            continue
        if k[:3] not in sbom_global:
            missing_from_sbom.append({"package": d.name, "version": d.version, "ecosystem": d.ecosystem,
                                      "lockfile": d.lockfile, "service": d.service_dir})
    lock_key_set_by_scope: dict[tuple, set] = defaultdict(set)
    for k, d in lock_keys.items():
        lock_key_set_by_scope[(d.ecosystem, d.service_dir)].add(k[:3])
    absent_from_lock = []
    for c in pkgs:
        if not (c.ecosystem and c.version):
            continue
        scope = (c.ecosystem, c.service_dir)
        if scope in lock_scopes and key_of(c.ecosystem, c.name, c.version) not in lock_key_set_by_scope[scope]:
            absent_from_lock.append({"package": c.name, "version": c.version, "ecosystem": c.ecosystem,
                                     "service": c.service_dir, "found_by": c.found_by, "locations": c.locations[:2]})
    uncovered = sorted({c.ecosystem or c.purl_type or "unknown" for c in pkgs
                        if (c.ecosystem, c.service_dir) not in lock_scopes and (c.ecosystem or c.purl_type)})

    # ---- unresolved identities
    unresolved = [c for c in pkgs if not c.purl or not c.ecosystem or not c.version]
    unsupported_eco = Counter(c.purl_type for c in pkgs if c.purl and not c.ecosystem)

    # ---- status
    if not syft_ok:
        inv = "unavailable"
        limitations.append("No SBOM was generated; inventory relies on lockfile parsing only.")
    elif not pkgs:
        inv = "no_components"
        limitations.append("The SBOM contains no package components.")
    elif missing_from_sbom:
        inv = "incomplete"
    elif absent_from_lock or unresolved or dup_refs:
        inv = "partial"
    else:
        inv = "consistent_with_lockfiles"
    if inv == "consistent_with_lockfiles":
        limitations.append("Consistency with parsed lockfiles does not prove completeness (unparsed ecosystems, "
                           "vendored code and runtime-installed packages are not covered).")
    if unsupported_eco:
        limitations.append("Components of ecosystems without vulnerability-database mapping: " + ", ".join(f"{k} ({v})" for k, v in unsupported_eco.items()))
    if unpinned:
        limitations.append(f"{len(unpinned)} declared dependencies have no pinned version and cannot be matched to advisories.")
    if lock_errors:
        limitations.append(f"{len(lock_errors)} manifest/lockfile(s) could not be parsed.")
    limitations.extend(inspection.limitations)
    if rel_status in ("absent", "partial"):
        limitations.append("Dependency relationships are " + rel_status + " in the SBOM; transitive tracing is limited to what the SBOM and lockfiles record.")

    meta_status = "complete_for_checked_fields" if not any(miss[k] for k in ("version", "purl", "license", "supplier")) else "partial"
    return {
        "inventory_status": inv,
        "dependency_relationships": rel_status,
        "metadata_status": meta_status,
        "total_components": len(components),
        "package_components": len(pkgs),
        "components_by_ecosystem": dict(Counter(c.ecosystem or c.purl_type or "unknown" for c in pkgs)),
        "lockfile_dependencies": len(lock_keys),
        "unpinned_declared_dependencies": len(unpinned),
        "unresolved_components": len(unresolved),
        "missing_metadata": {k: len(v) for k, v in miss.items()},
        "missing_metadata_examples": {k: v[:EXAMPLE_LIMIT] for k, v in miss.items()},
        "missing_relationships": len(no_rel),
        "relationship_edges": edge_count,
        "lockfile_missing_from_sbom": missing_from_sbom[:200],
        "lockfile_missing_from_sbom_count": len(missing_from_sbom),
        "sbom_absent_from_lockfile": absent_from_lock[:200],
        "sbom_absent_from_lockfile_count": len(absent_from_lock),
        "duplicate_bom_refs": dup_refs[:20],
        "duplicate_component_records": dup_records[:50],
        "multiple_versions_same_service": multiple_versions[:50],
        "ecosystems_without_lockfile_scope": uncovered,
        "unpinned_examples": unpinned[:EXAMPLE_LIMIT],
        "lockfile_parse_errors": lock_errors,
        "limitations": limitations,
    }
