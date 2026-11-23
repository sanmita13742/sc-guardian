"""Built-in rule-based SBOM generator: lockfile/manifest records -> CycloneDX 1.5 JSON.

Used when neither Syft nor Trivy is installed (or when selected explicitly). It is deterministic and needs no external
tool: the dependency records come from the scanner's own ecosystem parsers (npm/yarn/pnpm, pip/poetry/uv/Pipfile,
Go, Cargo, Composer, NuGet, Maven, Gradle), and each rule below decides what ends up in the document.

Rules
  R1  only records with a pinned version become components (unpinned ranges are not inventory; they are counted)
  R2  go.sum is a checksum list, not a dependency list -> ignored when go.mod is present
  R3  one component per (ecosystem, name, version, service); repeats merge their lockfile locations
  R4  component identity is the PURL; two services using the same package keep distinct bom-refs
  R5  edges come only from relationships a lockfile actually records and that resolve to exactly one package
  R6  scope: dev dependencies are marked ``optional`` and tagged, direct dependencies tagged
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Optional

from core.models import LockDependency
from sbom.package_extractors.common import make_purl, normalize_name, parse_purl

TOOL_NAME = "sc-guardian-rule-engine"
TOOL_VERSION = "1.0"
PROP = "sc-guardian"


def generate_cyclonedx(lock_deps: list[LockDependency], repo_name: str, commit_sha: str = "", own_version: Optional[str] = None) -> tuple[dict, dict]:
    """Return (cyclonedx_document, stats). Never raises on odd records; skipped records are counted in stats."""
    stats = {"records": len(lock_deps), "skipped_unpinned": 0, "skipped_go_sum": 0, "merged_duplicates": 0, "edges": 0, "ambiguous_edges": 0}
    has_go_mod = {d.service_dir for d in lock_deps if d.lockfile.endswith("go.mod")}
    comps: dict[tuple, dict] = {}
    meta: dict[tuple, LockDependency] = {}
    used_refs: set[str] = set()

    for d in lock_deps:
        if not d.version:
            stats["skipped_unpinned"] += 1  # R1
            continue
        if d.lockfile.endswith("go.sum") and d.service_dir in has_go_mod:
            stats["skipped_go_sum"] += 1  # R2
            continue
        key = (d.service_dir, d.ecosystem, normalize_name(d.ecosystem, d.name), d.version)
        if key in comps:
            stats["merged_duplicates"] += 1  # R3
            c = comps[key]
            n = sum(1 for p in c["properties"] if p["name"].startswith(f"{PROP}:location:"))
            if not any(p["value"] == d.lockfile for p in c["properties"] if p["name"].startswith(f"{PROP}:location:")):
                c["properties"].append({"name": f"{PROP}:location:{n}:path", "value": d.lockfile})
            if d.direct:
                _set_prop(c, f"{PROP}:direct", "true")
            continue
        purl = d.purl or make_purl(d.ecosystem, d.name, d.version)
        pp = parse_purl(purl) if purl else None
        ref = purl or f"{d.ecosystem}:{d.name}@{d.version}"
        if ref in used_refs:  # R4
            ref = f"{ref}#{d.service_dir}"
        used_refs.add(ref)
        c = {"bom-ref": ref, "type": "library", "name": pp["name"] if pp else d.name, "version": d.version,
             "properties": [{"name": f"{PROP}:package:foundBy", "value": f"{TOOL_NAME}:{d.lockfile.rsplit('/', 1)[-1]}"},
                            {"name": f"{PROP}:location:0:path", "value": d.lockfile},
                            {"name": f"{PROP}:service", "value": d.service_dir}]}
        if pp and pp.get("namespace"):
            c["group"] = pp["namespace"]
        if purl:
            c["purl"] = purl
        if d.dev:
            c["scope"] = "optional"  # R6
            c["properties"].append({"name": f"{PROP}:dev", "value": "true"})
        if d.direct:
            c["properties"].append({"name": f"{PROP}:direct", "value": "true"})
        if d.integrity:
            c["properties"].append({"name": f"{PROP}:integrity", "value": d.integrity})
        if d.resolved:
            c["properties"].append({"name": f"{PROP}:resolved", "value": d.resolved[:300]})
        comps[key] = c
        meta[key] = d

    # R5: relationships recorded by lockfiles
    by_name: dict[tuple, list[str]] = {}
    for key, c in comps.items():
        by_name.setdefault((key[0], key[1], key[2]), []).append(c["bom-ref"])
    dependsOn: dict[str, list[str]] = {c["bom-ref"]: [] for c in comps.values()}
    for key, d in meta.items():
        parent = comps[key]["bom-ref"]
        for req in d.requires or []:
            cands = [r for r in by_name.get((d.service_dir, d.ecosystem, normalize_name(d.ecosystem, req)), []) if r != parent]
            if len(cands) == 1:
                if cands[0] not in dependsOn[parent]:
                    dependsOn[parent].append(cands[0])
                    stats["edges"] += 1
            elif len(cands) > 1:
                stats["ambiguous_edges"] += 1

    doc = {
        "bomFormat": "CycloneDX", "specVersion": "1.5",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}", "version": 1,
        "metadata": {
            "timestamp": datetime.now(timezone.utc).isoformat(timespec="seconds"),
            "tools": {"components": [{"type": "application", "name": TOOL_NAME, "version": TOOL_VERSION,
                                      "description": "SC Guardian built-in rule-based SBOM generator (lockfile/manifest parsing)"}]},
            "component": {"bom-ref": f"app:{repo_name}", "type": "application", "name": repo_name,
                          **({"version": commit_sha[:12]} if commit_sha else {})},
            "properties": [{"name": f"{PROP}:generator", "value": "lockfile rules R1-R6 (see sbom/builtin_generator.py)"}],
        },
        "components": list(comps.values()),
        "dependencies": [{"ref": ref, "dependsOn": deps} for ref, deps in dependsOn.items()],
    }
    return doc, stats


def _set_prop(c: dict, name: str, value: str) -> None:
    for p in c["properties"]:
        if p["name"] == name:
            p["value"] = value
            return
    c["properties"].append({"name": name, "value": value})
