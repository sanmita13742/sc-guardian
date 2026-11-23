"""Merge two canonical inventories (e.g. Syft + Trivy) by component identity.

Identity key = (ecosystem, normalised name, version, service_dir). Matching components are unified (union of sources and
locations, primary's bom-ref kept); components seen only by the secondary tool are appended. Dependency records are remapped
onto the unified refs. Neither input is mutated and the raw tool outputs are never rewritten.
"""
from __future__ import annotations

import copy

from core.models import Component
from sbom.package_extractors.common import normalize_name


def identity(c: Component) -> tuple:
    return (c.ecosystem or c.purl_type or "", normalize_name(c.ecosystem or "", c.name), c.version or "", c.service_dir or ".")


def merge_inventories(primary_doc: dict, primary: list[Component], secondary_doc: dict, secondary: list[Component]) -> tuple[dict, list[Component], dict]:
    """Return (merged_doc, merged_components, stats)."""
    comps = [c.model_copy(deep=True) for c in primary]
    by_id = {identity(c): c for c in comps}
    used = {c.bom_ref for c in comps}
    remap: dict[str, str] = {}
    added = matched = 0
    extra_doc_components = []
    sec_raw = {c.get("bom-ref"): c for c in secondary_doc.get("components") or []}
    for c in secondary:
        hit = by_id.get(identity(c))
        if hit is not None:
            matched += 1
            remap[c.bom_ref] = hit.bom_ref
            hit.sources = sorted(set(hit.sources) | set(c.sources))
            hit.locations = sorted(set(hit.locations) | set(c.locations))
            hit.licenses = hit.licenses or c.licenses
            hit.supplier = hit.supplier or c.supplier
            hit.hashes = hit.hashes or c.hashes
            continue
        nc = c.model_copy(deep=True)
        ref, n = nc.bom_ref, 2
        while ref in used:
            ref = f"{nc.bom_ref}#m{n}"
            n += 1
        remap[c.bom_ref] = ref
        nc.bom_ref = ref
        used.add(ref)
        comps.append(nc)
        by_id[identity(nc)] = nc
        added += 1
        raw = copy.deepcopy(sec_raw.get(c.bom_ref) or {"type": "library", "name": c.name, "version": c.version, "purl": c.purl})
        raw["bom-ref"] = ref
        extra_doc_components.append(raw)

    doc = copy.deepcopy(primary_doc)
    doc["components"] = list(doc.get("components") or []) + extra_doc_components
    records: dict[str, list[str]] = {}
    for d in doc.get("dependencies") or []:
        records.setdefault(d["ref"], []).extend(d.get("dependsOn") or [])
    for d in secondary_doc.get("dependencies") or []:
        ref = remap.get(d.get("ref"))
        if ref is None:
            continue
        tgt = [remap[t] for t in d.get("dependsOn") or [] if t in remap]
        cur = records.setdefault(ref, [])
        for t in tgt:
            if t not in cur:
                cur.append(t)
    doc["dependencies"] = [{"ref": r, "dependsOn": sorted(set(t))} for r, t in records.items()]
    props = doc.setdefault("metadata", {}).setdefault("properties", [])
    props.append({"name": "sc-guardian:merged", "value": "true"})
    return doc, comps, {"matched": matched, "added_from_secondary": added, "total": len(comps)}
