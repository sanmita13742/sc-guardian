"""Trivy CycloneDX adapter.

Trivy emits one ``application`` component per lockfile (named by its path), a root component, and libraries whose
bom-ref is the PURL. The canonical form folds this into Syft-like shape:

* application components and the root record are removed; each library gets ``sc-guardian:location:0:path`` = its lockfile
* a library referenced by several lockfiles (monorepo) is cloned per lockfile (``<purl>#<n>``) with its dependency records
  remapped, so every service keeps its own node instead of losing it to a duplicate bom-ref
"""
from __future__ import annotations

import copy

NAME = "trivy"
LOC = "sc-guardian:location:0:path"


def _prop(c: dict, name: str) -> list[str]:
    return [p.get("value", "") for p in c.get("properties", []) or [] if isinstance(p, dict) and p.get("name") == name]


def canonicalize(raw: dict) -> dict:
    d = copy.deepcopy(raw)
    comps = d.get("components") or []
    deps = d.get("dependencies") or []
    apps = {c.get("bom-ref"): c for c in comps if c.get("type") == "application" and not c.get("purl")}
    meta_root = ((d.get("metadata") or {}).get("component") or {}).get("bom-ref")
    dep_of = {r.get("ref"): list(r.get("dependsOn") or []) for r in deps}

    members: dict[str, list[str]] = {}  # app ref -> library refs belonging to that lockfile
    for aref in apps:
        members[aref] = [t for t in dep_of.get(aref, []) if t not in apps]
    owners: dict[str, list[str]] = {}
    for aref, libs in members.items():
        for t in libs:
            owners.setdefault(t, []).append(aref)

    by_ref = {c.get("bom-ref"): c for c in comps if c.get("bom-ref") not in apps}
    out_comps, out_deps = [], []
    new_ref = {}  # (app, original ref) -> canonical ref
    for ref, c in by_ref.items():
        apps_for = owners.get(ref) or [None]
        multi = len(apps_for) > 1
        for i, a in enumerate(apps_for):
            nr = f"{ref}#{i}" if multi else ref
            new_ref[(a, ref)] = nr
            cc = copy.deepcopy(c)
            cc["bom-ref"] = nr
            if a is not None:
                cc.setdefault("properties", []).append({"name": LOC, "value": apps[a].get("name", "")})
            out_comps.append(cc)
    for ref in by_ref:
        for a in owners.get(ref) or [None]:
            targets = []
            for t in dep_of.get(ref, []):
                if t in apps:
                    continue
                targets.append(new_ref.get((a, t)) or new_ref.get((None, t)) or t)
            out_deps.append({"ref": new_ref[(a, ref)], "dependsOn": targets})
    d["components"], d["dependencies"] = out_comps, out_deps
    return d


def locations(c: dict) -> list[str]:
    out = []
    for i in range(20):
        v = _prop(c, f"sc-guardian:location:{i}:path")
        if not v:
            break
        out.append(v[0])
    return out


def found_by(c: dict):
    t = _prop(c, "aquasecurity:trivy:PkgType")
    return f"trivy:{t[0]}" if t else None
