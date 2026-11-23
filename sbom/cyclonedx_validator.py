"""CycloneDX validation (structural profile + referential integrity) and normalization to Component models.

Note: this validates a JSON-Schema *profile* of the fields the scanner relies on (CycloneDX 1.4-1.7 shape) plus
bom-ref integrity. It is not a byte-for-byte validation against every optional part of the official schema.
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

import jsonschema

from config.constants import PURL_TO_OSV
from core.models import Component
from core.repository_inspector import service_for_path
from sbom.package_extractors.common import parse_purl

SELF_MANIFESTS = {"package.json", "pyproject.toml", "setup.py", "pom.xml", "Cargo.toml", "composer.json", "build.gradle", "build.gradle.kts"}
SUPPORTED_SPECS = ("1.4", "1.5", "1.6", "1.7")

PROFILE_SCHEMA = {
    "type": "object",
    "required": ["bomFormat", "specVersion"],
    "properties": {
        "bomFormat": {"const": "CycloneDX"},
        "specVersion": {"type": "string", "pattern": r"^1\.\d+$"},
        "version": {"type": "integer"},
        "metadata": {"type": "object"},
        "components": {
            "type": "array",
            "items": {
                "type": "object",
                "required": ["type", "name"],
                "properties": {
                    "type": {"type": "string"}, "name": {"type": "string", "minLength": 1},
                    "version": {"type": "string"}, "purl": {"type": "string"}, "bom-ref": {"type": "string"},
                    "licenses": {"type": "array"}, "hashes": {"type": "array"}, "properties": {"type": "array"},
                },
            },
        },
        "dependencies": {
            "type": "array",
            "items": {
                "type": "object", "required": ["ref"],
                "properties": {"ref": {"type": "string"}, "dependsOn": {"type": "array", "items": {"type": "string"}}},
            },
        },
    },
}


def validate_cyclonedx(doc: Any) -> dict:
    """Return {valid, errors[], warnings[], stats{}}. Never raises on malformed input."""
    errors: list[str] = []
    warnings: list[str] = []
    stats = {"components": 0, "dependencies": 0, "spec_version": None}
    if not isinstance(doc, dict):
        return {"valid": False, "errors": ["document is not a JSON object"], "warnings": [], "stats": stats}
    v = jsonschema.Draft7Validator(PROFILE_SCHEMA)
    for e in sorted(v.iter_errors(doc), key=lambda e: list(e.path))[:25]:
        errors.append(f"{'/'.join(str(p) for p in e.path) or '<root>'}: {e.message[:160]}")
    spec = doc.get("specVersion")
    stats["spec_version"] = spec
    if isinstance(spec, str) and spec not in SUPPORTED_SPECS:
        warnings.append(f"specVersion {spec} is outside the tested range {SUPPORTED_SPECS[0]}-{SUPPORTED_SPECS[-1]}")
    comps = doc.get("components") if isinstance(doc.get("components"), list) else []
    deps = doc.get("dependencies") if isinstance(doc.get("dependencies"), list) else []
    stats["components"], stats["dependencies"] = len(comps), len(deps)
    refs: dict[str, int] = {}
    meta_comp = (doc.get("metadata") or {}).get("component") if isinstance(doc.get("metadata"), dict) else None
    if isinstance(meta_comp, dict) and meta_comp.get("bom-ref"):
        refs[meta_comp["bom-ref"]] = 1
    for c in comps:
        if isinstance(c, dict):
            r = c.get("bom-ref")
            if r:
                refs[r] = refs.get(r, 0) + 1
            else:
                warnings.append(f"component {c.get('name')!r} has no bom-ref")
            if c.get("purl") and not str(c["purl"]).startswith("pkg:"):
                errors.append(f"component {c.get('name')!r} has a malformed purl")
    dup = [r for r, n in refs.items() if n > 1]
    if dup:
        errors.append(f"duplicate bom-ref values: {dup[:5]}")
    dangling = set()
    for d in deps:
        if not isinstance(d, dict):
            continue
        if d.get("ref") not in refs:
            dangling.add(d.get("ref"))
        for t in d.get("dependsOn", []) or []:
            if t not in refs:
                dangling.add(t)
    if dangling:
        warnings.append(f"{len(dangling)} dependency reference(s) point to unknown components, e.g. {sorted(map(str, dangling))[:3]}")
    return {"valid": not errors, "errors": errors, "warnings": warnings, "stats": stats}


def _prop(c: dict, name: str) -> list[str]:
    return [p.get("value", "") for p in c.get("properties", []) or [] if isinstance(p, dict) and p.get("name") == name]


def _rel_location(loc: str, repo_root: Path) -> str:
    p = loc.replace("\\", "/")
    root = str(Path(repo_root).resolve()).replace("\\", "/").rstrip("/")
    if p.lower().startswith(root.lower() + "/"):
        p = p[len(root) + 1:]
    return p.lstrip("/")


def _licenses(c: dict) -> list[str]:
    out = []
    for l in c.get("licenses", []) or []:
        if not isinstance(l, dict):
            continue
        if "expression" in l:
            out.append(str(l["expression"]))
        lic = l.get("license") or {}
        val = lic.get("id") or lic.get("name")
        if val:
            out.append(str(val))
    return out


def normalize_components(doc: dict, repo_root: Path, service_dirs: list[str]) -> list[Component]:
    """Convert CycloneDX components to Component models, mapping each to its owning service directory."""
    result: list[Component] = []
    for c in doc.get("components", []) or []:
        if not isinstance(c, dict) or not c.get("name"):
            continue
        purl = c.get("purl")
        pp = parse_purl(purl) if purl else None
        locs = []
        for i in range(0, 20):
            vals = _prop(c, f"syft:location:{i}:path") or _prop(c, f"sc-guardian:location:{i}:path")
            if not vals:
                break
            locs.append(_rel_location(vals[0], repo_root))
        svc = None
        if locs:
            # a lockfile/manifest location decides the service; use the nearest ancestor service dir
            svc = service_for_path(locs[0], service_dirs)
        supplier = (c.get("supplier") or {}).get("name") if isinstance(c.get("supplier"), dict) else None
        supplier = supplier or c.get("publisher") or (c.get("author") if isinstance(c.get("author"), str) else None)
        own = bool(svc is not None and locs and locs[0] in {(f"{svc}/{m}" if svc != "." else m) for m in SELF_MANIFESTS})
        result.append(Component(
            bom_ref=c.get("bom-ref") or f"gen:{c['name']}@{c.get('version', '')}",
            name=(pp["osv_name"] if pp and pp["ecosystem"] in ("npm", "Maven", "Go", "Packagist") else c["name"]),
            version=c.get("version"), group=c.get("group"), type=c.get("type", "library"), purl=purl,
            ecosystem=pp["ecosystem"] if pp else None, purl_type=pp["type"] if pp else None,
            licenses=_licenses(c), supplier=supplier, cpe=c.get("cpe"),
            hashes=[h for h in c.get("hashes", []) or [] if isinstance(h, dict)],
            locations=locs, service_dir=svc, found_by=(_prop(c, "syft:package:foundBy") or _prop(c, "sc-guardian:package:foundBy")
                                       or [f"trivy:{t[0]}" if (t := _prop(c, "aquasecurity:trivy:PkgType")) else None])[0], is_self=own,
        ))
    return result


def load_sbom(path: str | Path) -> dict:
    return json.loads(Path(path).read_text(encoding="utf-8"))
