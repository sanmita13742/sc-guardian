"""Registry resolver: transitive dependencies for services that have no lockfile.

A ``pom.xml``, ``build.gradle`` or pinned ``requirements.txt`` lists only the dependencies a developer typed. Without running Maven, Gradle or pip
(which would execute repository-controlled code and is forbidden here) the transitive closure is unknown. deps.dev publishes the resolved
dependency graph of every package version, so for each *pinned* direct dependency we fetch that graph and add the packages and edges as
``derived`` dependency records.

Honest limits, recorded in the result and in every derived component (``sc-guardian:resolution = registry-resolved``):
* each direct dependency is resolved on its own; the project's real resolution (version mediation across all dependencies, exclusions,
  BOMs, profiles) can pick different versions
* a service that has a real lockfile for that ecosystem is never resolved this way - the lockfile is authoritative
"""
from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Optional
from urllib.parse import quote

from core.http import HttpClient, NotFound, SourceUnavailable
from core.models import LockDependency
from sbom.fusion.registries import DEPSDEV_SYSTEM
from sbom.package_extractors.common import make_purl, normalize_name
from storage.cache import Cache

TTL = 7 * 24 * 3600
BACK = {"NPM": "npm", "PYPI": "PyPI", "MAVEN": "Maven", "CARGO": "crates.io", "NUGET": "NuGet", "GO": "Go"}
RESOLVABLE = {"Maven", "npm", "PyPI", "NuGet", "crates.io"}
# files that carry exact lock information for an ecosystem: if one exists in a service, nothing is resolved there
LOCKING_FILES = {
    "npm": {"package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml"},
    "PyPI": {"poetry.lock", "uv.lock", "Pipfile.lock"},
    "Maven": {"gradle.lockfile"},
    "NuGet": {"packages.lock.json"},
    "crates.io": {"Cargo.lock"},
}
MANIFEST_ONLY_SOURCES = ("pom.xml", "build.gradle", "build.gradle.kts", "requirements", ".csproj", ".fsproj", ".vbproj")


def _basename(p: str) -> str:
    return p.replace("\\", "/").rsplit("/", 1)[-1]


def candidates(lock_deps: list[LockDependency]) -> list[LockDependency]:
    """Pinned direct dependencies from manifest-like files in services without an authoritative lockfile for the ecosystem."""
    locked: set[tuple] = set()
    for d in lock_deps:
        if _basename(d.lockfile) in LOCKING_FILES.get(d.ecosystem, ()):
            locked.add((d.service_dir, d.ecosystem))
    out = []
    for d in lock_deps:
        if d.derived or d.ecosystem not in RESOLVABLE or not d.version or (d.service_dir, d.ecosystem) in locked:
            continue
        base = _basename(d.lockfile)
        if not any(base == m or base.startswith(m) or base.endswith(m) for m in MANIFEST_ONLY_SOURCES):
            continue
        if d.direct is False:
            continue
        out.append(d)
    return out


def _fetch(http: HttpClient, cache: Optional[Cache], eco: str, name: str, version: str) -> Optional[dict]:
    key = f"{eco}:{name}@{version}"
    hit = cache.get("depsdev_deps", key, ttl=TTL) if cache else None
    if hit is not None:
        return hit or None
    url = f"https://api.deps.dev/v3/systems/{DEPSDEV_SYSTEM[eco]}/packages/{quote(name, safe='')}/versions/{quote(version, safe='')}:dependencies"
    try:
        d = http.get_json(url)
    except NotFound:
        if cache:
            cache.set("depsdev_deps", key, {})
        return None
    nodes = [{"eco": BACK.get(n["versionKey"]["system"], ""), "name": n["versionKey"]["name"], "version": n["versionKey"]["version"], "relation": n.get("relation", "")}
             for n in d.get("nodes", [])]
    res = {"nodes": nodes, "edges": [[e["fromNode"], e["toNode"]] for e in d.get("edges", [])]}
    if cache:
        cache.set("depsdev_deps", key, res)
    return res


def resolve(lock_deps: list[LockDependency], http: HttpClient, cache: Optional[Cache], limit: int = 150, budget_s: float = 90.0, workers: int = 6) -> dict[str, Any]:
    """Return {derived: [LockDependency], stats}. Also fills ``requires`` of the direct records so the graph gets their edges."""
    cands = candidates(lock_deps)
    stats: dict[str, Any] = {"candidates": len(cands), "resolved": 0, "not_found": 0, "unavailable": 0, "skipped_limit": 0, "skipped_budget": 0, "derived_packages": 0,
                             "services": sorted({f"{d.service_dir}:{d.ecosystem}" for d in cands})}
    if not cands:
        return {"derived": [], "stats": stats}
    if len(cands) > limit:
        stats["skipped_limit"] = len(cands) - limit
        cands = cands[:limit]
    t0, down = time.time(), {"n": 0}

    def work(d: LockDependency):
        if time.time() - t0 > budget_s:
            return d, None, "budget"
        if down["n"] >= 4:
            return d, None, "unavailable"
        try:
            r = _fetch(http, cache, d.ecosystem, d.name, d.version)
            down["n"] = 0
            return d, r, "ok" if r else "not_found"
        except SourceUnavailable:
            down["n"] += 1
            return d, None, "unavailable"
        except Exception:
            return d, None, "unavailable"

    derived: dict[tuple, LockDependency] = {}
    existing = {(d.service_dir, d.ecosystem, normalize_name(d.ecosystem, d.name), d.version) for d in lock_deps}
    with ThreadPoolExecutor(max_workers=workers) as ex:
        results = list(ex.map(work, cands))
    for d, r, status in results:
        if status != "ok":
            stats["not_found" if status == "not_found" else "skipped_budget" if status == "budget" else "unavailable"] += 1
            continue
        stats["resolved"] += 1
        nodes, edges = r["nodes"], r["edges"]
        out_edges: dict[int, list[int]] = {}
        for a, b in edges:
            out_edges.setdefault(a, []).append(b)
        self_idx = next((i for i, n in enumerate(nodes) if n["relation"] == "SELF"), 0)
        d.requires = sorted(set(d.requires) | {nodes[j]["name"] for j in out_edges.get(self_idx, [])})
        d.meta = {**(d.meta or {}), "requires_resolved_by": "deps.dev"}
        for i, n in enumerate(nodes):
            if i == self_idx or not n["eco"] or not n["version"]:
                continue
            k = (d.service_dir, n["eco"], normalize_name(n["eco"], n["name"]), n["version"])
            reqs = sorted({nodes[j]["name"] for j in out_edges.get(i, [])})
            if k in existing:
                continue  # already a declared/locked record: do not duplicate
            cur = derived.get(k)
            if cur:
                cur.requires = sorted(set(cur.requires) | set(reqs))
                cur.meta["resolved_from"] = sorted(set(cur.meta.get("resolved_from", [])) | {d.name})
                continue
            derived[k] = LockDependency(name=n["name"], version=n["version"], ecosystem=n["eco"], purl=make_purl(n["eco"], n["name"], n["version"]), direct=False,
                                        requires=reqs, lockfile=f"{d.lockfile} (resolved via deps.dev)", service_dir=d.service_dir, record=f"resolved from {d.name}@{d.version}",
                                        source_type="registry", derived=True, meta={"resolved_from": [d.name]})
    stats["derived_packages"] = len(derived)
    stats["seconds"] = round(time.time() - t0, 1)
    return {"derived": list(derived.values()), "stats": stats}
