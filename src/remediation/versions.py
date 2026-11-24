"""Candidate version selection for upgrades (deps.dev version lists, ecosystem-aware ordering)."""
from __future__ import annotations

import re
from typing import Optional
from urllib.parse import quote

from core.http import HttpClient, NotFound, SourceUnavailable
from sbom.fusion.registries import DEPSDEV_SYSTEM
from storage.cache import Cache
from vulnerability.version_matcher import VersionError, compare

TTL = 24 * 3600
_PRE = re.compile(r"(alpha|beta|rc|dev|snapshot|preview|nightly|canary|next|experimental|\.a\d|\.b\d|-\d+$)", re.I)


def list_versions(http: HttpClient, cache: Optional[Cache], eco: str, name: str) -> list[str]:
    key = f"{eco}:{name}"
    hit = cache.get("depsdev_versions", key, ttl=TTL) if cache else None
    if hit is not None:
        return hit
    system = DEPSDEV_SYSTEM.get(eco)
    if not system:
        return []
    try:
        d = http.get_json(f"https://api.deps.dev/v3/systems/{system}/packages/{quote(name, safe='')}")
    except (NotFound, SourceUnavailable):
        return []
    vs = [v["versionKey"]["version"] for v in d.get("versions", []) if v.get("versionKey")]
    if cache:
        cache.set("depsdev_versions", key, vs)
    return vs


def deprecated_message(http: HttpClient, cache: Optional[Cache], eco: str, name: str, ver: str) -> Optional[str]:
    """The npm registry's deprecation notice for name@ver (e.g. a withdrawn 'bad release'), or None. Other ecosystems: None."""
    if eco != "npm":
        return None
    key = f"{name}@{ver}"
    hit = cache.get("npm_deprecated", key, ttl=TTL) if cache else None
    if hit is not None:
        return hit or None
    try:
        d = http.get_json(f"https://registry.npmjs.org/{quote(name, safe='')}/{quote(ver, safe='')}")
    except (NotFound, SourceUnavailable):
        return None
    msg = str(d.get("deprecated") or "")
    if cache:
        cache.set("npm_deprecated", key, msg)
    return msg or None


def drop_deprecated(http: HttpClient, cache: Optional[Cache], eco: str, name: str, versions: list[str]) -> list[str]:
    """Prefer versions that are not deprecated; if every candidate is deprecated keep them all (validation will then warn)."""
    clean = [v for v in versions if not deprecated_message(http, cache, eco, name, v)]
    return clean or versions


def major_of(v: str) -> Optional[int]:
    m = re.match(r"^[vV]?(\d+)", v or "")
    return int(m.group(1)) if m else None


def change_kind(cur: str, new: str) -> str:
    a, b = re.findall(r"\d+", cur or "")[:3], re.findall(r"\d+", new or "")[:3]
    if not a or not b:
        return "unknown"
    a += ["0"] * (3 - len(a))
    b += ["0"] * (3 - len(b))
    return "major" if a[0] != b[0] else "minor" if a[1] != b[1] else "patch"


def candidates(eco: str, current: str, versions: list[str], min_version: Optional[str] = None, same_major: int = 8, other_major: int = 4) -> list[str]:
    """Stable versions newer than ``current`` (and >= ``min_version``), same major first (ascending), then later majors (ascending)."""
    ok: list[str] = []
    for v in versions:
        if _PRE.search(v) and not _PRE.search(current):
            continue
        try:
            if compare(eco, v, current) <= 0:
                continue
            if min_version and compare(eco, v, min_version) < 0:
                continue
        except VersionError:
            continue
        ok.append(v)
    import functools
    ok.sort(key=functools.cmp_to_key(lambda a, b: compare(eco, a, b)))
    cm = major_of(current)
    same = [v for v in ok if major_of(v) == cm]
    other = [v for v in ok if major_of(v) != cm]
    return same[:same_major] + other[:other_major]
