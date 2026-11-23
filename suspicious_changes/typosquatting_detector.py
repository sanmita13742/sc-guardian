"""Typosquatting detector: ecosystem-aware name similarity (RapidFuzz) corroborated by registry metadata.

A similarity score is a *signal*. Findings are always classified ``suspicious_name_similarity`` and carry the evidence,
caveats and the reference set used. Well-established packages (by registry age + downloads) are suppressed.
"""
from __future__ import annotations

import re
import time
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any, Optional

from rapidfuzz.distance import DamerauLevenshtein

from core.http import HttpClient, NotFound, SourceUnavailable
from core.models import Component
from sbom.package_extractors.common import normalize_name
from storage.cache import Cache
from suspicious_changes.popular_packages import POPULAR, REFERENCE_VERSION, TRUSTED_NPM_SCOPES
from suspicious_changes.suspicious_models import TyposquatFinding

HOMOGLYPHS = [("rn", "m"), ("vv", "w"), ("0", "o"), ("1", "l"), ("l", "i"), ("5", "s")]
AFFIXES = ("js", "-js", ".js", "py", "-py", "python", "node", "-node", "nodejs", "-official", "-lib", "-dev", "-sdk", "-api")
REGISTRY_TTL = 24 * 3600


def _strip_seps(s: str) -> str:
    return re.sub(r"[-_.]+", "", s)


def candidate_matches(eco: str, name: str, refs: list[str]) -> list[dict]:
    """Return similarity candidates for ``name`` against reference names of the same ecosystem."""
    n = normalize_name(eco, name)
    out = []
    for ref in refs:
        r = normalize_name(eco, ref)
        if n == r:
            continue
        if eco == "npm" and n.startswith("@") != r.startswith("@"):
            continue
        dist = DamerauLevenshtein.distance(n, r)
        longest = max(len(n), len(r))
        sim = round((1 - dist / longest) * 100, 1)
        techniques: list[str] = []
        base = 0
        if dist == 1 and len(r) >= 5:
            techniques.append("single-edit (insertion/deletion/substitution/transposition)")
            if DamerauLevenshtein.distance(n, r) == 1 and sorted(n) == sorted(r):
                techniques.append("character transposition")
            elif len(n) == len(r) + 1 and any(n[:i] + n[i + 1:] == r for i in range(len(n))):
                techniques.append("extra character")
                if any(n[i] == n[i - 1] and n[:i] + n[i + 1:] == r for i in range(1, len(n))):
                    techniques.append("repeated character")
            elif len(n) == len(r) - 1:
                techniques.append("missing character")
            base += 3
        elif dist == 2 and len(r) >= 9 and sim >= 85:
            techniques.append("two edits on a long name")
            base += 2
        if _strip_seps(n) == _strip_seps(r):
            techniques.append("separator variant")
            base += 2
        for a, b in HOMOGLYPHS:
            if len(n) >= 4 and n.replace(a, b) == r and a in n:
                techniques.append(f"look-alike characters ({a}->{b})")
                base += 2
                break
        for af in AFFIXES:
            if n == r + af or n == af.strip("-.") + "-" + r:
                techniques.append(f"common affix ({af.strip('-.')})")
                base += 1
                break
        if techniques:
            out.append({"ref": ref, "distance": dist, "similarity": sim, "techniques": techniques, "points": base})
    out.sort(key=lambda c: (-c["points"], -c["similarity"]))
    return out[:1]  # best match only


def _age_days(iso: Optional[str]) -> Optional[int]:
    if not iso:
        return None
    try:
        dt = datetime.fromisoformat(iso.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return max(0, (datetime.now(timezone.utc) - dt).days)
    except ValueError:
        return None


def fetch_registry_signals(http: HttpClient, cache: Cache | None, eco: str, name: str) -> dict[str, Any]:
    key = f"{eco}:{name}"
    hit = cache.get("registry_signals", key, ttl=REGISTRY_TTL) if cache else None
    if hit is not None:
        return hit
    sig: dict[str, Any] = {"checked": True, "exists": None, "age_days": None, "monthly_downloads": None,
                           "version_count": None, "source": None}
    try:
        if eco == "npm":
            sig["source"] = f"https://registry.npmjs.org/{name}"
            d = http.get_json(sig["source"])
            sig["exists"] = True
            sig["age_days"] = _age_days((d.get("time") or {}).get("created"))
            sig["version_count"] = len(d.get("versions") or {})
            try:
                dl = http.get_json(f"https://api.npmjs.org/downloads/point/last-month/{name}")
                sig["monthly_downloads"] = dl.get("downloads")
            except (NotFound, SourceUnavailable):
                pass
        elif eco == "PyPI":
            sig["source"] = f"https://pypi.org/pypi/{name}/json"
            d = http.get_json(sig["source"])
            sig["exists"] = True
            times = [f["upload_time_iso_8601"] for files in (d.get("releases") or {}).values() for f in files if f.get("upload_time_iso_8601")]
            sig["age_days"] = _age_days(min(times)) if times else None
            sig["version_count"] = len(d.get("releases") or {})
        else:
            sig["checked"] = False
            sig["note"] = f"no registry integration for {eco}"
    except NotFound:
        sig["exists"] = False
    except SourceUnavailable as e:
        sig = {"checked": False, "error": str(e)[:120], "source": sig.get("source")}
        return sig  # do not cache failures
    if cache:
        cache.set("registry_signals", key, sig)
    return sig


def _score_registry(sig: dict) -> tuple[int, list[str], bool]:
    pts, ev, established = 0, [], False
    if not sig.get("checked"):
        return 0, ["registry metadata unavailable; assessment is name-similarity only"], False
    if sig.get("exists") is False:
        ev.append("package name was not found in the public registry (could be a private/internal package or a removed one)")
        return 1, ev, False
    age, dl, vc = sig.get("age_days"), sig.get("monthly_downloads"), sig.get("version_count")
    if age is not None:
        ev.append(f"first published ~{age} days ago")
        if age < 90:
            pts += 2
        elif age > 730:
            pts -= 1
    if dl is not None:
        ev.append(f"{dl:,} downloads in the last month")
        if dl < 1000:
            pts += 2
        elif dl >= 50_000:
            pts -= 3
    if vc is not None:
        ev.append(f"{vc} published versions")
    if age is not None and dl is not None and age > 365 and dl >= 20_000:
        established = True
    return pts, ev, established


def detect_typosquatting(components: list[Component], http: HttpClient | None = None, cache: Cache | None = None,
                         dependency_info: dict[str, dict] | None = None, scan_timestamp: str = "",
                         max_registry_checks: int = 30, min_points: int = 3) -> dict[str, Any]:
    """Return {findings: [...], suppressed: [...], stats: {...}}.

    ``dependency_info`` maps component bom-ref -> {"type": direct|transitive.., "roots": [...]} for context.
    """
    dependency_info = dependency_info or {}
    groups: dict[tuple[str, str], list[Component]] = defaultdict(list)
    for c in components:
        if c.type != "file" and c.ecosystem in POPULAR and c.name:
            groups[(c.ecosystem, c.name)].append(c)
    popular_sets = {e: {normalize_name(e, n) for n in names} for e, names in POPULAR.items()}
    stats = {"unique_packages_checked": len(groups), "reference_version": REFERENCE_VERSION, "candidates": 0,
             "registry_checks": 0, "registry_unavailable": 0, "suppressed_established": 0, "below_threshold": 0}
    findings: list[TyposquatFinding] = []
    suppressed: list[dict] = []
    cands: list[tuple[tuple[str, str], dict]] = []
    for (eco, name), comps in groups.items():
        n = normalize_name(eco, name)
        if n in popular_sets[eco]:
            continue  # it IS a reference package
        if eco == "npm" and name.startswith("@") and name.split("/")[0] in TRUSTED_NPM_SCOPES:
            continue
        m = candidate_matches(eco, name, POPULAR[eco])
        if m:
            cands.append(((eco, name), m[0]))
    stats["candidates"] = len(cands)
    cands.sort(key=lambda x: -x[1]["points"])
    for i, ((eco, name), m) in enumerate(cands):
        pts = m["points"] + (1 if m["similarity"] >= 90 else 0)
        evidence = [f"name '{name}' is {m['similarity']}% similar to well-known {eco} package '{m['ref']}' "
                    f"(edit distance {m['distance']}); techniques: {', '.join(m['techniques'])}"]
        caveats = ["Name similarity does not prove malicious intent; many legitimate packages have similar names."]
        sig: dict[str, Any] = {"checked": False}
        established = False
        if http is not None and i < max_registry_checks:
            sig = fetch_registry_signals(http, cache, eco, name)
            stats["registry_checks"] += 1
            if not sig.get("checked") and sig.get("error"):
                stats["registry_unavailable"] += 1
            rp, rev, established = _score_registry(sig)
            pts += rp
            evidence += rev
        else:
            evidence.append("registry corroboration not performed" + (" (check limit reached)" if http is not None else " (offline mode)"))
        if established:
            stats["suppressed_established"] += 1
            suppressed.append({"package": name, "ecosystem": eco, "similar_to": m["ref"], "reason": "registry shows an established package (age > 1 year, >= 20k monthly downloads)"})
            continue
        if pts < min_points:
            stats["below_threshold"] += 1
            continue
        strength = "high" if pts >= 6 else "medium" if pts >= 4 else "low"
        comps = groups[(eco, name)]
        deps = [dependency_info.get(c.bom_ref, {}) for c in comps]
        types = {d.get("type") for d in deps if d.get("type")}
        dtype = "direct" if "direct" in types else "direct_inferred" if "direct_inferred" in types else "transitive" if "transitive" in types else "unknown"
        if dtype == "transitive":
            caveats.append("This package is a transitive dependency; check which parent introduces it.")
        findings.append(TyposquatFinding(
            package_name=name, ecosystem=eco, versions=sorted({c.version for c in comps if c.version}),
            component_refs=[c.bom_ref for c in comps], similar_to=m["ref"], similarity_score=m["similarity"],
            edit_distance=m["distance"], techniques=m["techniques"],
            reference_source=f"curated popular-{eco}-package list ({REFERENCE_VERSION})", evidence=evidence, registry=sig,
            evidence_strength=strength, evidence_points=pts,
            why_flagged=(f"'{name}' closely resembles the popular {eco} package '{m['ref']}' ({', '.join(m['techniques'])})"
                         + (" and registry signals support suspicion." if pts - m["points"] >= 2 else ".")),
            caveats=caveats, dependency_type=dtype,
            roots=sorted({r for d in deps for r in d.get("roots", [])}), services=sorted({c.service_dir or "." for c in comps}),
            scan_timestamp=scan_timestamp))
    findings.sort(key=lambda f: (-f.evidence_points, f.package_name))
    for n, f in enumerate(findings, 1):
        f.finding_id = f"TYPO-{n:03d}"
    return {"findings": findings, "suppressed": suppressed, "stats": stats}
