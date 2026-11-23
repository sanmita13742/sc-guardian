"""Advanced package risk signals derived from fused metadata (no extra network calls).

Signals are *indicators*, not verdicts, and each states what it does and does not prove:

PKG-INT   lockfile digest differs from the registry's digest for the same version      (possible tampered lockfile / republished artifact)
PKG-INST  direct dependency runs code at install time and publishes no build provenance (install scripts are the classic malware vector)
PKG-NEW   direct dependency version published very recently                             (typical window for hijacked-maintainer releases)
PKG-DEP   direct dependency is deprecated / yanked                                      (no fixes will follow)
PKG-CONF  package is unknown to the public registry but resolved from a registry        (dependency-confusion candidate if it is an internal name)
"""
from __future__ import annotations

import calendar
import time
from typing import Any

from core.models import Component
from pipeline_analysis.models import PipelineFinding

NEW_DAYS = 7


def _age_days(published: str | None, now_ts: str) -> float | None:
    if not published:
        return None
    try:
        t = calendar.timegm(time.strptime(published[:19], "%Y-%m-%dT%H:%M:%S"))
        n = calendar.timegm(time.strptime(now_ts, "%Y-%m-%dT%H:%M:%SZ"))
        return (n - t) / 86400
    except (ValueError, TypeError):
        return None


def _f(rule, title, sev, c: Component, why, fix, strength="high", **extra) -> PipelineFinding:
    return PipelineFinding(kind="package_risk", rule_id=rule, category="package", ecosystem=c.ecosystem or "", title=title, severity=sev, file=(c.locations or [""])[0], line=0,
                           snippet=f"{c.name}@{c.version}", subject=f"{c.name}@{c.version}", why=why, remediation=fix, evidence_strength=strength, extra={"package": c.name, "version": c.version, **extra})


def assess(components: list[Component], scan_ts: str) -> dict[str, Any]:
    out: list[PipelineFinding] = []
    attested = total_meta = 0
    for c in components:
        if c.is_self or c.type in ("file", "container") or not c.ecosystem or not c.version:
            continue
        direct = bool(c.direct_declared)
        if c.integrity.get("lookup") or c.integrity.get("status") in ("verified", "mismatch", "absent", "unverifiable"):
            total_meta += 1
            if c.integrity.get("attested"):
                attested += 1
        if c.integrity.get("status") == "mismatch":
            out.append(_f("PKG-INT", f"Lockfile digest of {c.name}@{c.version} differs from the registry", "HIGH", c,
                          "The digest pinned in the lockfile is not the digest the registry publishes today for this exact version: the lockfile may have been altered, or the package version was re-published.",
                          "Do not install. Compare the lockfile history (`git log -p`) for this entry, regenerate it from a trusted environment, and check the package's release history.",
                          lockfile=c.integrity.get("lockfile", {}).get("file"), algorithm=c.integrity.get("algorithm")))
        if direct and c.install_script and not c.integrity.get("attested"):
            age = _age_days(c.published_at, scan_ts)
            sev = "MEDIUM" if (age is not None and age < 30) else "LOW"
            out.append(_f("PKG-INST", f"{c.name} runs install-time scripts and publishes no build provenance", sev, c,
                          "Install scripts execute arbitrary code on every developer machine and CI runner at `npm install` time, and no signed build attestation links this release to its source.",
                          "Review the script (`npm view <pkg>@<version> scripts`), install with `--ignore-scripts` where possible, and prefer releases with provenance.", strength="medium"))
        age = _age_days(c.published_at, scan_ts)
        if direct and age is not None and 0 <= age < NEW_DAYS:
            out.append(_f("PKG-NEW", f"{c.name}@{c.version} was published {age:.1f} day(s) before the scan", "LOW", c,
                          "Very new releases have had little community review; hijacked-maintainer attacks are typically discovered within days.", "Consider waiting a few days (a minimum release-age policy) before adopting new versions.", strength="medium",
                          published=c.published_at))
        if direct and (c.deprecated or c.integrity.get("yanked")):
            out.append(_f("PKG-DEP", f"{c.name}@{c.version} is " + ("yanked" if c.integrity.get("yanked") else "deprecated"), "MEDIUM" if c.integrity.get("yanked") else "LOW", c,
                          "The maintainers withdrew or deprecated this version; it will not receive security fixes.", "Move to the recommended replacement or a maintained fork."))
        if direct and c.integrity.get("lookup") == "not_found" and c.source_type in ("registry", None) and c.ecosystem in ("npm", "PyPI"):
            out.append(_f("PKG-CONF", f"{c.name} is not found on the public {c.ecosystem} registry", "MEDIUM", c,
                          "The lockfile resolves this name from a registry, but the public registry does not know it. If it is an internal package, anyone can publish the same name publicly and a misconfigured client may install theirs (dependency confusion).",
                          "Scope internal packages (`@org/name`) and pin the registry for that scope; reserve the name on the public registry.", strength="medium"))
    for n, f in enumerate(sorted(out, key=lambda x: ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"].index(x.severity)), 1):
        f.finding_id = f"PKG-{n:03d}"
        f.scan_timestamp = scan_ts
    ordered = sorted(out, key=lambda x: x.finding_id)
    return {"findings": [f.model_dump() for f in ordered], "provenance": {"attested": attested, "with_registry_data": total_meta,
                                                                       "note": "attestation presence only (npm provenance / deps.dev SLSA); signatures are not cryptographically verified here"}}
