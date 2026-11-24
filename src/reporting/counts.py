"""Single source of truth for the counts shown across pages and reports.

Definitions (each number means the same thing everywhere):
  * components        - software packages only (files, container images and CI actions are excluded; the SBOM lists those separately)
  * findings          - vulnerability findings; ``confirmed`` + ``unconfirmed`` = total
  * by_cvss_severity  - findings grouped by the advisory's CVSS severity
  * by_risk / by_priority - findings grouped by contextual risk label / priority (vulnerability findings only)
  * by_risk_other     - assessments that are not vulnerabilities (pipeline, package risk), kept out of the vulnerability totals
  * remediation       - findings fixed / covered counted once, even when several proposals touch the same finding
"""
from __future__ import annotations

from typing import Iterable

RISK_ORDER = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL")


def is_package(c: dict) -> bool:
    return c.get("type") not in ("file", "container") and c.get("purl_type") not in ("docker", "github") and not c.get("is_self")


def package_components(components: Iterable[dict]) -> list[dict]:
    return [c for c in components if is_package(c)]


def risk_breakdown(assessments: Iterable[dict], vulns: Iterable[dict]) -> tuple[dict, dict, dict]:
    """(by_risk, by_priority, other) where the first two cover vulnerability findings only."""
    vid = {v["finding_id"] for v in vulns}
    by_risk: dict[str, int] = {}
    by_pri: dict[str, int] = {}
    other: dict[str, int] = {}
    for a in assessments:
        if a.get("finding_id") in vid:
            by_risk[a.get("label") or "INFORMATIONAL"] = by_risk.get(a.get("label") or "INFORMATIONAL", 0) + 1
            by_pri[a.get("priority") or "P3"] = by_pri.get(a.get("priority") or "P3", 0) + 1
        else:
            k = a.get("kind") or "other"
            other[k] = other.get(k, 0) + 1
    return by_risk, by_pri, other


def remediation_totals(items: Iterable[dict], total_findings: int = 0) -> dict:
    """Unique findings fixed / covered by the proposals (proposal groups overlap, so plain sums over-count)."""
    items = list(items)
    fixed = {(f.get("id"), f.get("package"), f.get("version")) for i in items for f in (i.get("what_if") or {}).get("fixed", [])}
    covered = {f for i in items for f in i.get("finding_ids", [])}
    return {"proposals": len(items), "fixed_unique": len(fixed), "covered_unique": len(covered), "total_findings": total_findings}


def reconcile_summary(result: dict) -> dict:
    """Bring ``result['summary']`` in line with the definitions above (also repairs scans stored before they existed). Idempotent."""
    s = result.get("summary")
    if not isinstance(s, dict):
        return result
    vulns = result.get("vulnerabilities") or []
    ass = result.get("risk_assessments")
    if ass is not None:
        s["by_risk"], s["by_priority"], s["by_risk_other"] = risk_breakdown(ass, vulns)
    comps = result.get("components")
    if comps:
        s["components"] = len(package_components(comps))
        s["other_components"] = sum(1 for c in comps if not is_package(c) and c.get("type") != "file" and not c.get("is_self"))  # CI actions and images
    return result
