"""Static what-if simulation: apply a proposed change to the inventory *in memory* and re-match advisories.

No repository code is built or run. For a parent upgrade the registry-resolved tree of the candidate version (deps.dev) replaces the
current sub-tree; every node of the new tree is re-checked against OSV with the same local range validation the scan uses. The result
says exactly what is fixed, what remains, and what would be *newly introduced*.
"""
from __future__ import annotations

from typing import Any, Iterable, Optional

from core.models import Component
from sbom.package_extractors.common import make_purl, normalize_name
from vulnerability.osv_client import OsvClient
from vulnerability.vulnerability_correlator import correlate

SEV_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, None: 0}


def check_nodes(osv: OsvClient, nodes: Iterable[tuple[str, str, str]]) -> list[dict]:
    """Confirmed findings for (ecosystem, name, version) nodes, using the production matching code."""
    comps = [Component(bom_ref=f"{e}:{n}@{v}", name=n, version=v, ecosystem=e, purl=make_purl(e, n, v), service_dir=".") for e, n, v in sorted(set(nodes))]
    if not comps:
        return []
    out = correlate(comps, None, [], osv)
    if out["source_status"]["OSV"]["state"] == "unavailable":
        raise RuntimeError("OSV unavailable")
    return [{"id": f.primary_id, "ids": f.vulnerability_ids, "package": f.package_name, "version": f.installed_version, "severity": f.severity, "ecosystem": f.ecosystem}
            for f in out["findings"] if f.affected_status == "confirmed_affected"]


def sbom_diff(before: set[tuple[str, str]], after: set[tuple[str, str]]) -> dict:
    """before/after are {(name, version)}; changed = same name with a different version."""
    bn, an = {}, {}
    for n, v in before:
        bn.setdefault(n, set()).add(v)
    for n, v in after:
        an.setdefault(n, set()).add(v)
    added = sorted(f"{n}@{v}" for n in an.keys() - bn.keys() for v in an[n])
    removed = sorted(f"{n}@{v}" for n in bn.keys() - an.keys() for v in bn[n])
    changed = sorted([{"package": n, "from": ", ".join(sorted(bn[n])), "to": ", ".join(sorted(an[n]))} for n in bn.keys() & an.keys() if bn[n] != an[n]], key=lambda x: x["package"])
    return {"added": added, "removed": removed, "changed": changed, "unchanged": len({n for n in bn.keys() & an.keys() if bn[n] == an[n]})}


def evaluate(before_findings: list[dict], after_findings: list[dict], before_nodes: set[tuple[str, str]], after_nodes: set[tuple[str, str]], known_all: Optional[list[dict]] = None) -> dict[str, Any]:
    """Compare the finding sets (matched by advisory ids + package) and summarise the effect."""
    def key(f): return (normalize_name(f["ecosystem"], f["package_name"] if "package_name" in f else f["package"]), frozenset(f.get("vulnerability_ids") or f.get("ids") or [f.get("primary_id") or f.get("id")]))
    bset = {key(f): f for f in before_findings}
    remaining, new = [], []
    for f in after_findings:
        k = key(f)
        match = next((b for bk, b in bset.items() if bk[0] == k[0] and (bk[1] & k[1])), None)
        (remaining if match else new).append(f)
    known_keys = [key(f) for f in (known_all or [])]
    elsewhere = [f for f in new if any(key(f)[0] == k[0] and (key(f)[1] & k[1]) for k in known_keys)]
    new = [f for f in new if f not in elsewhere]  # already present in the project through another path: not *introduced* by this change
    after_keys = [key(f) for f in after_findings]
    fixed = [f for k, f in bset.items() if not any(k[0] == ak[0] and (k[1] & ak[1]) for ak in after_keys)]
    sev = lambda lst: {s: sum(1 for x in lst if (x.get("severity") or "UNKNOWN") == s) for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN") if any((x.get("severity") or "UNKNOWN") == s for x in lst)}  # noqa: E731
    verdict = ("introduces_risk" if any(SEV_RANK.get(x.get("severity"), 0) >= 3 for x in new) else "reduces_risk" if fixed and not remaining and not new else "partial" if fixed else "no_effect")
    return {"before": {"findings": len(before_findings), "by_severity": sev(before_findings)}, "after": {"findings_remaining": len(remaining), "by_severity": sev(remaining)},
            "fixed": [{"id": f.get("primary_id") or f.get("id"), "package": f.get("package_name") or f.get("package"), "version": f.get("installed_version") or f.get("version"), "severity": f.get("severity")} for f in fixed],
            "remaining": [{"id": f.get("id") or f.get("primary_id"), "package": f.get("package") or f.get("package_name"), "version": f.get("version") or f.get("installed_version"), "severity": f.get("severity")} for f in remaining],
            "newly_introduced": [{"id": f["id"], "package": f["package"], "version": f["version"], "severity": f["severity"]} for f in new],
            "already_present_elsewhere": len(elsewhere), "sbom_diff": sbom_diff(before_nodes, after_nodes), "verdict": verdict}
