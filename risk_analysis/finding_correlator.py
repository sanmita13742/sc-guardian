"""Cross-detector correlation and dedup: links findings that concern the same package and builds risk assessments."""
from __future__ import annotations

from collections import defaultdict
from typing import Any

from risk_analysis.risk_scorer import score_lockfile_change, score_pipeline, score_typosquat, score_vulnerability
from sbom.package_extractors.common import normalize_name


def _k(eco: str, name: str) -> tuple[str, str]:
    return (eco, normalize_name(eco, name))


def correlate_findings(vulns: list[dict], typos: list[dict], locks: list[dict], rules: dict | None = None, pipes: list[dict] | None = None) -> dict[str, Any]:
    """Return {assessments: [...], correlations: [...]} (assessments are deterministic and rule-based)."""
    v_by = defaultdict(list)
    t_by = defaultdict(list)
    l_by = defaultdict(list)
    for v in vulns:
        v_by[_k(v["ecosystem"], v["package_name"])].append(v)
    for t in typos:
        t_by[_k(t["ecosystem"], t["package_name"])].append(t)
    for c in locks:
        if c["classification"] in ("potentially_suspicious", "unexplained_change"):
            l_by[_k(c["ecosystem"], c["package_name"])].append(c)
    correlations: list[dict] = []
    assessments: list[dict] = []
    for key in set(v_by) | set(t_by) | set(l_by):
        involved = [x["finding_id"] for grp in (v_by.get(key, []), t_by.get(key, []), l_by.get(key, [])) for x in grp]
        kinds = [k for k, g in (("vulnerability", v_by), ("typosquatting", t_by), ("lockfile_change", l_by)) if g.get(key)]
        if len(kinds) > 1:
            correlations.append({"package": key[1], "ecosystem": key[0], "kinds": kinds, "finding_ids": involved,
                                 "note": f"{key[1]} appears in multiple independent detections: {', '.join(kinds)}."})
    for v in vulns:
        key = _k(v["ecosystem"], v["package_name"])
        rel = {}
        if l_by.get(key):
            rel["lockfile_change"] = f"{l_by[key][0]['finding_id']} ({l_by[key][0]['classification']}) changed this package in commit {l_by[key][0]['commit'][:10]}"
        assessments.append(score_vulnerability(v, rules, rel))
    for t in typos:
        key = _k(t["ecosystem"], t["package_name"])
        rel = {}
        added = [c for c in l_by.get(key, []) if c["change_type"] == "added"]
        if added:
            rel["lockfile_addition"] = f"{added[0]['finding_id']}: added in commit {added[0]['commit'][:10]}"
        if v_by.get(key):
            rel["vulnerability"] = f"{v_by[key][0]['finding_id']} ({v_by[key][0]['primary_id']})"
        assessments.append(score_typosquat(t, rules, rel))
    for c in locks:
        key = _k(c["ecosystem"], c["package_name"])
        rel = {}
        if v_by.get(key) and c["classification"] != "insufficient_baseline":
            rel["vulnerability"] = f"{v_by[key][0]['finding_id']} ({v_by[key][0]['primary_id']})"
        if t_by.get(key):
            rel["typosquat"] = f"{t_by[key][0]['finding_id']} resembles {t_by[key][0]['similar_to']}"
        assessments.append(score_lockfile_change(c, rules, rel))
    for p in pipes or []:
        assessments.append(score_pipeline(p, rules))
    return {"assessments": assessments, "correlations": correlations}


def summarize_by_root(vulns: list[dict], assessments: list[dict]) -> list[dict]:
    """Per-root exposure summary: counts of findings by risk label, direct vs transitive."""
    risk = {a["finding_id"]: a["label"] for a in assessments}
    roots: dict[str, dict] = {}
    for v in vulns:
        for e in v.get("exposures", []):
            r = roots.setdefault(e["root"], {"root": e["root"], "findings": 0, "direct": 0, "transitive": 0,
                                             "by_risk": {l: 0 for l in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL")}})
            r["findings"] += 1
            r["direct" if e["relationship"].startswith("direct") else "transitive"] += 1
            r["by_risk"][risk.get(v["finding_id"], "INFORMATIONAL")] += 1
    return sorted(roots.values(), key=lambda r: -r["findings"])
