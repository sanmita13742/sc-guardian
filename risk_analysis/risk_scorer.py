"""Deterministic, rule-based risk scoring. No LLM is involved in labels, scores or factors."""
from __future__ import annotations

from typing import Any, Optional

from config.constants import RISK_ORDER
from risk_analysis.risk_rules import DEFAULT_RULES, RULES_VERSION


def label_for(score: int, thresholds: dict) -> str:
    for lab in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        if score >= thresholds[lab]:
            return lab
    return "INFORMATIONAL"


def _cap(label: str, cap: str) -> tuple[str, bool]:
    if RISK_ORDER.index(label) < RISK_ORDER.index(cap):
        return cap, True
    return label, False


def _assessment(fid: str, kind: str, score: int, factors: list[dict], rules: dict, cap: Optional[str], unknowns: list[str],
                cvss_severity: Optional[str] = None) -> dict[str, Any]:
    score = max(score, 0)
    label = label_for(score, rules["thresholds"])
    capped = False
    if cap:
        label, capped = _cap(label, cap)
        if capped:
            factors.append({"factor": "label cap", "points": 0, "detail": f"label limited to {cap} for this finding type/state"})
    return {"finding_id": fid, "kind": kind, "score": score, "label": label, "factors": factors, "unknowns": unknowns,
            "cvss_severity": cvss_severity, "rules_version": RULES_VERSION,
            "thresholds": rules["thresholds"]}


def score_vulnerability(f: dict, rules: dict | None = None, related: dict | None = None) -> dict[str, Any]:
    r = (rules or DEFAULT_RULES)["vulnerability"]
    rules = rules or DEFAULT_RULES
    related = related or {}
    factors: list[dict] = []
    unknowns: list[str] = []
    total = 0
    sev = f.get("severity")
    key = sev if sev in r["severity_points"] else "UNAVAILABLE"
    pts = r["severity_points"][key]
    total += pts
    if sev:
        factors.append({"factor": "CVSS severity", "points": pts,
                        "detail": f"{sev}" + (f" (CVSS {f['cvss_score']} from {f.get('severity_source')})" if f.get("cvss_score") is not None else f" (from {f.get('severity_source')}; no numeric score)")})
    else:
        factors.append({"factor": "CVSS severity", "points": pts, "detail": "severity/CVSS unavailable from the advisory sources; neutral baseline used (not treated as low or critical)"})
        unknowns.append("Severity/CVSS is not available for this advisory.")
    if f.get("kev"):
        total += r["kev"]
        factors.append({"factor": "Known exploited (CISA KEV)", "points": r["kev"], "detail": f"{(f.get('kev_info') or {}).get('cve')} is in the CISA KEV catalog"})
        if str((f.get("kev_info") or {}).get("ransomware_use", "")).lower() == "known":
            total += r["kev_ransomware"]
            factors.append({"factor": "Ransomware campaign use (KEV)", "points": r["kev_ransomware"], "detail": "KEV flags known ransomware use"})
    else:
        factors.append({"factor": "Known exploited (CISA KEV)", "points": 0, "detail": "not listed in the KEV catalog (or catalog unavailable); absence does not imply it is not exploited"})
    dt = f.get("dependency_type", "unknown")
    ep = r["exposure"].get(dt, 0)
    total += ep
    factors.append({"factor": "Dependency exposure", "points": ep,
                    "detail": {"direct": "direct dependency of at least one application root", "direct_inferred": "direct dependency (inferred: no recorded parent)",
                               "transitive": "transitive dependency only (not discounted: reachability is unknown)",
                               "unknown": "not reachable from any root in the graph"}.get(dt, dt)})
    if len(f.get("roots", [])) >= 2:
        total += r["multiple_roots"]
        factors.append({"factor": "Multiple application roots", "points": r["multiple_roots"], "detail": f"affects {len(f['roots'])} roots: {', '.join(f['roots'][:4])}"})
    if f.get("affected_status") == "confirmed_affected" and not f.get("fixed_versions"):
        total += r["no_fix_recorded"]
        factors.append({"factor": "No fixed version recorded", "points": r["no_fix_recorded"], "detail": "remediation requires mitigation, replacement or monitoring"})
    elif f.get("fixed_versions"):
        factors.append({"factor": "Fix available", "points": 0, "detail": f"fixed in {', '.join(f['fixed_versions'][:3])}"})
    if f.get("dev_dependency"):
        total += r["dev_dependency"]
        factors.append({"factor": "Development-only dependency", "points": r["dev_dependency"], "detail": "lockfile marks it dev-only; build/CI exposure remains"})
    if related.get("lockfile_change"):
        total += r["correlated_lockfile_change"]
        factors.append({"factor": "Correlated lockfile change", "points": r["correlated_lockfile_change"], "detail": related["lockfile_change"]})
    factors.append({"factor": "Reachability", "points": 0, "detail": "not assessed (unknown; NOT treated as unreachable)"})
    unknowns.append("Reachability of the vulnerable code is not assessed.")
    cap = None
    if f.get("affected_status") != "confirmed_affected":
        cap = r["unconfirmed_applicability_cap"]
        unknowns.append("Applicability of the advisory to the installed version could not be confirmed locally.")
    if not f.get("fixed_versions"):
        unknowns.append("No fixed version is recorded in the advisory data.")
    return _assessment(f["finding_id"], "vulnerability", total, factors, rules, cap, unknowns, cvss_severity=sev)


def score_pipeline(f: dict, rules: dict | None = None) -> dict[str, Any]:
    rules = rules or DEFAULT_RULES
    r = rules["pipeline"]
    pts = r["severity_points"].get(f["severity"], 4)
    factors = [{"factor": "Rule severity", "points": pts, "detail": f"{f['rule_id']} {f['severity']}: {f['title']}"}]
    total = pts
    if f.get("evidence_strength") == "medium":
        total += r["heuristic_penalty"]
        factors.append({"factor": "Heuristic evidence", "points": r["heuristic_penalty"], "detail": "pattern-based, not directly provable from the file alone"})
    if (f.get("extra") or {}).get("third_party"):
        total += r["third_party_unpinned_action"]
        factors.append({"factor": "Third-party action", "points": r["third_party_unpinned_action"], "detail": "the action is maintained outside GitHub/known first-party orgs"})
    unknowns = ["Static analysis of the file only; whether the workflow/container is used in production is not known."]
    return _assessment(f["finding_id"], "pipeline", total, factors, rules, None, unknowns)


def score_typosquat(f: dict, rules: dict | None = None, related: dict | None = None) -> dict[str, Any]:
    rules = rules or DEFAULT_RULES
    r = rules["typosquatting"]
    related = related or {}
    factors: list[dict] = []
    s = f.get("evidence_strength", "low")
    total = r["strength_points"][s]
    factors.append({"factor": "Name-similarity evidence strength", "points": total,
                    "detail": f"{s}: '{f['package_name']}' vs '{f['similar_to']}' (similarity {f['similarity_score']}%, techniques: {', '.join(f['techniques'])})"})
    ep = r["exposure"].get(f.get("dependency_type", "unknown"), 0)
    total += ep
    factors.append({"factor": "Dependency exposure", "points": ep, "detail": f.get("dependency_type", "unknown")})
    if related.get("lockfile_addition"):
        total += r["correlated_lockfile_addition"]
        factors.append({"factor": "Recently added in lockfile history", "points": r["correlated_lockfile_addition"], "detail": related["lockfile_addition"]})
    if related.get("vulnerability"):
        total += r["correlated_vulnerability"]
        factors.append({"factor": "Also has a vulnerability finding", "points": r["correlated_vulnerability"], "detail": related["vulnerability"]})
    reg = f.get("registry") or {}
    unknowns = ["Similarity is a signal, not proof of malicious intent."]
    if not reg.get("checked"):
        unknowns.append("Registry metadata was not available to corroborate this finding.")
    if reg.get("exists") is False:
        unknowns.append("The package was not found in the public registry; it may be private/internal.")
    return _assessment(f["finding_id"], "typosquatting", total, factors, rules, r["cap"], unknowns)


def score_lockfile_change(c: dict, rules: dict | None = None, related: dict | None = None) -> dict[str, Any]:
    rules = rules or DEFAULT_RULES
    r = rules["lockfile_change"]
    related = related or {}
    cls = c.get("classification", "normal_update")
    total = r["classification_points"].get(cls, 0)
    factors = [{"factor": "Change classification", "points": total, "detail": f"{cls}: {'; '.join(c.get('signals', [])) or c['change_type']}"}]
    if cls in ("potentially_suspicious", "unexplained_change"):
        b = r["strength_bonus"].get(c.get("evidence_strength", "low"), 0)
        total += b
        factors.append({"factor": "Evidence strength", "points": b, "detail": c.get("evidence_strength", "low")})
    if related.get("vulnerability"):
        total += r["correlated_vulnerability"]
        factors.append({"factor": "Changed package has a vulnerability finding", "points": r["correlated_vulnerability"], "detail": related["vulnerability"]})
    if related.get("typosquat"):
        total += r["correlated_typosquat"]
        factors.append({"factor": "Changed package is a typosquat candidate", "points": r["correlated_typosquat"], "detail": related["typosquat"]})
    unknowns = ["A lockfile change does not prove compromise; intent cannot be determined from the diff alone."]
    if cls == "insufficient_baseline":
        unknowns.append("No valid comparison baseline was available; nothing was inferred.")
    return _assessment(c["finding_id"], "lockfile_change", total, factors, rules, r["cap"], unknowns)
