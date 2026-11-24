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


def priority_for(label: str, f: dict, reach_status: str = "unknown", reach_density: str = "unknown") -> str:
    """P0 act now / P1 this sprint / P2 plan / P3 monitor.
    Escalation:
    - P0: CRITICAL risk OR (KEV + app import) OR (HIGH risk with heavy codebase influence in production).
    - P1: HIGH risk OR (MEDIUM risk with heavy codebase influence in production).
    - P2: MEDIUM risk OR (deprioritized unimported/test-only findings that were capped from higher CVSS).
    - P3: LOW or INFORMATIONAL.
    """
    reach = f.get("reachability") or {}
    density = reach_density if reach_density != "unknown" else (reach.get("import_density") or reach.get("influence_tier") or "unknown")
    is_dev = bool(f.get("dev_dependency"))
    is_heavy = density == "heavy" and not is_dev
    has_kev = bool(f.get("kev"))

    # Deprioritize unimported or test-only findings with no active KEV exploitation to P2/P3
    if reach_status in ("not_imported", "used_in_tests_only") and not has_kev:
        if label in ("CRITICAL", "HIGH", "MEDIUM"):
            return "P2"
        return "P3"

    if label == "CRITICAL" or (has_kev and reach_status in ("used_by_app", "reachable_via_dependency")) or (label == "HIGH" and is_heavy):
        return "P0"
    if label == "HIGH" or (label == "MEDIUM" and is_heavy):
        return "P1"
    if label == "MEDIUM":
        return "P2"
    return "P3"


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
    ep = f.get("epss")
    if ep is not None:
        pts = next((p for thr, p in r["epss"] if ep >= thr), 0)
        total += pts
        factors.append({"factor": "Exploitation probability (EPSS)", "points": pts, "detail": f"EPSS {ep:.1%} (percentile {((f.get('epss_percentile') or 0) * 100):.0f}) - a statistical estimate, not a fact"})
    else:
        factors.append({"factor": "Exploitation probability (EPSS)", "points": 0, "detail": "not available"})
    reach = (f.get("reachability") or {})
    rst = reach.get("status") or "unknown"
    density = reach.get("import_density") or reach.get("influence_tier") or "unknown"
    app_files = reach.get("app_files", 0)
    test_files = reach.get("test_files", 0)

    if rst == "unknown":
        rp = r["reachability"].get("unknown", 0)
        total += rp
        factors.append({"factor": "Reachability", "points": rp, "detail": "not assessed (unknown; NOT treated as unreachable)"})
        unknowns.append("Reachability of the vulnerable code is not assessed.")
    elif rst == "used_by_app":
        loc = (reach.get("locations") or [{}])[0]
        loc_str = f" ({loc.get('path')}:{loc.get('line')})" if loc.get("path") else ""
        if app_files >= 5 or density == "heavy":
            rp = r["reachability"].get("used_by_app_heavy", 35)
            detail = f"heavy application usage: imported across {app_files} files{loc_str} (high codebase blast radius)"
            factor_name = "Reachability (heavy app usage)"
        elif app_files >= 2 or density == "moderate":
            rp = r["reachability"].get("used_by_app_moderate", 20)
            detail = f"application imports {reach.get('package')} in {app_files} files{loc_str}"
            factor_name = "Reachability (static import evidence)"
        else:
            rp = r["reachability"].get("used_by_app_single", 12)
            detail = f"application imports {reach.get('package')} in 1 file{loc_str}"
            factor_name = "Reachability (single app import)"
        total += rp
        factors.append({"factor": factor_name, "points": rp, "detail": detail})
        unknowns.append("Reachability is package-level import evidence, not a call graph: it does not prove the vulnerable function is called.")
    elif rst == "reachable_via_dependency":
        via_str = ", ".join(reach.get("via") or [reach.get("package")])
        if app_files >= 5 or density == "heavy":
            rp = r["reachability"].get("reachable_via_dependency_heavy", 18)
            detail = f"transitive dependency pulled in by heavily imported package ({via_str} in {app_files} files)"
            factor_name = "Reachability (transitive via heavy root)"
        else:
            rp = r["reachability"].get("reachable_via_dependency", 8)
            detail = f"the application imports {via_str}, which brings this package in (exact use of the vulnerable code unknown)"
            factor_name = "Reachability (transitive via app import)"
        total += rp
        factors.append({"factor": factor_name, "points": rp, "detail": detail})
        unknowns.append("Reachability is package-level import evidence, not a call graph: it does not prove the vulnerable function is called.")
    elif rst == "used_in_tests_only":
        rp = r["reachability"].get("used_in_tests_only", -10)
        total += rp
        factors.append({"factor": "Reachability (tests only)", "points": rp,
                        "detail": f"imported only by test code ({test_files} files); excluded from production execution path"})
        unknowns.append("Reachability is package-level import evidence: test imports indicate build/test surface rather than runtime exposure.")
    elif rst == "not_imported":
        rp = r["reachability"].get("not_imported", -25)
        total += rp
        factors.append({"factor": "Reachability (not imported)", "points": rp,
                        "detail": "no import found in analysed source; deprioritized (it may still be used via configuration, plugins or a CLI)"})
        unknowns.append("No static import was found in the application source; runtime exposure is reduced compared to raw CVSS severity.")
    else:
        rp = r["reachability"].get(rst, 0)
        total += rp
        factors.append({"factor": "Reachability", "points": rp, "detail": str(rst)})

    cap = None
    if f.get("affected_status") != "confirmed_affected":
        cap = r.get("unconfirmed_applicability_cap", "MEDIUM")
        unknowns.append("Applicability of the advisory to the installed version could not be confirmed locally.")
    if rst == "not_imported" and not f.get("kev"):
        unreach_cap = r.get("unreachable_cap", "MEDIUM")
        if cap is None or RISK_ORDER.index(unreach_cap) > RISK_ORDER.index(cap):
            cap = unreach_cap
    elif rst == "used_in_tests_only" and not f.get("kev"):
        test_cap = r.get("test_only_cap", "MEDIUM")
        if cap is None or RISK_ORDER.index(test_cap) > RISK_ORDER.index(cap):
            cap = test_cap

    if not f.get("fixed_versions"):
        unknowns.append("No fixed version is recorded in the advisory data.")
    a = _assessment(f["finding_id"], "vulnerability", total, factors, rules, cap, unknowns, cvss_severity=sev)
    vc = f.get("verdict_confidence")
    a["confidence"] = vc or {"score": 30 + (20 if f.get("cross_verified") else 0) + (10 if sev else 0), "label": "Medium" if f.get("cross_verified") else "Low", "basis": ["investigation not run"]}
    a["priority"] = priority_for(a["label"], f, rst, density)
    a["verdict"] = f.get("verdict")
    a["influence_tier"] = density
    a["app_files"] = app_files
    return a


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
    a = _assessment(f["finding_id"], f.get("kind", "pipeline"), total, factors, rules, None, unknowns)
    a["confidence"] = {"score": 85 if f.get("evidence_strength") == "high" else 55, "label": "High" if f.get("evidence_strength") == "high" else "Medium", "basis": ["rule matched directly in the file" if f.get("evidence_strength") == "high" else "pattern-based rule"]}
    a["priority"] = {"CRITICAL": "P0", "HIGH": "P1", "MEDIUM": "P2"}.get(a["label"], "P3")
    return a


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
    a = _assessment(f["finding_id"], "typosquatting", total, factors, rules, r["cap"], unknowns)
    a["confidence"] = {"score": 60 if reg.get("checked") else 35, "label": "Medium" if reg.get("checked") else "Low", "basis": ["name similarity", "registry corroboration" if reg.get("checked") else "no registry corroboration"]}
    a["priority"] = {"CRITICAL": "P0", "HIGH": "P1", "MEDIUM": "P2"}.get(a["label"], "P3")
    return a


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
    a = _assessment(c["finding_id"], "lockfile_change", total, factors, rules, r["cap"], unknowns)
    a["confidence"] = {"score": 40, "label": "Medium" if c.get("evidence_strength") == "high" else "Low", "basis": ["Git diff evidence"]}
    a["priority"] = {"CRITICAL": "P0", "HIGH": "P1", "MEDIUM": "P2"}.get(a["label"], "P3")
    return a
