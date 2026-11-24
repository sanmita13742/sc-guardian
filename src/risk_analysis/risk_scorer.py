"""Contextual Risk Scoring Engine.

Implements the four-factor linear contextual vulnerability risk model (v2.0):
    R = 0.15*C + 0.20*A + 0.35*P + 0.30*I
With function-level application impact:
    I = 0.25*F + 0.25*S + 0.20*B + 0.20*D + 0.10*X

Maintains deterministic, evidence-grounded rule scoring for pipeline, typosquatting, and lockfile findings.
"""
from __future__ import annotations

from typing import Any, Optional

from config.constants import RISK_ORDER
from reachability.app_reachability import evaluate_app_reachability, extract_vulnerable_symbols
from risk_analysis.contextual_scorer import ContextualScorer, DimensionScore
from risk_analysis.function_impact import FunctionImpactAnalyzer
from risk_analysis.production_context import ProductionContextAnalyzer
from risk_analysis.risk_rules import DEFAULT_RULES, RULES_VERSION


def label_for(score: int | float, thresholds: dict) -> str:
    for lab in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        if score >= thresholds[lab]:
            return lab
    return "INFORMATIONAL"


def _cap(label: str, cap: str) -> tuple[str, bool]:
    if RISK_ORDER.index(label) < RISK_ORDER.index(cap):
        return cap, True
    return label, False


def _assessment(
    fid: str,
    kind: str,
    score: int,
    factors: list[dict],
    rules: dict,
    cap: Optional[str],
    unknowns: list[str],
    cvss_severity: Optional[str] = None,
) -> dict[str, Any]:
    score = max(score, 0)
    label = label_for(score, rules["thresholds"])
    capped = False
    if cap:
        label, capped = _cap(label, cap)
        if capped:
            factors.append({
                "factor": "label cap",
                "points": 0,
                "detail": f"label limited to {cap} for this finding type/state",
            })
    return {
        "finding_id": fid,
        "kind": kind,
        "score": score,
        "label": label,
        "factors": factors,
        "unknowns": unknowns,
        "cvss_severity": cvss_severity,
        "rules_version": RULES_VERSION,
        "thresholds": rules["thresholds"],
    }


def priority_for(
    label: str,
    f: dict,
    reach_status: str = "unknown",
    reach_density: str = "unknown",
) -> str:
    """Operational priority rating (P0 act now / P1 this sprint / P2 plan / P3 monitor)."""
    reach = f.get("reachability") or {}
    density = (
        reach_density
        if reach_density != "unknown"
        else (reach.get("import_density") or reach.get("influence_tier") or "unknown")
    )
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


def score_vulnerability(
    f: dict,
    rules: dict | None = None,
    related: dict | None = None,
) -> dict[str, Any]:
    """Score a vulnerability finding using the Contextual Vulnerability Risk Scoring v2.0 model."""
    rules = rules or DEFAULT_RULES
    related = related or {}
    source_index = related.get("source_index") or f.get("source_index")
    repo_dir = related.get("repo_dir") or f.get("repo_dir")

    # Initialize sub-analyzers
    c_weights = (rules.get("contextual_v2") or {}).get("weights", ContextualScorer.DEFAULT_WEIGHTS)
    c_thresholds = (rules.get("contextual_v2") or {}).get("thresholds", rules.get("thresholds", ContextualScorer.DEFAULT_THRESHOLDS))
    scorer = ContextualScorer(weights=c_weights, thresholds=c_thresholds)
    prod_analyzer = ProductionContextAnalyzer(repo_dir=repo_dir)
    impact_analyzer = FunctionImpactAnalyzer()

    # -------------------------------------------------------------
    # 1. Dimension C: CVSS Severity (Weight: 15%)
    # -------------------------------------------------------------
    raw_cvss = f.get("cvss_score")
    sev = f.get("severity")
    if raw_cvss is not None:
        score_C = max(0.0, min(100.0, float(raw_cvss) * 10.0))
        status_C = "numeric_cvss"
        ev_C = [f"Raw CVSS {raw_cvss:.1f} ({sev or 'unspecified'}) from {f.get('severity_source') or 'advisory'}"]
        conf_C = "high"
    else:
        # Qualitative fallback if numeric CVSS is unavailable
        sev_map = {"CRITICAL": 90.0, "HIGH": 75.0, "MEDIUM": 50.0, "LOW": 25.0}
        score_C = sev_map.get(sev, 40.0)
        status_C = "estimated_from_severity" if sev else "severity_unavailable"
        ev_C = [f"Numeric CVSS unavailable; estimated from severity '{sev or 'UNAVAILABLE'}'"]
        conf_C = "medium" if sev else "low"

    dim_c = DimensionScore(
        dimension="C",
        name="CVSS Severity",
        weight=scorer.weights["C"],
        raw_value=raw_cvss if raw_cvss is not None else sev,
        normalized_score=score_C,
        status=status_C,
        weighted_contribution=round(scorer.weights["C"] * score_C, 2),
        evidence=ev_C,
        confidence=conf_C,
    )

    # -------------------------------------------------------------
    # 2. Dimension A: Application Code Reachability (Weight: 20%)
    # -------------------------------------------------------------
    reach = f.get("reachability") or {}
    vuln_symbols = extract_vulnerable_symbols(summary=f.get("summary"), details=f.get("summary"))

    if source_index:
        dim_a = evaluate_app_reachability(
            package_name=f["package_name"],
            ecosystem=f["ecosystem"],
            source_index=source_index,
            vulnerable_symbols=vuln_symbols,
            dependency_type=f.get("dependency_type", "direct"),
            roots=f.get("roots", []),
            is_dev=bool(f.get("dev_dependency")),
        )
    else:
        # Derive Dimension A from pre-calculated reachability dictionary
        rst = reach.get("status", "unknown")
        app_files = reach.get("app_files", 0)
        density = reach.get("import_density") or reach.get("influence_tier") or "unknown"
        locs = reach.get("locations") or []
        loc_str = f" ({locs[0]['path']}:{locs[0]['line']})" if locs and locs[0].get("path") else ""

        if rst == "confirmed_reachable":
            norm_a = 100.0
            stat_a = "confirmed_reachable"
            ev_a = ["Vulnerable symbol confirmed reachable in application source code"]
        elif rst == "used_by_app":
            norm_a = 80.0 if (app_files >= 5 or density == "heavy") else 60.0
            stat_a = "potentially_reachable"
            ev_a = [f"Imported in {app_files} application file(s){loc_str}"]
        elif rst == "reachable_via_dependency":
            norm_a = 40.0
            stat_a = "transitive_reachable"
            ev_a = [f"Transitive dependency pulled in by application import(s): {', '.join(reach.get('via') or [])}"]
        elif rst == "used_in_tests_only":
            norm_a = 0.0
            stat_a = "test_only"
            ev_a = [f"Imported only in test files ({reach.get('test_files', 0)} files); excluded from app code"]
        elif rst == "not_imported":
            norm_a = 0.0
            stat_a = "unreachable"
            ev_a = ["No static imports found in analysed application source code"]
        else:
            norm_a = None
            stat_a = "unknown"
            ev_a = ["Reachability has not been assessed; unknown evidence state"]

        dim_a = DimensionScore(
            dimension="A",
            name="Application Code Reachability",
            weight=scorer.weights["A"],
            raw_value=reach,
            normalized_score=norm_a,
            status=stat_a,
            weighted_contribution=round(scorer.weights["A"] * norm_a, 2) if norm_a is not None else 0.0,
            evidence=ev_a,
            confidence=reach.get("confidence", "medium"),
        )

    # -------------------------------------------------------------
    # 3. Dimension P: Production Code Reachability (Weight: 35%)
    # -------------------------------------------------------------
    dim_p = prod_analyzer.evaluate_production_reachability(
        package_name=f["package_name"],
        ecosystem=f["ecosystem"],
        source_index=source_index,
        is_dev=bool(f.get("dev_dependency")),
        asset_type=f.get("asset_type", "source_dependency"),
        dependency_type=f.get("dependency_type", "direct"),
        container_details=f.get("container_details"),
    )

    # -------------------------------------------------------------
    # 4. Dimension I: Function-Level Application Impact (Weight: 30%)
    # -------------------------------------------------------------
    loc_paths = [loc["path"] for loc in (reach.get("locations") or []) if loc.get("path")]
    dim_i, impact_breakdown = impact_analyzer.evaluate_function_impact(
        package_name=f["package_name"],
        vulnerable_symbols=vuln_symbols,
        advisory_summary=f.get("summary"),
        advisory_details=f.get("summary"),
        app_file_locations=loc_paths,
        dim_p_score=dim_p.normalized_score,
        is_dev=bool(f.get("dev_dependency")),
    )

    # -------------------------------------------------------------
    # 5. Execute 4-Factor Contextual Risk Calculation
    # -------------------------------------------------------------
    result = scorer.score(
        finding_id=f.get("finding_id", "VULN-000"),
        dim_c=dim_c,
        dim_a=dim_a,
        dim_p=dim_p,
        dim_i=dim_i,
        impact_breakdown=impact_breakdown,
        kev=bool(f.get("kev")),
        epss=f.get("epss"),
    )

    unknowns = list(result.missing_evidence_reasons)
    if not f.get("fixed_versions"):
        unknowns.append("No fixed version is recorded in the advisory data.")
    if f.get("affected_status") != "confirmed_affected":
        unknowns.append("Applicability of the advisory to the installed version could not be confirmed locally.")

    density = reach.get("import_density") or reach.get("influence_tier") or "unknown"
    app_files = reach.get("app_files", 0)

    # Confidence calculation
    vc = f.get("verdict_confidence")
    confidence = vc or {
        "score": 30 + (20 if f.get("cross_verified") else 0) + (10 if sev else 0) + (15 if not result.is_provisional else 0),
        "label": "High" if (f.get("cross_verified") and not result.is_provisional) else "Medium" if f.get("cross_verified") else "Low",
        "basis": ["4-factor contextual assessment complete" if not result.is_provisional else "provisional assessment (missing evidence)"],
    }

    return {
        "finding_id": result.finding_id,
        "kind": "vulnerability",
        "score": result.rounded_score,
        "exact_score": result.score,
        "label": result.label,
        "priority": result.priority,
        "is_provisional": result.is_provisional,
        "formula": result.formula,
        "weights": result.weights,
        "dimensions": {k: v.to_dict() for k, v in result.dimensions.items()},
        "impact_breakdown": result.impact_breakdown.to_dict() if result.impact_breakdown else None,
        "factors": result.factors,
        "missing_dimensions": result.missing_dimensions,
        "missing_evidence_reasons": result.missing_evidence_reasons,
        "threat_intel_escalations": result.threat_intel_escalations,
        "unknowns": unknowns,
        "cvss_severity": sev,
        "cvss_score": raw_cvss,
        "rules_version": RULES_VERSION,
        "thresholds": rules["thresholds"],
        "confidence": confidence,
        "verdict": f.get("verdict"),
        "influence_tier": density,
        "app_files": app_files,
        "asset_type": f.get("asset_type", "source_dependency"),
        "container_details": f.get("container_details"),
    }


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
    a["confidence"] = {
        "score": 85 if f.get("evidence_strength") == "high" else 55,
        "label": "High" if f.get("evidence_strength") == "high" else "Medium",
        "basis": ["rule matched directly in the file" if f.get("evidence_strength") == "high" else "pattern-based rule"],
    }
    a["priority"] = {"CRITICAL": "P0", "HIGH": "P1", "MEDIUM": "P2"}.get(a["label"], "P3")
    return a


def score_typosquat(f: dict, rules: dict | None = None, related: dict | None = None) -> dict[str, Any]:
    rules = rules or DEFAULT_RULES
    r = rules["typosquatting"]
    related = related or {}
    factors: list[dict] = []
    s = f.get("evidence_strength", "low")
    total = r["strength_points"][s]
    factors.append({
        "factor": "Name-similarity evidence strength",
        "points": total,
        "detail": f"{s}: '{f['package_name']}' vs '{f['similar_to']}' (similarity {f['similarity_score']}%, techniques: {', '.join(f['techniques'])})",
    })
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
    a["confidence"] = {
        "score": 60 if reg.get("checked") else 35,
        "label": "Medium" if reg.get("checked") else "Low",
        "basis": ["name similarity", "registry corroboration" if reg.get("checked") else "no registry corroboration"],
    }
    a["priority"] = {"CRITICAL": "P0", "HIGH": "P1", "MEDIUM": "P2"}.get(a["label"], "P3")
    return a


def score_lockfile_change(c: dict, rules: dict | None = None, related: dict | None = None) -> dict[str, Any]:
    rules = rules or DEFAULT_RULES
    r = rules["lockfile_change"]
    related = related or {}
    factors: list[dict] = []
    total = r["classification_points"].get(c["classification"], 0)
    factors.append({
        "factor": "Classification",
        "points": total,
        "detail": f"{c['classification']}: {c['change_type']} in {c['file']}",
    })
    bonus = r["strength_bonus"].get(c["evidence_strength"], 0)
    total += bonus
    factors.append({
        "factor": "Evidence strength",
        "points": bonus,
        "detail": f"{c['evidence_strength']} ({len(c['signals'])} signal(s): {', '.join(c['signals'])})",
    })
    if related.get("vulnerability"):
        total += r["correlated_vulnerability"]
        factors.append({"factor": "Correlated vulnerability", "points": r["correlated_vulnerability"], "detail": related["vulnerability"]})
    if related.get("typosquat"):
        total += r["correlated_typosquat"]
        factors.append({"factor": "Correlated typosquat candidate", "points": r["correlated_typosquat"], "detail": related["typosquat"]})
    unknowns = ["Lockfile diffs are static changes; they do not prove malicious intent or that the change was unauthorized."]
    a = _assessment(c["finding_id"], "lockfile_change", total, factors, rules, r["cap"], unknowns)
    a["confidence"] = {
        "score": 80 if c["evidence_strength"] == "high" else 50,
        "label": "High" if c["evidence_strength"] == "high" else "Medium",
        "basis": [f"{c['evidence_strength']} evidence ({len(c['signals'])} signals)"],
    }
    a["priority"] = {"CRITICAL": "P0", "HIGH": "P1", "MEDIUM": "P2"}.get(a["label"], "P3")
    return a
