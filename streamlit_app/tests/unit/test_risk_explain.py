import json

import pytest

from explainability.explanation_engine import explain, explain_deterministic
from explainability.explanation_validator import validate_text
from risk_analysis.evidence_collector import collect_lockfile_evidence, collect_typosquat_evidence, collect_vulnerability_evidence
from risk_analysis.evidence_normalizer import normalize_bundle
from risk_analysis.finding_correlator import correlate_findings, summarize_by_root
from risk_analysis.risk_rules import DEFAULT_RULES, load_rules
from risk_analysis.risk_scorer import label_for, score_lockfile_change, score_typosquat, score_vulnerability
from tests.unit.test_vulnerability import (MINIMIST_GHSA, FakeHttp, osv, scenario)
from vulnerability.vulnerability_correlator import correlate

REPO = {"url": "https://github.com/x/y", "commit_sha": "abc123", "branch": "main", "scan_id": "s1", "scan_timestamp": "2026-01-01T00:00:00Z"}


def vuln(**kw):
    base = {"finding_id": "VULN-001", "severity": "HIGH", "severity_source": "OSV", "cvss_score": 7.5, "kev": False, "kev_info": None,
            "dependency_type": "transitive", "roots": ["fe"], "affected_status": "confirmed_affected", "fixed_versions": ["2.0.0"],
            "dev_dependency": None}
    base.update(kw)
    return base


def test_thresholds_and_labels():
    t = DEFAULT_RULES["thresholds"]
    assert [label_for(s, t) for s in (0, 9, 10, 24, 25, 44, 45, 69, 70, 120)] == [
        "INFORMATIONAL", "INFORMATIONAL", "LOW", "LOW", "MEDIUM", "MEDIUM", "HIGH", "HIGH", "CRITICAL", "CRITICAL"]


def test_critical_cvss_transitive_is_not_automatically_critical_risk():
    a = score_vulnerability(vuln(severity="CRITICAL", cvss_score=9.8))
    assert a["cvss_severity"] == "CRITICAL" and a["label"] == "HIGH"  # CVSS severity != project risk
    assert any(f["factor"] == "Reachability" and "NOT treated as unreachable" in f["detail"] for f in a["factors"])
    assert sum(f["points"] for f in a["factors"]) == a["score"]


def test_kev_and_direct_escalate():
    a = score_vulnerability(vuln(severity="CRITICAL", kev=True, kev_info={"cve": "CVE-1", "ransomware_use": "Known"}, dependency_type="direct"))
    assert a["label"] == "CRITICAL" and a["score"] == 55 + 30 + 5 + 8
    low_direct = score_vulnerability(vuln(severity="LOW", dependency_type="direct", cvss_score=2.0))
    assert low_direct["label"] == "LOW"  # a direct dependency is not automatically critical


def test_missing_severity_is_neutral_and_flagged_unknown():
    a = score_vulnerability(vuln(severity=None, cvss_score=None, fixed_versions=[]))
    assert a["label"] == "LOW" and any("unavailable" in f["detail"] for f in a["factors"])
    assert any("not available" in u for u in a["unknowns"]) and any("No fixed version" in u for u in a["unknowns"])
    assert a["cvss_severity"] is None


def test_unknown_applicability_capped_and_dev_discount():
    a = score_vulnerability(vuln(severity="CRITICAL", kev=True, kev_info={"cve": "x"}, affected_status="unknown"))
    assert a["label"] == "MEDIUM" and any("cap" in f["factor"] for f in a["factors"])
    d = score_vulnerability(vuln(severity="HIGH", dev_dependency=True))
    assert any(f["factor"].startswith("Development") and f["points"] < 0 for f in d["factors"])


def test_no_fix_not_automatically_critical():
    a = score_vulnerability(vuln(severity="MEDIUM", fixed_versions=[], dependency_type="transitive"))
    assert a["label"] == "MEDIUM"


def test_typosquat_and_lockfile_caps():
    t = {"finding_id": "TYPO-001", "package_name": "lodahs", "similar_to": "lodash", "similarity_score": 83.3, "techniques": ["x"],
         "evidence_strength": "high", "dependency_type": "direct", "registry": {"checked": True}}
    a = score_typosquat(t, related={"lockfile_addition": "LOCK-001", "vulnerability": "VULN-1"})
    assert a["label"] == "HIGH" and a["score"] == 65
    eager = load_rules()
    eager["thresholds"]["CRITICAL"] = 50  # even if the score would reach CRITICAL, similarity alone is capped at HIGH
    capped = score_typosquat(t, eager, {"lockfile_addition": "LOCK-001"})
    assert capped["label"] == "HIGH" and any(f["factor"] == "label cap" for f in capped["factors"])
    assert any("not proof" in u for u in a["unknowns"])
    c = {"finding_id": "LOCK-001", "classification": "potentially_suspicious", "evidence_strength": "high", "signals": ["integrity_changed_same_version"],
         "change_type": "integrity_changed"}
    b = score_lockfile_change(c, related={"vulnerability": "v", "typosquat": "t"})
    assert b["label"] == "HIGH" and "does not prove compromise" in " ".join(b["unknowns"])
    n = score_lockfile_change({**c, "classification": "unexplained_change", "evidence_strength": "low"})
    assert n["label"] == "LOW"
    ib = score_lockfile_change({**c, "classification": "insufficient_baseline"})
    assert ib["label"] == "INFORMATIONAL"


def test_rules_override(tmp_path):
    p = tmp_path / "r.json"
    p.write_text(json.dumps({"vulnerability": {"kev": 99}, "thresholds": {"HIGH": 50}}))
    r = load_rules(p)
    assert r["vulnerability"]["kev"] == 99 and r["thresholds"]["HIGH"] == 50 and r["thresholds"]["CRITICAL"] == 70
    assert DEFAULT_RULES["vulnerability"]["kev"] == 30  # defaults untouched


def _real_finding(tmp_path):
    comps, locks, g = scenario()
    http = FakeHttp({("npm", "minimist", "0.0.8"): [MINIMIST_GHSA["id"]]}, {MINIMIST_GHSA["id"]: MINIMIST_GHSA})
    client, _ = osv(http, tmp_path)
    return correlate(comps, g, locks, client, scan_timestamp="2026-01-01T00:00:00Z")["findings"][0].model_dump()


def test_template_explanation_is_grounded_for_all_kinds(tmp_path):
    f = _real_finding(tmp_path)
    risk = score_vulnerability(f)
    b = normalize_bundle(collect_vulnerability_evidence(f, REPO, "urn:sbom", {}))
    e = explain_deterministic(b, risk, f)
    s = e["sections"]
    assert "GHSA-vh95-rmgr-6w4m" in s["what"] and "0.0.8" in s["what"]
    assert "TRANSITIVE" in s["direct_transitive"] and "fe (service) -> mkdirp@0.5.1 -> minimist@0.0.8" in s["how_entered"]
    assert "0.2.1" in s["remediation"] and "not been assessed" in s["impact"]
    for name, text in s.items():
        assert validate_text(text, b, risk) == [], (name, validate_text(text, b, risk))
    t = {"finding_id": "TYPO-001", "package_name": "lodahs", "ecosystem": "npm", "similar_to": "lodash", "similarity_score": 83.3,
         "edit_distance": 1, "techniques": ["character transposition"], "reference_source": "list", "evidence": ["a", "b 12 downloads"],
         "registry": {}, "evidence_strength": "high", "caveats": [], "versions": ["1.0.0"], "component_refs": ["r"], "services": ["fe"],
         "dependency_type": "direct", "roots": ["fe (service)"]}
    rt = score_typosquat(t)
    bt = normalize_bundle(collect_typosquat_evidence(t, REPO, None))
    for name, text in explain_deterministic(bt, rt, t)["sections"].items():
        assert validate_text(text, bt, rt) == [], (name, text)
    lc = {"finding_id": "LOCK-001", "file": "package-lock.json", "package_name": "a", "ecosystem": "npm", "change_type": "integrity_changed",
          "previous": {"version": "1.0.0", "integrity": "sha512-AAA"}, "new": {"version": "1.0.0", "integrity": "sha512-BBB"},
          "classification": "potentially_suspicious", "signals": ["integrity_changed_same_version"], "reasons": ["hash changed"],
          "evidence_strength": "high", "diff_excerpt": ["-x", "+y"], "manifest_changed": False, "manifest_files_changed": [], "commit": "c" * 40,
          "baseline": "b" * 40, "baseline_mode": "parent", "commit_info": {"subject": "bump", "author": "dev", "date": "2026-01-01"}}
    rl = score_lockfile_change(lc)
    bl = normalize_bundle(collect_lockfile_evidence(lc, REPO, None))
    for name, text in explain_deterministic(bl, rl, lc)["sections"].items():
        assert validate_text(text, bl, rl) == [], (name, text)


def test_validator_rejects_invented_claims(tmp_path):
    f = _real_finding(tmp_path)
    risk = score_vulnerability(f)
    b = normalize_bundle(collect_vulnerability_evidence(f, REPO, None, {}))
    assert validate_text("This is CVE-2099-12345.", b, risk)
    assert validate_text("CVSS 9.9 applies.", b, risk)
    assert validate_text("Upgrade to 7.7.7.", b, risk)
    assert validate_text("It is actively exploited in the wild.", b, risk)
    assert validate_text("Allows remote code execution.", b, risk)
    assert validate_text("The package is malicious.", b, risk)
    assert validate_text("The overall risk is CRITICAL.", b, risk)
    assert validate_text("The code is unreachable.", b, risk)
    assert validate_text("Upgrade minimist to 0.2.1 (CVE-2020-7598).", b, risk) == []


def test_llm_output_is_validated_per_section(tmp_path):
    f = _real_finding(tmp_path)
    risk = score_vulnerability(f)
    b = normalize_bundle(collect_vulnerability_evidence(f, REPO, None, {}))
    good = {k: "ok" for k in ["what", "why", "package", "how_entered", "direct_transitive", "impact", "evidence", "remediation", "unknown"]}
    good["what"] = "minimist 0.0.8 is affected by CVE-2020-7598."
    good["impact"] = "CVSS 9.9, trivially exploitable (CVE-2099-1111)."  # invented -> must be replaced
    e = explain(b, risk, f, llm=lambda s, u: "Here you go:\n" + json.dumps(good))
    assert e["sections"]["what"] == good["what"]
    assert "9.9" not in e["sections"]["impact"] and "not been assessed" in e["sections"]["impact"]
    assert [r["section"] for r in e["validation"]["removed_sections"]] == ["impact"]
    assert e["source"] == "llm+template" and e["risk_label"] == risk["label"]  # label comes from the rule engine only


def test_llm_failure_falls_back_to_template(tmp_path):
    f = _real_finding(tmp_path)
    risk = score_vulnerability(f)
    b = normalize_bundle(collect_vulnerability_evidence(f, REPO, None, {}))

    def boom(s, u):
        raise RuntimeError("no network")
    e = explain(b, risk, f, llm=boom)
    assert e["source"] == "template" and "llm_error" in e["validation"]
    e2 = explain(b, risk, f, llm=lambda s, u: "not json at all")
    assert e2["source"] == "template"
    assert explain(b, risk, f)["source"] == "template"  # fully usable without any LLM


def test_correlation_links_findings_and_summarizes_roots(tmp_path):
    f = _real_finding(tmp_path)
    lock = {"finding_id": "LOCK-001", "kind": "lockfile_change", "classification": "potentially_suspicious", "ecosystem": "npm",
            "package_name": "minimist", "change_type": "version_changed", "signals": ["x"], "evidence_strength": "medium", "commit": "c" * 40}
    typo = {"finding_id": "TYPO-001", "ecosystem": "npm", "package_name": "minimist", "similar_to": "x", "similarity_score": 90,
            "techniques": ["t"], "evidence_strength": "medium", "dependency_type": "transitive", "registry": {}}
    out = correlate_findings([f], [typo], [lock])
    assert out["correlations"] and set(out["correlations"][0]["kinds"]) == {"vulnerability", "typosquatting", "lockfile_change"}
    by = {a["finding_id"]: a for a in out["assessments"]}
    assert any("Correlated lockfile change" == x["factor"] for x in by["VULN-001"]["factors"])
    roots = summarize_by_root([f], out["assessments"])
    assert roots[0]["root"] == "fe (service)" and roots[0]["transitive"] == 1 and roots[0]["findings"] == 1
