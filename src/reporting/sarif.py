"""SARIF 2.1.0 export (GitHub code scanning, VS Code, Azure DevOps ...): vulnerabilities, pipeline and package-risk findings."""
from __future__ import annotations

from typing import Any

LEVEL = {"CRITICAL": "error", "HIGH": "error", "MEDIUM": "warning", "LOW": "note", "INFO": "note", "INFORMATIONAL": "note", None: "warning"}
SECURITY_SEVERITY = {"CRITICAL": "9.5", "HIGH": "8.0", "MEDIUM": "5.5", "LOW": "3.0", "INFO": "1.0", "INFORMATIONAL": "1.0"}


def _loc(path: str, line: int = 1) -> dict:
    return {"physicalLocation": {"artifactLocation": {"uri": (path or "unknown").replace("\\", "/")}, "region": {"startLine": max(int(line or 1), 1)}}}


def to_sarif(r: dict, version: str = "2.2") -> dict[str, Any]:
    risks = {a["finding_id"]: a for a in r.get("risk_assessments", [])}
    inv = r.get("investigations") or {}
    rules: dict[str, dict] = {}
    results: list[dict] = []

    def rule(rid: str, name: str, desc: str, help_: str, sev: str | None, uri: str | None = None) -> None:
        if rid not in rules:
            rules[rid] = {"id": rid, "name": name[:120], "shortDescription": {"text": name[:200]}, "fullDescription": {"text": desc[:1000] or name}, "help": {"text": help_[:1500] or name},
                          "defaultConfiguration": {"level": LEVEL.get(sev, "warning")}, "properties": {"security-severity": SECURITY_SEVERITY.get(sev or "MEDIUM", "5.5"), "tags": ["security", "supply-chain"]},
                          **({"helpUri": uri} if uri else {})}

    for f in r.get("vulnerabilities", []):
        a = risks.get(f["finding_id"], {})
        rule(f["primary_id"], f"{f['primary_id']} in {f['package_name']}", f.get("summary") or f["primary_id"], f.get("remediation") or "", f["severity"], (f.get("advisory_urls") or [None])[0])
        i = inv.get(f["finding_id"]) or {}
        lock = f.get("lockfile") or "package manifest"
        text = f"{f['package_name']}@{f['installed_version']} is affected by {f['primary_id']}" + (f" (fixed in {', '.join(f['fixed_versions'][:2])})" if f["fixed_versions"] else " (no fixed version recorded)") + "."
        if i:
            text += f" Verdict: {i['verdict'].replace('_', ' ')} ({i['confidence']['label']} confidence). {i['rationale']}"
        results.append({"ruleId": f["primary_id"], "level": LEVEL.get(a.get("label") if a.get("label") in LEVEL else f["severity"], "warning"), "message": {"text": text[:1900]}, "locations": [_loc(lock)],
                        "partialFingerprints": {"guardianFinding": f"{f['ecosystem']}:{f['package_name']}@{f['installed_version']}:{f['primary_id']}"},
                        "properties": {"priority": a.get("priority"), "risk": a.get("label"), "cvss": f.get("cvss_score"), "epss": f.get("epss"), "kev": f["kev"], "verdict": f.get("verdict"),
                                       "dependencyType": f["dependency_type"], "sourcePackages": f["source_packages"][:3], "evidence": (i.get("evidence_ids") or [])[:6]}})
    for kind, lst in (("pipeline", (r.get("pipeline") or {}).get("findings", [])), ("package_risk", (r.get("package_risk") or {}).get("findings", []))):
        for f in lst:
            a = risks.get(f["finding_id"], {})
            rule(f["rule_id"], f["title"], f["why"], f["remediation"], f["severity"], (f.get("references") or [None])[0])
            results.append({"ruleId": f["rule_id"], "level": LEVEL.get(f["severity"], "warning"), "message": {"text": f"{f['title']}. {f['why']} Fix: {f['remediation']}"[:1900]}, "locations": [_loc(f["file"], f["line"])],
                            "partialFingerprints": {"guardianFinding": f"{f['rule_id']}:{f['file']}:{f.get('subject', '')[:60]}"},
                            "properties": {"priority": a.get("priority"), "risk": a.get("label"), "evidence": [f["evidence_id"]] if f.get("evidence_id") else [], "kind": kind}})
    repo = r.get("repo", {})
    return {"$schema": "https://json.schemastore.org/sarif-2.1.0.json", "version": "2.1.0",
            "runs": [{"tool": {"driver": {"name": "SC Guardian", "version": version, "informationUri": repo.get("url") or "", "rules": list(rules.values())}},
                      "results": results,
                      "properties": {"repository": repo.get("url"), "commit": repo.get("commit_sha"), "generatedBy": "evidence-gated agents; verdicts cite evidence ids"}}]}
