"""CycloneDX 1.6 VEX (Vulnerability Exploitability eXchange) from the Investigator's evidence-backed verdicts and analyst decisions.

Mapping is deliberately conservative: the Guardian never states ``not_affected`` from absence of an import alone (that is only "no static
evidence"); such findings stay ``in_triage`` with the detail spelled out. Only an explicit analyst decision can set ``false_positive``.
"""
from __future__ import annotations

import time
import uuid
from typing import Any, Optional

STATE = {"exploitable_likely": "exploitable", "reachable": "exploitable", "possibly_reachable": "in_triage", "test_only": "in_triage", "no_import_evidence": "in_triage", "needs_review": "in_triage"}
DETAIL = {"exploitable_likely": "The application imports the package and exploitation signals (KEV/EPSS/CVSS) are strong.", "reachable": "The application's own code imports the vulnerable package.",
          "possibly_reachable": "A direct dependency that brings the package in is imported by the application; use of the vulnerable code is unknown.",
          "test_only": "Imported only by test code in the analysed source; production use not evidenced.", "no_import_evidence": "No import found in the analysed source; may still be used through configuration, plugins or a CLI.",
          "needs_review": "Insufficient evidence to judge automatically."}


def to_vex(r: dict, decisions: Optional[dict[str, dict]] = None) -> dict[str, Any]:
    decisions = decisions or {}
    fps = (r.get("memory") or {}).get("fingerprints") or {}
    risks = {a["finding_id"]: a for a in r.get("risk_assessments", [])}
    inv = r.get("investigations") or {}
    comp_by_ref = {c["bom_ref"]: c for c in r.get("components", [])}
    vulns = []
    for f in r.get("vulnerabilities", []):
        i = inv.get(f["finding_id"]) or {}
        v = i.get("verdict") or "needs_review"
        state, detail = STATE.get(v, "in_triage"), DETAIL.get(v, "")
        d = decisions.get(fps.get(f["finding_id"]) or "")
        response = []
        analysis = {"state": state, "detail": (detail + " " + (i.get("rationale") or ""))[:1000].strip()}
        if d:
            if d["decision"] == "false_positive":
                analysis.update(state="false_positive", detail=f"Analyst decision: {d['reason']}")
            elif d["decision"] in ("accepted_risk", "suppress"):
                response = ["will_not_fix"]
                analysis["detail"] += f" Analyst decision ({d['decision']}): {d['reason']}"
        if f["fixed_versions"] and not response:
            response = ["update"]
        if response:
            analysis["response"] = response
        ref = next((c["purl"] for c in (comp_by_ref.get(x) for x in (f.get("component_refs") or [f["component_ref"]])) if c and c.get("purl")), f["component_ref"])
        a = risks.get(f["finding_id"], {})
        vulns.append({"bom-ref": f"vuln-{f['finding_id']}", "id": f["primary_id"], "source": {"name": "OSV", "url": (f.get("advisory_urls") or ["https://osv.dev"])[0]},
                      "ratings": ([{"source": {"name": f.get("severity_source") or "OSV"}, "score": f["cvss_score"], "severity": (f["severity"] or "unknown").lower(), "vector": f.get("cvss_vector")}] if f["severity"] else []),
                      "description": f.get("summary") or "", "recommendation": f.get("remediation") or "", "analysis": analysis, "affects": [{"ref": ref}],
                      "properties": [{"name": "sc-guardian:priority", "value": str(a.get("priority"))}, {"name": "sc-guardian:confidence", "value": str((i.get("confidence") or {}).get("label"))},
                                     {"name": "sc-guardian:epss", "value": str(f.get("epss"))}, {"name": "sc-guardian:kev", "value": str(f["kev"]).lower()},
                                     {"name": "sc-guardian:evidence", "value": ",".join((i.get("evidence_ids") or [])[:8])}]})
    repo = r.get("repo", {})
    return {"bomFormat": "CycloneDX", "specVersion": "1.6", "serialNumber": f"urn:uuid:{uuid.uuid4()}", "version": 1,
            "metadata": {"timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "tools": {"components": [{"type": "application", "name": "sc-guardian", "version": "2.2"}]},
                         "component": {"type": "application", "name": repo.get("name", "repository"), "version": (repo.get("commit_sha") or "")[:12]}},
            "vulnerabilities": vulns}
