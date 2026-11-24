import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture
def item() -> dict:
    return json.loads((FIXTURES / "remediation_item.json").read_text(encoding="utf-8"))


def vuln(fid, pkg, ver, adv, sev="HIGH", eco="npm", svc="."):
    return {"finding_id": fid, "package_name": pkg, "installed_version": ver, "primary_id": adv, "severity": sev, "ecosystem": eco, "service_dir": svc}


def comp(name, ver, eco="npm", svc="."):
    return {"name": name, "version": ver, "ecosystem": eco, "service_dir": svc}


@pytest.fixture
def before() -> dict:
    return {"repo": {"scan_id": "before1", "url": "https://github.com/o/demo-app", "commit_sha": "abc"},
            "components": [comp("express", "4.17.1"), comp("qs", "6.7.0"), comp("lodash", "4.17.21")],
            "vulnerabilities": [vuln("F-1", "express", "4.17.1", "GHSA-aaaa"), vuln("F-2", "qs", "6.7.0", "GHSA-bbbb", "MEDIUM"),
                                vuln("F-3", "lodash", "4.17.21", "GHSA-cccc", "LOW")],
            "risk_assessments": [{"finding_id": "F-1", "label": "HIGH", "priority": "P1"}, {"finding_id": "F-2", "label": "MEDIUM", "priority": "P2"},
                                 {"finding_id": "F-3", "label": "LOW", "priority": "P3"}]}


def make_after(vulns, comps):
    return {"repo": {"scan_id": "after1"}, "status": "completed", "components": comps, "vulnerabilities": vulns,
            "risk_assessments": [{"finding_id": v["finding_id"], "label": v["severity"]} for v in vulns]}
