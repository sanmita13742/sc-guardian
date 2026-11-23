"""JSON exports of scan results."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def dumps(obj: Any) -> str:
    return json.dumps(obj, indent=2, default=str, ensure_ascii=False)


def vulnerability_export(result: dict) -> dict:
    return {"scan": _scan_ref(result), "source_status": result.get("source_status", {}), "coverage": result.get("vuln_coverage", {}),
            "findings": result.get("vulnerabilities", []),
            "risk_assessments": [a for a in result.get("risk_assessments", []) if a["kind"] == "vulnerability"]}


def suspicious_export(result: dict) -> dict:
    return {"scan": _scan_ref(result),
            "typosquatting": {"findings": result.get("typosquatting", []), **result.get("typosquatting_meta", {})},
            "lockfile_changes": {"findings": result.get("lockfile_changes", []), **{k: v for k, v in result.get("lockfile_analysis", {}).items() if k != "findings"}},
            "risk_assessments": [a for a in result.get("risk_assessments", []) if a["kind"] != "vulnerability"],
            "correlations": result.get("correlations", [])}


def graph_export(result: dict) -> dict:
    return {"scan": _scan_ref(result), **(result.get("graph") or {})}


def consolidated_export(result: dict) -> dict:
    return result


def _scan_ref(result: dict) -> dict:
    r = result.get("repo", {})
    return {"scan_id": r.get("scan_id"), "repository": r.get("url"), "commit_sha": r.get("commit_sha"), "branch": r.get("branch"),
            "scan_timestamp": r.get("scan_timestamp"), "tool_versions": result.get("tool_versions", {})}


def write_all(result: dict, out_dir: Path, prefix: str) -> dict[str, str]:
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    files = {
        "vulnerabilities": (f"{prefix}-vulnerabilities.json", vulnerability_export(result)),
        "suspicious": (f"{prefix}-suspicious-changes.json", suspicious_export(result)),
        "graph": (f"{prefix}-dependency-graph.json", graph_export(result)),
        "consolidated": (f"{prefix}-consolidated.json", consolidated_export(result)),
    }
    paths = {}
    for k, (name, obj) in files.items():
        p = out_dir / name
        p.write_text(dumps(obj), encoding="utf-8")
        paths[k] = str(p)
    return paths
