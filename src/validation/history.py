"""Read stored validation runs (``artifacts/validation/<scan_id>/<remediation_id>/``) for the UI and reports.

Only the latest run per proposal is kept on disk (a new run overwrites the folder), so "history" is one entry per proposal.
Missing or unreadable files never raise: the entry simply lacks that part.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Optional

FILES = {"final": "final_assessment.json", "comparison": "before_after_comparison.json", "report": "validation_report.json",
         "provenance": "provenance.intoto.json", "audit": "final_audit_report.json"}
SBOM = "after_sbom.cdx.json"
PDF = "final_audit_report.pdf"


def _read(p: Path) -> Optional[Any]:
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def run_dir(artifacts_dir: Path, scan_id: str, remediation_id: str) -> Path:
    return Path(artifacts_dir) / "validation" / scan_id / remediation_id


def load_run(artifacts_dir: Path, scan_id: str, remediation_id: str) -> Optional[dict[str, Any]]:
    d = run_dir(artifacts_dir, scan_id, remediation_id)
    if not (d / FILES["final"]).exists():
        return None
    out: dict[str, Any] = {k: _read(d / f) for k, f in FILES.items()}
    out["dir"] = str(d)
    out["files"] = {f: str(d / f) for f in [*FILES.values(), SBOM, PDF] if (d / f).exists()}
    return out


def list_runs(artifacts_dir: Path, scan_id: str) -> list[dict[str, Any]]:
    """One summary row per validated proposal of the scan, newest first."""
    base = Path(artifacts_dir) / "validation" / scan_id
    rows = []
    if not base.is_dir():
        return rows
    for d in base.iterdir():
        fa = _read(d / FILES["final"]) if d.is_dir() else None
        if not isinstance(fa, dict):
            continue
        rep = _read(d / FILES["report"]) or {}
        rows.append({"remediation_id": fa.get("remediation_id") or d.name, "verdict": fa.get("verdict"), "created_at": fa.get("created_at"),
                     "approved_by": fa.get("approved_by"), "seconds": rep.get("seconds"),
                     "sandbox": (rep.get("sandbox") or {}).get("status"), "decider": ((rep.get("agent") or {}).get("decider") or {}).get("enabled")})
    return sorted(rows, key=lambda r: r.get("created_at") or "", reverse=True)
