"""Writes the validation outputs to ``artifacts/validation/<scan_id>/<remediation_id>/``."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from pydantic import BaseModel


def _dump(obj: Any) -> str:
    if isinstance(obj, BaseModel):
        obj = obj.model_dump(mode="json", by_alias=True)
    return json.dumps(obj, indent=2, default=str, ensure_ascii=False)


def output_dir(artifacts_dir: Path, scan_id: str, remediation_id: str) -> Path:
    d = Path(artifacts_dir) / "validation" / scan_id / remediation_id
    d.mkdir(parents=True, exist_ok=True)
    return d


def write_outputs(out_dir: Path, *, comparison: Any, validation_report: Any, final_assessment: Any, provenance: Any = None) -> dict[str, str]:
    files = {"before_after_comparison.json": comparison, "validation_report.json": validation_report, "final_assessment.json": final_assessment}
    if provenance is not None:
        files["provenance.intoto.json"] = provenance
    paths = {}
    for name, obj in files.items():
        p = out_dir / name
        p.write_text(_dump(obj), encoding="utf-8")
        paths[name] = str(p)
    return paths
