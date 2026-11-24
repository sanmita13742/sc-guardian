"""Writes the validation outputs to ``artifacts/validation/<scan_id>/<remediation_id>/``."""
from __future__ import annotations

import json
import textwrap
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


def final_audit_report(*, remediation: dict, approval: dict, final_assessment: dict, comparison: dict,
                       validation_report: dict, provenance: dict) -> dict[str, Any]:
    """Concise, evidence-linked view for an analyst; detailed source files remain authoritative."""
    from validation.fix_validator import approval_mode
    sb = validation_report.get("sandbox") or {}
    tests = sb.get("test_evidence") or {}
    rescan = validation_report.get("rescan") or {}
    materials = (((provenance.get("predicate") or {}).get("buildDefinition") or {}).get("resolvedDependencies") or [])
    verdict = final_assessment.get("verdict")
    action = "ready_for_review" if verdict == "verified_fixed" else "hold_and_review"
    return {
        "schema_version": 1,
        "remediation": {"id": remediation.get("id"), "priority": remediation.get("priority"),
                        "source_package": remediation.get("source_package"), "changes": remediation.get("changes") or []},
        "approval": {"mode": approval_mode(approval, remediation.get("priority")) or "unqualified",
                     "actor": approval.get("actor"), "reason": approval.get("reason")},
        "conclusion": {"verdict": verdict, "analyst_action": action, "reasons": final_assessment.get("reasons") or [],
                       "checks": final_assessment.get("checks") or {}, "limitations": final_assessment.get("limitations") or []},
        "execution": {"sandbox_status": sb.get("status"), "test_evidence": tests, "baseline": sb.get("baseline"),
                      "rescan_ok": rescan.get("ok"), "rescan_status": rescan.get("status"),
                      "runs": [{k: r.get(k) for k in ("phase", "exit_code", "seconds")} for r in sb.get("runs") or []]},
        "security_delta": {"targeted_fixed": len(comparison.get("targeted_fixed") or []),
                           "targeted_remaining": len(comparison.get("targeted_remaining") or []),
                           "newly_introduced": len(comparison.get("newly_introduced") or []),
                           "other_resolved": len(comparison.get("other_resolved") or []),
                           "target_versions_present": comparison.get("target_versions_present"),
                           "component_changes": comparison.get("components_changed") or [],
                           "risk_before": comparison.get("risk_before") or {}, "risk_after": comparison.get("risk_after") or {}},
        "evidence": {"artifact_digests": provenance.get("subject") or [], "materials": materials,
                     "signature": validation_report.get("signature") or {},
                     "detailed_files": ["before_after_comparison.json", "validation_report.json", "final_assessment.json", "provenance.intoto.json"]},
        "created_at": final_assessment.get("created_at"),
    }


def _pdf_lines(audit: dict[str, Any]) -> list[str]:
    """Turn the consolidated audit evidence into a compact analyst-facing narrative."""
    rem = audit.get("remediation") or {}
    approval = audit.get("approval") or {}
    conclusion = audit.get("conclusion") or {}
    execution = audit.get("execution") or {}
    tests = execution.get("test_evidence") or {}
    delta = audit.get("security_delta") or {}
    evidence = audit.get("evidence") or {}
    lines = [
        "SC Guardian - Fix Validation Audit Report",
        f"Created: {audit.get('created_at') or 'not recorded'}",
        "",
        "ASSESSMENT",
        f"Remediation: {rem.get('id') or 'unknown'} | Priority: {rem.get('priority') or 'unknown'}",
        f"Package: {rem.get('source_package') or 'not recorded'}",
        f"Verdict: {(conclusion.get('verdict') or 'unknown').replace('_', ' ').upper()}",
        f"Analyst action: {(conclusion.get('analyst_action') or 'unknown').replace('_', ' ')}",
        f"Approval: {(approval.get('mode') or 'unknown').replace('_', ' ')} by {approval.get('actor') or 'not recorded'}",
        "",
        "VALIDATION RESULTS",
        f"Sandbox: {execution.get('sandbox_status') or 'unknown'} | Rescan: {'passed' if execution.get('rescan_ok') else 'failed'}",
        f"Tests: {tests.get('passed', 0)} passed, {tests.get('failed', 0)} failed, {tests.get('executed', 0)} executed",
        f"Security delta: {delta.get('targeted_fixed', 0)} fixed, {delta.get('targeted_remaining', 0)} remaining, "
        f"{delta.get('newly_introduced', 0)} newly introduced",
        f"Required target versions present: {delta.get('target_versions_present')}",
        "",
        "DEPENDENCY CHANGES",
    ]
    for change in delta.get("component_changes") or []:
        component = str(change.get("key") or "unknown").split("|")[-1]
        lines.append(f"- {component}: {', '.join(change.get('before') or []) or 'none'} -> {', '.join(change.get('after') or []) or 'none'}")
    if not (delta.get("component_changes") or []):
        lines.append("- No dependency version change was recorded.")
    lines.extend(["", "DECISION EVIDENCE"])
    for reason in conclusion.get("reasons") or []:
        lines.append(f"- {reason}")
    if not (conclusion.get("reasons") or []):
        lines.append("- No decision reasons were recorded.")
    lines.extend(["", "ARTIFACT DIGESTS"])
    for subject in evidence.get("artifact_digests") or []:
        lines.append(f"- {subject.get('name') or 'artifact'}: {(subject.get('digest') or {}).get('sha256') or 'digest unavailable'}")
    if not (evidence.get("artifact_digests") or []):
        lines.append("- No artifact digest was produced.")
    return lines


def audit_pdf_bytes(audit: dict[str, Any]) -> bytes:
    """Create a dependency-free, valid multi-page PDF from a consolidated audit report."""
    wrapped: list[str] = []
    for line in _pdf_lines(audit):
        wrapped.extend(textwrap.wrap(str(line), width=92, subsequent_indent="  ") or [""])
    pages = [wrapped[i:i + 50] for i in range(0, len(wrapped), 50)] or [["No report data available."]]

    objects: list[bytes] = []
    page_ids = [4 + i * 2 for i in range(len(pages))]
    objects.append(b"<< /Type /Catalog /Pages 2 0 R >>")
    kids = " ".join(f"{page_id} 0 R" for page_id in page_ids)
    objects.append(f"<< /Type /Pages /Kids [{kids}] /Count {len(pages)} >>".encode("ascii"))
    objects.append(b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>")
    for index, lines in enumerate(pages):
        page_id = page_ids[index]
        content_id = page_id + 1
        objects.append((f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] "
                        f"/Resources << /Font << /F1 3 0 R >> >> /Contents {content_id} 0 R >>").encode("ascii"))
        commands = ["BT", "/F1 10 Tf", "50 752 Td", "14 TL"]
        for line in lines:
            safe = str(line).encode("cp1252", errors="replace").decode("cp1252").replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")
            commands.extend([f"({safe}) Tj", "T*"])
        commands.append("ET")
        stream = "\n".join(commands).encode("cp1252")
        objects.append(f"<< /Length {len(stream)} >>\nstream\n".encode("ascii") + stream + b"\nendstream")

    pdf = bytearray(b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n")
    offsets = [0]
    for object_id, obj in enumerate(objects, start=1):
        offsets.append(len(pdf))
        pdf.extend(f"{object_id} 0 obj\n".encode("ascii") + obj + b"\nendobj\n")
    xref = len(pdf)
    pdf.extend(f"xref\n0 {len(objects) + 1}\n".encode("ascii"))
    pdf.extend(b"0000000000 65535 f \n")
    for offset in offsets[1:]:
        pdf.extend(f"{offset:010d} 00000 n \n".encode("ascii"))
    pdf.extend(f"trailer\n<< /Size {len(objects) + 1} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n".encode("ascii"))
    return bytes(pdf)


def write_outputs(out_dir: Path, *, comparison: Any, validation_report: Any, final_assessment: Any, provenance: Any = None,
                  final_audit: Any = None) -> dict[str, str]:
    files = {"before_after_comparison.json": comparison, "validation_report.json": validation_report, "final_assessment.json": final_assessment}
    if provenance is not None:
        files["provenance.intoto.json"] = provenance
    if final_audit is not None:
        files["final_audit_report.json"] = final_audit
    paths = {}
    for name, obj in files.items():
        p = out_dir / name
        p.write_text(_dump(obj), encoding="utf-8")
        paths[name] = str(p)
    if final_audit is not None:
        p = out_dir / "final_audit_report.pdf"
        p.write_bytes(audit_pdf_bytes(final_audit))
        paths[p.name] = str(p)
    return paths
