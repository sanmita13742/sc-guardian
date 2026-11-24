"""Collects everything about the remediations that were actually fixed, for the Fix Report page and its PDF.

For a project scanned from a local folder a fix counts as *fixed* when it was accepted and written to the files (the applied record);
for a GitHub scan when its change was committed to a remediation branch. Per fix we gather the findings it resolves with their CVSS and
contextual risk scores, the files that changed (real before/after diff from the stored backup), and the validation record.
"""
from __future__ import annotations

import difflib
import json
from pathlib import Path
from typing import Any, Optional

SEV_ORDER = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN")


def _read(p: str | Path) -> Optional[str]:
    try:
        return Path(p).read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return None


def _diff_files(root: Path, rec: dict, rem: dict) -> list[dict]:
    """Per changed file: path, kind, +/- counts and the changed lines (real diff of backup vs current file)."""
    manifest = (rem.get("patch") or {}).get("path")
    out: list[dict] = []
    for rel, backup in (rec.get("backups") or {}).items():
        old, new = _read(backup), _read(root / rel)
        if old is None or new is None:
            out.append({"path": rel, "kind": _kind(rel, manifest), "added": 0, "removed": 0, "lines": []})
            continue
        lines = [ln for ln in difflib.unified_diff(old.splitlines(), new.splitlines(), lineterm="", n=0) if not ln.startswith(("---", "+++", "@@"))]
        out.append({"path": rel, "kind": _kind(rel, manifest), "added": sum(1 for ln in lines if ln.startswith("+")),
                    "removed": sum(1 for ln in lines if ln.startswith("-")), "lines": lines[:40]})
    out.sort(key=lambda f: (f["path"] != manifest, f["path"]))
    return out


def _diff_from_patch(rem: dict) -> list[dict]:
    p = rem.get("patch") or {}
    lines = [ln for ln in (p.get("diff") or "").splitlines() if ln[:1] in "+-" and not ln.startswith(("---", "+++"))]
    return [{"path": p["path"], "kind": _kind(p["path"], p["path"]), "added": sum(1 for ln in lines if ln.startswith("+")),
             "removed": sum(1 for ln in lines if ln.startswith("-")), "lines": lines[:40]}] if p.get("path") else []


def _kind(rel: str, manifest: Optional[str]) -> str:
    base = rel.rsplit("/", 1)[-1].lower()
    if base.endswith(("lock.json", ".lock", "lock.yaml", "go.sum", "shrinkwrap.json")) or base in ("yarn.lock", "poetry.lock", "uv.lock", "cargo.lock", "composer.lock"):
        return "lockfile"
    if base.startswith("dockerfile") or base.endswith(".dockerfile"):
        return "Dockerfile"
    return "manifest" if rel == manifest else "config"


def _finding_rows(rem: dict, fixed: list[dict], vulns: list[dict], risks: dict[str, dict]) -> list[dict]:
    by_key = {(v.get("package_name"), v.get("installed_version"), v.get("primary_id")): v for v in vulns}
    by_id = {v["finding_id"]: v for v in vulns}
    found: list[dict] = []
    for f in fixed:
        v = by_key.get((f.get("package"), f.get("version"), f.get("id")))
        if v:
            found.append(v)
    if not found:  # applied before fixed findings were recorded, or no clone comparison: fall back to the proposal's own group
        found = [by_id[i] for i in rem.get("finding_ids", []) if i in by_id]
    rows = []
    for v in found:
        a = risks.get(v["finding_id"], {})
        rows.append({"id": v.get("primary_id"), "package": v.get("package_name"), "version": v.get("installed_version"),
                     "severity": (v.get("severity") or "UNKNOWN").upper(), "cvss": v.get("cvss_score"),
                     "risk": a.get("label"), "score": a.get("score"), "priority": a.get("priority"),
                     "fixed_in": ", ".join(v.get("fixed_versions") or []) or v.get("recommended_fix") or "-",
                     "summary": (v.get("summary") or "")[:140]})
    rows.sort(key=lambda r: (SEV_ORDER.index(r["severity"]) if r["severity"] in SEV_ORDER else 9, -(r["score"] or 0)))
    return rows


def collect_fixes(result: dict, trial_loader=None, delivered: Optional[dict[str, dict]] = None) -> list[dict]:
    """All fixed remediations of a scan result, newest first. ``delivered`` maps proposal id -> delivery result for GitHub scans."""
    from remediation.apply_local import applied_record
    repo = result.get("repo") or {}
    items = (result.get("remediation") or {}).get("items") or []
    vulns = result.get("vulnerabilities") or []
    risks = {a["finding_id"]: a for a in result.get("risk_assessments") or []}
    is_local = repo.get("source") == "local"
    root = Path(repo.get("local_path") or repo.get("repo_dir") or ".")
    base = {"name": repo.get("name"), "url": repo.get("url"), "path": str(root) if is_local else None, "scan_id": repo.get("scan_id"),
            "commit": (repo.get("commit_sha") or "")[:12], "scanned_at": repo.get("scan_timestamp"), "source": "local folder" if is_local else "GitHub",
            "scanner": ((result.get("sbom_tool") or {}).get("used") or "").title()}
    fixes: list[dict] = []
    for it in items:
        if is_local:
            rec = applied_record(root, it)
            if not rec:
                continue
            changes = _diff_files(root, rec, it)
            applied_at, how, lock = rec.get("applied_at"), "Applied to the project files after validation on a clone", rec.get("lock") or {}
            fixed = rec.get("fixed") or []
            trial = trial_loader(root, it) if trial_loader else None
        else:
            d = (delivered or {}).get(it["id"]) or it.get("delivery_result")
            if not d or d.get("status") != "success":
                continue
            changes = _diff_from_patch(it)
            applied_at, how, lock = d.get("committed_at") or "", f"Committed to branch {d.get('branch')}", {}
            fixed = ((it.get("what_if") or {}).get("fixed")) or []
            trial = None
        rows = _finding_rows(it, fixed, vulns, risks)
        sev = {k: sum(1 for r in rows if r["severity"] == k) for k in SEV_ORDER}
        scores = [r["score"] for r in rows if r["score"] is not None]
        comparison = (trial or {}).get("comparison") or {}
        fixes.append({
            "id": it["id"], "title": it["title"], "action": it.get("action"), "ecosystem": it.get("ecosystem"), "priority": it.get("priority"),
            "risk_label": it.get("risk_label"), "rationale": it.get("rationale", ""), "target": it.get("target") or {}, "applied_at": applied_at, "how": how,
            "findings": rows, "severity_counts": sev, "max_score": max(scores) if scores else None,
            "risk_counts": {k: sum(1 for r in rows if (r["risk"] or "").upper() == k) for k in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL")},
            "changes": changes, "lock": lock, "validation": _validation_summary(trial, it), "comparison": comparison, "repo": base,
            "compat": (it.get("compatibility") or {}),
        })
    fixes.sort(key=lambda f: f["applied_at"] or "", reverse=True)
    return fixes


def _validation_summary(trial: Optional[dict], rem: dict) -> dict:
    if not trial:
        v = rem.get("validation") or {}
        return {"status": "static" if v else "n/a", "steps": [], "warnings": [], "tests": "not recorded"}
    t = trial.get("tests") or {}
    return {"status": trial.get("status"), "steps": [{"step": s["step"], "ok": s["ok"], "detail": s["detail"]} for s in trial.get("steps", [])],
            "warnings": trial.get("warnings") or [], "tests": t.get("status", "not_run"), "compat": (trial.get("compat") or {}).get("status")}


def totals(fixes: list[dict], all_findings: int) -> dict[str, Any]:
    keys = {(r["package"], r["version"], r["id"]) for f in fixes for r in f["findings"]}
    return {"fixes": len(fixes), "findings_fixed": len(keys), "remaining": max(all_findings - len(keys), 0)}
