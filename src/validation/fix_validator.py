"""End-to-end validation of one approved remediation.

    approved item -> disposable clone + patch -> install (writes the new lockfile) -> tests (no network) -> baseline on failure
                  -> rescan the patched tree (isolated DB/artifacts) -> before/after comparison -> verdict -> provenance -> reports

Safety
* Runs only for a proposal a human approved (``Memory.approvals``); start and end are written to the audit log.
* Repository commands run only inside the Docker sandbox (``sandbox.runner``); without Docker the flow still rescans the patched
  manifests statically and the verdict can be at most ``fixed_untested``.
* The rescan uses a throw-away database and artifacts folder, so the saved-scan list and the finding history are not touched.
"""
from __future__ import annotations

import dataclasses
import shutil
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Optional

from config.settings import Settings, get_settings
from core import git_manager as gm
from sandbox import runner as sbx
from storage.database import Database
from storage.memory import Memory
from validation import comparison, provenance, report, verdict
from validation.contracts import ApprovedRemediation, FinalAssessment, PhaseRun, SandboxOutcome

TOOL_VERSION = "0.1.0"


class ValidationError(Exception):
    """The request cannot be validated (unknown scan/proposal, not approved, no patch)."""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def load_request(db: Database, scan_id: str, remediation_id: str) -> tuple[dict, ApprovedRemediation, dict]:
    before = db.load_scan(scan_id)
    if not before:
        raise ValidationError(f"scan '{scan_id}' not found")
    item = next((i for i in (before.get("remediation") or {}).get("items") or [] if i.get("id") == remediation_id), None)
    if not item:
        raise ValidationError(f"remediation '{remediation_id}' not found in scan '{scan_id}'")
    rem = ApprovedRemediation.from_item(item)
    if not rem.patch_diff:
        raise ValidationError(f"{remediation_id} has no patch (action '{rem.action}'); nothing to validate")
    ap = Memory(db).approvals(before["repo"]["url"]).get(rem.fingerprint)
    if not ap or ap.get("state") != "approved":
        raise ValidationError(f"{remediation_id} is not approved (state: {(ap or {}).get('state', 'none')}); approve it on the Remediation page first")
    return before, rem, ap


def _sandbox(clone: Path, rem: ApprovedRemediation, settings: Settings, repo: dict, say: Callable[[str], None]) -> SandboxOutcome:
    ds = sbx.docker_status()
    if not ds["available"]:
        return SandboxOutcome(status="skipped", reason=ds["reason"])
    recipe = sbx.detect_recipe(clone, rem.ecosystem, rem.service)
    if not recipe:
        return SandboxOutcome(status="skipped", reason=f"No recognised build/test recipe for {rem.ecosystem} in this repository.", docker_version=ds["version"])
    say(f"Installing dependencies in {recipe['image']} ...")
    inst = sbx.run_phase(ds["exe"], clone, recipe, "install")
    out = SandboxOutcome(status="error", recipe=recipe, runs=[PhaseRun.model_validate(inst)], docker_version=ds["version"],
                         isolation="cap-drop ALL, no-new-privileges, 2 CPU / 2 GB / 512 pids, tests without network, no host env or secrets")
    if inst["exit_code"] != 0:
        out.reason = "dependency installation failed with the patch applied"
        return out
    say("Running the tests with the network disabled ...")
    test = sbx.run_phase(ds["exe"], clone, recipe, "test")
    out.runs.append(PhaseRun.model_validate(test))
    out.status = "passed" if test["exit_code"] == 0 else "failed"
    if out.status == "failed":
        say("Tests failed: running the unpatched baseline ...")
        ws_b, base = sbx.prepare_workspace(settings, repo, None)
        try:
            bi = sbx.run_phase(ds["exe"], base, recipe, "install")
            bt = sbx.run_phase(ds["exe"], base, recipe, "test") if bi["exit_code"] == 0 else None
            out.baseline = {"status": "passed" if bt and bt["exit_code"] == 0 else "failed", "runs": [bi] + ([bt] if bt else [])}
            out.attribution = ("the same failure occurs without the patch (pre-existing)" if out.baseline["status"] == "failed"
                               else "the baseline passes: the patch likely broke a test")
        finally:
            gm.cleanup(ws_b)
    return out


def _rescan(clone: Path, ws: Path, settings: Settings) -> dict[str, Any]:
    from core.scan_orchestrator import ScanOptions, scan_local_directory
    iso = dataclasses.replace(settings, data_dir=ws / "rescan-data", artifacts_dir=ws / "rescan-artifacts")
    iso.data_dir.mkdir(parents=True, exist_ok=True)
    for sub in ("sbom", "scans", "reports", "graphs"):
        (iso.artifacts_dir / sub).mkdir(parents=True, exist_ok=True)
    opts = ScanOptions(remediate=False, use_llm=False, reuse_cached=False, lockfile_commits=1)
    return scan_local_directory(clone, opts, settings=iso, db=Database(iso.db_path), name=clone.name)


def _changed_files(clone: Path) -> list[str]:
    r = gm.run_git(["status", "--porcelain", "--untracked-files=no"], cwd=clone, check=False, timeout=60)
    return [ln[3:].strip() for ln in r.stdout.splitlines() if ln.strip()]


def validate_fix(scan_id: str, remediation_id: str, *, settings: Optional[Settings] = None, db: Optional[Database] = None,
                 actor: str = "cli", progress: Optional[Callable[[str], None]] = None, use_sandbox: bool = True) -> dict[str, Any]:
    s = settings or get_settings()
    db = db or Database(s.db_path)
    say = progress or (lambda m: None)
    before, rem, ap = load_request(db, scan_id, remediation_id)
    repo = before["repo"]
    mem = Memory(db)
    started = _now()
    t0 = time.time()
    mem.audit(repo["url"], actor, "fix_validation_started", f"{rem.id} {rem.source_package}", f"approved by {ap.get('actor')}")
    out_dir = report.output_dir(s.artifacts_dir, scan_id, rem.id)
    limitations: list[str] = []
    ws = None
    after: Optional[dict] = None
    cmp = None
    sandbox = SandboxOutcome(status="skipped", reason="sandbox disabled by the caller")
    subjects: list[dict] = []
    try:
        say("Cloning at the scanned commit and applying the patch ...")
        try:
            ws, clone = sbx.prepare_workspace(s, repo, rem.patch_diff)
        except gm.GitError as e:
            sandbox = SandboxOutcome(status="error", reason=f"patch could not be applied: {str(e)[:200]}")
            raise
        if use_sandbox:
            sandbox = _sandbox(clone, rem, s, repo, say)
        if sandbox.install_ok:
            limitations.append("Inventory taken after the sandbox install: it reflects the regenerated lockfile (and any installed tree).")
        else:
            limitations.append("Dependencies were not installed: the lockfile was not regenerated, so the rescan sees the patched manifests only.")
        for f in _changed_files(clone):
            subjects.append(provenance.subject(f, clone / f))
        say("Rescanning the patched tree ...")
        after = _rescan(clone, ws, s)
        if after.get("status") == "failed":
            limitations.append(f"Rescan failed: {after.get('error', '')[:200]}")
        else:
            cmp = comparison.compare(before, after, rem)
            if after.get("sbom_path") and Path(after["sbom_path"]).exists():
                kept = out_dir / "after_sbom.cdx.json"
                shutil.copyfile(after["sbom_path"], kept)
                subjects.append(provenance.subject("after_sbom.cdx.json", kept))
    except gm.GitError as e:
        limitations.append(f"Git error during validation: {str(e)[:200]}")
    finally:
        if ws:
            gm.cleanup(ws)

    rescan_ok = after is not None and after.get("status") != "failed"
    v, reasons, checks = verdict.decide(cmp, sandbox, rescan_ok)
    image = (sandbox.recipe or {}).get("image")
    stmt = provenance.statement(subjects, repo_url=repo["url"], commit_sha=repo.get("commit_sha") or "", patch_sha256=provenance.sha256_text(rem.patch_diff or ""),
                                remediation_id=rem.id, recipe=sandbox.recipe,
                                image_digest=provenance.docker_image_digest(shutil.which("docker"), image) if image else None,
                                started_on=started, finished_on=_now(), tool_version=TOOL_VERSION)
    final = FinalAssessment(remediation_id=rem.id, fingerprint=rem.fingerprint, scan_id=scan_id, verdict=v, reasons=reasons, checks=checks,
                            limitations=limitations, provenance_ref=str(out_dir / "provenance.intoto.json"), created_at=_now(), approved_by=ap.get("actor"))
    validation_report = {"remediation": rem.model_dump(mode="json", by_alias=True, exclude={"patch_diff"}), "sandbox": sandbox.model_dump(mode="json"),
                         "rescan": {"ok": rescan_ok, "scan_id": (after or {}).get("repo", {}).get("scan_id"), "status": (after or {}).get("status"),
                                    "errors": (after or {}).get("errors", [])},
                         "signature": provenance.signature_status(), "seconds": round(time.time() - t0, 1), "tool_version": TOOL_VERSION}
    paths = report.write_outputs(out_dir, comparison=cmp.model_dump(mode="json") if cmp else {"available": False}, validation_report=validation_report,
                                 final_assessment=final, provenance=stmt)
    mem.audit(repo["url"], actor, f"fix_validation_{v}", f"{rem.id} {rem.source_package}", "; ".join(reasons)[:1000])
    return {"final_assessment": final.model_dump(mode="json"), "files": paths}
