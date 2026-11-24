"""Building blocks for fix validation (request loading, isolated rescan) and the ``validate_fix`` entry point.

The workflow itself is owned by ``validation.agent.FixValidationAgent``:
    approved item -> disposable clone + patch -> install (writes the new lockfile) -> tests (no network) -> baseline on failure
                  -> rescan the patched tree (isolated DB/artifacts) -> before/after comparison -> verdict -> provenance -> reports

Safety
* P0/P1 proposals require human approval; policy-approved P2/P3 proposals may validate automatically. Start and end are audited.
* Repository commands run only inside the Docker sandbox (``sandbox.runner``); without Docker the flow still rescans the patched
  manifests statically and the verdict can be at most ``fixed_untested``.
* The rescan uses a throw-away database and artifacts folder, so the saved-scan list and the finding history are not touched.
"""
from __future__ import annotations

import dataclasses
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Optional

from config.settings import Settings, get_settings
from core import git_manager as gm
from storage.database import Database
from storage.memory import Memory
from validation.contracts import ApprovedRemediation

class ValidationError(Exception):
    """The request cannot be validated (unknown scan/proposal, not approved, no patch)."""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


# Approvals written by the low/medium automation policy.
AUTOMATED_ACTORS = {"sc guardian policy engine", "auto-policy"}


def is_human_approval(ap: Optional[dict]) -> bool:
    if not ap or ap.get("state") != "approved":
        return False
    actor = (ap.get("actor") or "").strip().lower()
    reason = (ap.get("reason") or "").strip().lower()
    return bool(actor) and actor not in AUTOMATED_ACTORS and not reason.startswith("automated policy")


def is_policy_approval(ap: Optional[dict]) -> bool:
    if not ap or ap.get("state") != "approved":
        return False
    actor = (ap.get("actor") or "").strip().lower()
    reason = (ap.get("reason") or "").strip().lower()
    return actor in AUTOMATED_ACTORS or reason.startswith("automated policy")


def is_validation_approved(ap: Optional[dict], priority: Optional[str]) -> bool:
    """Human approval always qualifies; policy approval qualifies only for P2/P3."""
    if is_human_approval(ap):
        return True
    return is_policy_approval(ap) and priority in ("P2", "P3")


def approval_mode(ap: Optional[dict], priority: Optional[str]) -> Optional[str]:
    if is_human_approval(ap):
        return "human"
    if is_validation_approved(ap, priority):
        return "automated_policy"
    return None


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
    if not is_validation_approved(ap, rem.priority):
        raise ValidationError(f"{remediation_id} is {rem.priority or 'unclassified'} and was approved automatically by '{ap.get('actor')}'. "
                              "Only P2/P3 proposals may use policy approval; P0/P1 validation requires a person")
    return before, rem, ap


def _seed_cache(src: Database, dst: Database) -> int:
    """Copy the HTTP/registry/advisory cache (only that table) into the isolated rescan database.

    Without this the rescan starts cold and re-fetches every OSV/NVD/registry response (measured: 18.5 min vs 5 min on NodeGoat).
    Scans, findings, approvals and history are *not* copied, so the rescan still cannot touch the user's records.
    """
    with dst.connect() as c:
        c.execute("ATTACH DATABASE ? AS src", (str(src.path),))
        try:
            before = c.execute("SELECT COUNT(*) FROM cache").fetchone()[0]
            c.execute("INSERT OR IGNORE INTO cache SELECT * FROM src.cache")
            n = c.execute("SELECT COUNT(*) FROM cache").fetchone()[0] - before
            c.commit()
        finally:
            c.execute("DETACH DATABASE src")
    return n


def _rescan(clone: Path, ws: Path, settings: Settings, src_db: Optional[Database] = None) -> dict[str, Any]:
    from core.scan_orchestrator import ScanOptions, scan_local_directory
    iso = dataclasses.replace(settings, data_dir=ws / "rescan-data", artifacts_dir=ws / "rescan-artifacts")
    iso.data_dir.mkdir(parents=True, exist_ok=True)
    for sub in ("sbom", "scans", "reports", "graphs"):
        (iso.artifacts_dir / sub).mkdir(parents=True, exist_ok=True)
    iso_db = Database(iso.db_path)
    if src_db is not None:
        try:
            _seed_cache(src_db, iso_db)
        except Exception:  # noqa: BLE001 - a cold cache is slower, never wrong
            pass
    opts = ScanOptions(remediate=False, use_llm=False, reuse_cached=False, lockfile_commits=1)
    return scan_local_directory(clone, opts, settings=iso, db=iso_db, name=clone.name)


def _changed_files(clone: Path) -> list[str]:
    r = gm.run_git(["status", "--porcelain", "--untracked-files=no"], cwd=clone, check=False, timeout=60)
    return [ln[3:].strip() for ln in r.stdout.splitlines() if ln.strip()]


def validate_fix(scan_id: str, remediation_id: str, *, settings: Optional[Settings] = None, db: Optional[Database] = None,
                 actor: str = "cli", progress: Optional[Callable[[str], None]] = None, use_sandbox: bool = True) -> dict[str, Any]:
    """Validate one approved remediation. The Fix Validation Agent owns the workflow (see ``validation.agent``)."""
    from validation.agent import FixValidationAgent
    return FixValidationAgent(settings, db, actor=actor, progress=progress, use_sandbox=use_sandbox).run(scan_id, remediation_id)


def approved_items(db: Database, scan_id: str) -> tuple[list[str], list[str]]:
    """(validation-eligible ids, manual-approval-required ids), in proposal order."""
    before = db.load_scan(scan_id)
    if not before:
        raise ValidationError(f"scan '{scan_id}' not found")
    ap = Memory(db).approvals(before["repo"]["url"])
    eligible, manual_required = [], []
    for i in (before.get("remediation") or {}).get("items") or []:
        a = ap.get(i.get("fingerprint"))
        if not i.get("patch") or not a or a.get("state") != "approved":
            continue
        (eligible if is_validation_approved(a, i.get("priority")) else manual_required).append(i["id"])
    return eligible, manual_required


def validate_all(scan_id: str, *, settings: Optional[Settings] = None, db: Optional[Database] = None, actor: str = "cli",
                 progress: Optional[Callable[[str], None]] = None, use_sandbox: bool = True, workers: int = 1) -> list[dict[str, Any]]:
    """Validate every approved proposal of a scan.

    Scales by sharing work, not only by parallelism: one baseline run per commit (memoised), warm package-cache volumes and a warm
    advisory cache. ``workers`` > 1 runs proposals in parallel; each sandbox uses 2 CPU / 2 GB, so keep workers <= CPUs // 2.
    """
    from concurrent.futures import ThreadPoolExecutor
    from validation.agent import FixValidationAgent
    s = settings or get_settings()
    db = db or Database(s.db_path)
    ids, manual_required = approved_items(db, scan_id)
    say = progress or (lambda m: None)
    skipped = [{"remediation_id": rid, "skipped": "P0/P1 proposal requires a person's approval before validation"} for rid in manual_required]

    def one(rid: str) -> dict[str, Any]:
        try:
            out = FixValidationAgent(s, db, actor=actor, progress=lambda m: say(f"[{rid}] {m}"), use_sandbox=use_sandbox).run(scan_id, rid)
            return {"remediation_id": rid, **out}
        except Exception as e:  # noqa: BLE001 - one proposal failing must not stop the batch
            return {"remediation_id": rid, "error": f"{type(e).__name__}: {str(e)[:300]}"}

    with ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
        return list(pool.map(one, ids)) + skipped
