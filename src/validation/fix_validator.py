"""Building blocks for fix validation (request loading, isolated rescan) and the ``validate_fix`` entry point.

The workflow itself is owned by ``validation.agent.FixValidationAgent``:
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


def approved_items(db: Database, scan_id: str) -> list[str]:
    """Ids of the scan's remediation proposals that have a patch and are approved, in proposal order."""
    before = db.load_scan(scan_id)
    if not before:
        raise ValidationError(f"scan '{scan_id}' not found")
    ap = Memory(db).approvals(before["repo"]["url"])
    return [i["id"] for i in (before.get("remediation") or {}).get("items") or []
            if i.get("patch") and (ap.get(i.get("fingerprint")) or {}).get("state") == "approved"]


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
    ids = approved_items(db, scan_id)
    say = progress or (lambda m: None)

    def one(rid: str) -> dict[str, Any]:
        try:
            out = FixValidationAgent(s, db, actor=actor, progress=lambda m: say(f"[{rid}] {m}"), use_sandbox=use_sandbox).run(scan_id, rid)
            return {"remediation_id": rid, **out}
        except Exception as e:  # noqa: BLE001 - one proposal failing must not stop the batch
            return {"remediation_id": rid, "error": f"{type(e).__name__}: {str(e)[:300]}"}

    with ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
        return list(pool.map(one, ids))
