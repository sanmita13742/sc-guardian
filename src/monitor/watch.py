"""Continuous monitoring: re-assess *stored* inventories against newly disclosed vulnerabilities without re-cloning or re-scanning.

For each watched repository (or every repository that has a stored scan) the latest completed scan's component list is re-checked against OSV
(cache bypassed), the CISA KEV catalog and EPSS. Differences against what that scan recorded become alerts:

  new_vulnerability   an advisory now matches a component that had no finding for it when the scan ran
  now_exploited       a finding that was not in KEV when scanned is now listed as known exploited
  epss_rise           exploitation probability rose by >= 0.2 or crossed 0.5

Alerts are deduplicated per repository (a given alert is raised once), stored in ``monitor_events`` and shown in the Monitoring page.
Nothing is modified in the repository or the stored scan.
"""
from __future__ import annotations

import json
import time
from typing import Any, Optional

from config.settings import Settings
from core.http import HttpClient
from core.models import Component
from intel.epss import EpssClient
from storage.cache import Cache
from storage.database import Database
from vulnerability.kev_client import KevClient
from vulnerability.osv_client import OsvClient
from vulnerability.vulnerability_correlator import correlate

SCHEMA = """
CREATE TABLE IF NOT EXISTS watchlist (
    repo_url TEXT PRIMARY KEY,
    added_at TEXT NOT NULL,
    interval_hours INTEGER NOT NULL DEFAULT 24,
    enabled INTEGER NOT NULL DEFAULT 1,
    last_run TEXT,
    last_scan_id TEXT
);
CREATE TABLE IF NOT EXISTS monitor_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    repo_url TEXT NOT NULL,
    at TEXT NOT NULL,
    kind TEXT NOT NULL,
    severity TEXT,
    fingerprint TEXT NOT NULL,
    title TEXT NOT NULL,
    detail TEXT,
    scan_id TEXT,
    acknowledged INTEGER NOT NULL DEFAULT 0,
    UNIQUE (repo_url, fingerprint)
);
"""


def _now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def ensure(db: Database) -> None:
    with db.connect() as c:
        c.executescript(SCHEMA)


def add_watch(db: Database, repo_url: str, interval_hours: int = 24) -> None:
    ensure(db)
    with db.connect() as c:
        c.execute("INSERT OR REPLACE INTO watchlist(repo_url, added_at, interval_hours, enabled) VALUES (?,?,?,1)", (repo_url, _now(), interval_hours))


def remove_watch(db: Database, repo_url: str) -> None:
    ensure(db)
    with db.connect() as c:
        c.execute("DELETE FROM watchlist WHERE repo_url=?", (repo_url,))


def watchlist(db: Database) -> list[dict]:
    ensure(db)
    with db.connect() as c:
        return [dict(r) for r in c.execute("SELECT * FROM watchlist ORDER BY added_at").fetchall()]


def events(db: Database, repo_url: Optional[str] = None, limit: int = 200) -> list[dict]:
    ensure(db)
    with db.connect() as c:
        q, a = "SELECT * FROM monitor_events", []
        if repo_url:
            q += " WHERE repo_url=?"
            a.append(repo_url)
        return [dict(r) for r in c.execute(q + " ORDER BY id DESC LIMIT ?", (*a, limit)).fetchall()]


def acknowledge(db: Database, event_id: int) -> None:
    with db.connect() as c:
        c.execute("UPDATE monitor_events SET acknowledged=1 WHERE id=?", (event_id,))


def _latest_scans(db: Database) -> dict[str, str]:
    seen: dict[str, str] = {}
    for s in db.list_scans(500):
        if s["status"] != "failed" and not s["repo_url"].startswith(("local:", "local-fixture")) and s["repo_url"] not in seen:
            seen[s["repo_url"]] = s["scan_id"]
    return seen


def _record(db: Database, repo: str, scan_id: str, kind: str, severity: Optional[str], fp: str, title: str, detail: dict) -> Optional[dict]:
    with db.connect() as c:
        try:
            c.execute("INSERT INTO monitor_events(repo_url, at, kind, severity, fingerprint, title, detail, scan_id) VALUES (?,?,?,?,?,?,?,?)", (repo, _now(), kind, severity, fp, title, json.dumps(detail, default=str), scan_id))
        except Exception:  # UNIQUE violation: already alerted
            return None
    return {"repo": repo, "kind": kind, "severity": severity or "UNKNOWN", "title": title, "detail": detail, "scan_id": scan_id}


def run_monitor(settings: Settings, db: Database, repo_url: Optional[str] = None, max_repos: int = 20, http: Optional[HttpClient] = None) -> dict[str, Any]:
    ensure(db)
    http = http or HttpClient(timeout=settings.http_timeout_s, retries=2)
    latest = _latest_scans(db)
    wl = [w["repo_url"] for w in watchlist(db) if w["enabled"]]
    targets = [repo_url] if repo_url else (wl or list(latest))
    targets = [t for t in targets if t in latest][:max_repos]
    osv = OsvClient(http, None, settings.osv_batch_size, settings.osv_workers)  # no cache: the point is to see *new* advisories
    kev = KevClient(http, None)
    epss = EpssClient(http, None)
    out: dict[str, Any] = {"repos_checked": 0, "alerts": [], "errors": [], "checked_at": _now(), "sources": {}}
    for repo in targets:
        sid = latest[repo]
        r = db.load_scan(sid)
        if not r:
            continue
        try:
            comps = [Component(**{k: v for k, v in c.items() if k in Component.model_fields}) for c in r.get("components", []) if not c.get("is_self") and c.get("ecosystem") and c.get("version") and c.get("type") != "file"]
            res = correlate(comps, None, [], osv)
            if res["source_status"]["OSV"]["state"] == "unavailable":
                out["errors"].append(f"{repo}: OSV unavailable")
                continue
            old = {(f["package_name"], f["installed_version"], pid) for f in r.get("vulnerabilities", []) for pid in f["vulnerability_ids"]}
            old_cves = {c for f in r.get("vulnerabilities", []) for c in f["cve_ids"]}
            for f in res["findings"]:
                if f.affected_status != "confirmed_affected":
                    continue
                if any((f.package_name, f.installed_version, pid) in old for pid in f.vulnerability_ids):
                    continue
                al = _record(db, repo, sid, "new_vulnerability", f.severity, f"new|{f.package_name}|{f.installed_version}|{f.primary_id}", f"{f.primary_id} now affects {f.package_name}@{f.installed_version}" + (f" (fixed in {', '.join(f.fixed_versions[:2])})" if f.fixed_versions else ""),
                             {"package": f.package_name, "version": f.installed_version, "id": f.primary_id, "severity": f.severity, "cves": f.cve_ids[:4], "fixed": f.fixed_versions[:3]})
                if al:
                    out["alerts"].append(al)
            cves = sorted(old_cves | {c for f in res["findings"] for c in f.cve_ids})
            for f in r.get("vulnerabilities", []):
                for c in f["cve_ids"]:
                    if not f.get("kev") and kev.lookup(c):
                        al = _record(db, repo, sid, "now_exploited", "CRITICAL", f"kev|{c}", f"{c} ({f['package_name']}@{f['installed_version']}) is now listed as actively exploited (CISA KEV)", {"cve": c, "package": f["package_name"], "kev": kev.lookup(c)})
                        if al:
                            out["alerts"].append(al)
            scores = epss.get_many(sorted(old_cves))
            for f in r.get("vulnerabilities", []):
                before = f.get("epss")
                for c in f["cve_ids"]:
                    now = (scores.get(c) or {}).get("epss")
                    if now is None:
                        continue
                    if (before is None and now >= 0.5) or (before is not None and (now - before >= 0.2 or (before < 0.5 <= now))):
                        al = _record(db, repo, sid, "epss_rise", "HIGH", f"epss|{c}|{round(now, 1)}", f"Exploitation probability of {c} ({f['package_name']}) rose to {now:.0%}" + (f" from {before:.0%}" if before is not None else ""),
                                     {"cve": c, "before": before, "now": now})
                        if al:
                            out["alerts"].append(al)
            out["repos_checked"] += 1
            with db.connect() as cx:
                cx.execute("UPDATE watchlist SET last_run=?, last_scan_id=? WHERE repo_url=?", (_now(), sid, repo))
        except Exception as e:  # noqa: BLE001 - one repository failing must not stop the rest
            out["errors"].append(f"{repo}: {type(e).__name__}: {str(e)[:120]}")
    out["sources"] = {"osv": osv.status.get("state"), "kev": kev.status.get("state"), "epss": epss.status.get("state")}
    return out
