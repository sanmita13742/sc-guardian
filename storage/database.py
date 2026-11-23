"""SQLite persistence: scan records, findings and a generic advisory/registry cache."""
from __future__ import annotations

import json
import sqlite3
import threading
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator, Optional

SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    scan_id TEXT PRIMARY KEY,
    repo_url TEXT NOT NULL,
    repo_name TEXT,
    ref TEXT,
    commit_sha TEXT NOT NULL,
    scan_timestamp TEXT NOT NULL,
    status TEXT NOT NULL,
    tool_versions TEXT,
    sbom_path TEXT,
    summary TEXT,
    result_json TEXT
);
CREATE INDEX IF NOT EXISTS idx_scans_repo_commit ON scans(repo_url, commit_sha);
CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id TEXT NOT NULL REFERENCES scans(scan_id) ON DELETE CASCADE,
    kind TEXT NOT NULL,            -- vulnerability | typosquatting | lockfile_change
    finding_id TEXT NOT NULL,
    component_ref TEXT,
    severity TEXT,
    risk_label TEXT,
    payload TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id, kind);
CREATE TABLE IF NOT EXISTS cache (
    namespace TEXT NOT NULL,
    key TEXT NOT NULL,
    payload TEXT NOT NULL,
    fetched_at REAL NOT NULL,
    PRIMARY KEY (namespace, key)
);
"""


class Database:
    def __init__(self, path: Path | str):
        self.path = str(path)
        self._lock = threading.RLock()
        with self.connect() as c:
            c.executescript(SCHEMA)

    @contextmanager
    def connect(self) -> Iterator[sqlite3.Connection]:
        with self._lock:
            conn = sqlite3.connect(self.path, timeout=30)
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA foreign_keys=ON")
            conn.execute("PRAGMA journal_mode=WAL")
            try:
                yield conn
                conn.commit()
            finally:
                conn.close()

    # ------------------------------------------------------------ scans
    def save_scan(self, result: dict[str, Any]) -> None:
        repo = result["repo"]
        findings: list[tuple[str, dict]] = []
        for f in result.get("vulnerabilities", []):
            findings.append(("vulnerability", f))
        for f in result.get("typosquatting", []):
            findings.append(("typosquatting", f))
        for f in result.get("lockfile_changes", []):
            findings.append(("lockfile_change", f))
        risks = {r["finding_id"]: r for r in result.get("risk_assessments", [])}
        with self.connect() as c:
            c.execute("DELETE FROM scans WHERE scan_id=?", (repo["scan_id"],))
            c.execute(
                "INSERT INTO scans(scan_id, repo_url, repo_name, ref, commit_sha, scan_timestamp, status, tool_versions,"
                " sbom_path, summary, result_json) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                (repo["scan_id"], repo["url"], repo["name"], repo.get("ref"), repo["commit_sha"], repo["scan_timestamp"],
                 result.get("status", "unknown"), json.dumps(result.get("tool_versions", {})), result.get("sbom_path"),
                 json.dumps(result.get("summary", {})), json.dumps(result, default=str)),
            )
            for kind, f in findings:
                fid = f.get("finding_id", "")
                c.execute(
                    "INSERT INTO findings(scan_id, kind, finding_id, component_ref, severity, risk_label, payload)"
                    " VALUES (?,?,?,?,?,?,?)",
                    (repo["scan_id"], kind, fid, f.get("component_ref"), f.get("severity"),
                     (risks.get(fid) or {}).get("label"), json.dumps(f, default=str)),
                )

    def list_scans(self, limit: int = 50) -> list[dict]:
        with self.connect() as c:
            rows = c.execute(
                "SELECT scan_id, repo_url, repo_name, ref, commit_sha, scan_timestamp, status, summary FROM scans"
                " ORDER BY scan_timestamp DESC LIMIT ?", (limit,)).fetchall()
        return [{**dict(r), "summary": json.loads(r["summary"] or "{}")} for r in rows]

    def load_scan(self, scan_id: str) -> Optional[dict]:
        with self.connect() as c:
            r = c.execute("SELECT result_json FROM scans WHERE scan_id=?", (scan_id,)).fetchone()
        return json.loads(r["result_json"]) if r else None

    def find_scan(self, repo_url: str, commit_sha: str) -> Optional[str]:
        with self.connect() as c:
            r = c.execute("SELECT scan_id FROM scans WHERE repo_url=? AND commit_sha=? AND status!='failed'"
                          " ORDER BY scan_timestamp DESC LIMIT 1", (repo_url, commit_sha)).fetchone()
        return r["scan_id"] if r else None

    def prune_repo(self, repo_url: str, keep: int) -> list[str]:
        """Keep the newest ``keep`` scans of a repository; return the ids that were deleted."""
        with self.connect() as c:
            ids = [r["scan_id"] for r in c.execute("SELECT scan_id FROM scans WHERE repo_url=? ORDER BY scan_timestamp DESC, rowid DESC", (repo_url,)).fetchall()]
            old = ids[keep:]
            for sid in old:
                c.execute("DELETE FROM scans WHERE scan_id=?", (sid,))
        return old

    def findings(self, scan_id: str, kind: str | None = None) -> list[dict]:
        q, args = "SELECT payload FROM findings WHERE scan_id=?", [scan_id]
        if kind:
            q += " AND kind=?"
            args.append(kind)
        with self.connect() as c:
            return [json.loads(r["payload"]) for r in c.execute(q, args).fetchall()]
