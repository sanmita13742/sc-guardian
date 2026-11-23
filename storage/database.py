"""SQLite persistence: scan records, findings and a generic advisory/registry cache."""
from __future__ import annotations

import json
import sqlite3
import threading
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator, Optional

SCHEMA_VERSION = 2  # 1: scans/findings/cache  2: + memory tables, graph tables, scans.scanner_version

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
CREATE TABLE IF NOT EXISTS finding_state (
    repo_url TEXT NOT NULL,
    fingerprint TEXT NOT NULL,
    kind TEXT NOT NULL,
    title TEXT,
    severity TEXT,
    risk_label TEXT,
    status TEXT NOT NULL,              -- open | fixed
    first_seen_scan TEXT NOT NULL,
    first_seen_at TEXT NOT NULL,
    last_seen_scan TEXT NOT NULL,
    last_seen_at TEXT NOT NULL,
    fixed_scan TEXT,
    times_seen INTEGER NOT NULL DEFAULT 1,
    PRIMARY KEY (repo_url, fingerprint)
);
CREATE TABLE IF NOT EXISTS decisions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    repo_url TEXT NOT NULL,
    fingerprint TEXT NOT NULL,
    decision TEXT NOT NULL,            -- accepted_risk | false_positive | suppress
    reason TEXT NOT NULL,
    title TEXT,
    created_at TEXT NOT NULL,
    expires_at TEXT,
    author TEXT
);
CREATE INDEX IF NOT EXISTS idx_decisions_repo ON decisions(repo_url, fingerprint);
CREATE TABLE IF NOT EXISTS package_seen (
    ecosystem TEXT NOT NULL,
    name TEXT NOT NULL,
    first_seen_at TEXT NOT NULL,
    last_seen_at TEXT NOT NULL,
    repos_seen INTEGER NOT NULL DEFAULT 1,
    scans_seen INTEGER NOT NULL DEFAULT 1,
    last_repo TEXT,
    PRIMARY KEY (ecosystem, name)
);
CREATE TABLE IF NOT EXISTS graph_meta (
    scan_id TEXT PRIMARY KEY REFERENCES scans(scan_id) ON DELETE CASCADE,
    graph_hash TEXT NOT NULL,
    nodes INTEGER NOT NULL,
    edges INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS graph_nodes (
    scan_id TEXT NOT NULL REFERENCES scans(scan_id) ON DELETE CASCADE,
    node_id TEXT NOT NULL,
    node_key TEXT NOT NULL,
    kind TEXT, label TEXT, name TEXT, version TEXT, ecosystem TEXT, service_dir TEXT, purl TEXT,
    PRIMARY KEY (scan_id, node_id)
);
CREATE TABLE IF NOT EXISTS graph_edges (
    scan_id TEXT NOT NULL REFERENCES scans(scan_id) ON DELETE CASCADE,
    src TEXT NOT NULL,
    dst TEXT NOT NULL,
    provenance TEXT,
    PRIMARY KEY (scan_id, src, dst)
);
CREATE INDEX IF NOT EXISTS idx_graph_nodes_key ON graph_nodes(node_key);
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
            self._migrate(c)

    @staticmethod
    def _migrate(c: sqlite3.Connection) -> None:
        """Forward-only migrations keyed by PRAGMA user_version (CREATE IF NOT EXISTS above covers new tables)."""
        ver = c.execute("PRAGMA user_version").fetchone()[0]
        if ver > SCHEMA_VERSION:
            raise RuntimeError(f"database schema v{ver} is newer than this code (v{SCHEMA_VERSION}); refusing to open it")
        cols = {r[1] for r in c.execute("PRAGMA table_info(scans)").fetchall()}
        if "scanner_version" not in cols:
            c.execute("ALTER TABLE scans ADD COLUMN scanner_version TEXT")
        if ver < SCHEMA_VERSION:
            c.execute(f"PRAGMA user_version={SCHEMA_VERSION}")

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
                " sbom_path, summary, result_json, scanner_version) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                (repo["scan_id"], repo["url"], repo["name"], repo.get("ref"), repo["commit_sha"], repo["scan_timestamp"],
                 result.get("status", "unknown"), json.dumps(result.get("tool_versions", {})), result.get("sbom_path"),
                 json.dumps(result.get("summary", {})), json.dumps(result, default=str), (result.get("tool_versions") or {}).get("scanner")),
            )
            self._save_graph(c, repo["scan_id"], result.get("graph") or {})
            for kind, f in findings:
                fid = f.get("finding_id", "")
                c.execute(
                    "INSERT INTO findings(scan_id, kind, finding_id, component_ref, severity, risk_label, payload)"
                    " VALUES (?,?,?,?,?,?,?)",
                    (repo["scan_id"], kind, fid, f.get("component_ref"), f.get("severity"),
                     (risks.get(fid) or {}).get("label"), json.dumps(f, default=str)),
                )

    @staticmethod
    def _save_graph(c: sqlite3.Connection, scan_id: str, graph: dict) -> None:
        from graph.graph_diff import graph_hash, node_key
        nodes, edges = graph.get("nodes") or [], graph.get("edges") or []
        if not nodes:
            return
        c.execute("INSERT OR REPLACE INTO graph_meta(scan_id, graph_hash, nodes, edges) VALUES (?,?,?,?)", (scan_id, graph_hash(graph), len(nodes), len(edges)))
        c.executemany("INSERT OR REPLACE INTO graph_nodes(scan_id,node_id,node_key,kind,label,name,version,ecosystem,service_dir,purl) VALUES (?,?,?,?,?,?,?,?,?,?)",
                      [(scan_id, n["id"], node_key(n), n.get("kind"), n.get("label"), n.get("name"), n.get("version"), n.get("ecosystem"), n.get("service_dir"), n.get("purl")) for n in nodes])
        c.executemany("INSERT OR REPLACE INTO graph_edges(scan_id,src,dst,provenance) VALUES (?,?,?,?)", [(scan_id, e["source"], e["target"], e.get("provenance")) for e in edges])

    def load_graph(self, scan_id: str) -> Optional[dict]:
        """Rebuild a ``graph_to_json``-shaped dict from the persisted tables (queryable/diffable without loading the full result)."""
        with self.connect() as c:
            nodes = [dict(r) for r in c.execute("SELECT * FROM graph_nodes WHERE scan_id=?", (scan_id,)).fetchall()]
            edges = [dict(r) for r in c.execute("SELECT * FROM graph_edges WHERE scan_id=?", (scan_id,)).fetchall()]
        if not nodes:
            return None
        return {"nodes": [{"id": n["node_id"], **{k: n[k] for k in ("kind", "label", "name", "version", "ecosystem", "service_dir", "purl")}} for n in nodes],
                "edges": [{"source": e["src"], "target": e["dst"], "provenance": e["provenance"]} for e in edges]}

    def previous_scan(self, repo_url: str, scan_id: str) -> Optional[str]:
        """Id of the scan of the same repository that precedes ``scan_id`` (by timestamp)."""
        with self.connect() as c:
            cur = c.execute("SELECT scan_timestamp, rowid FROM scans WHERE scan_id=?", (scan_id,)).fetchone()
            if not cur:
                return None
            r = c.execute("SELECT scan_id FROM scans WHERE repo_url=? AND status!='failed' AND (scan_timestamp < ? OR (scan_timestamp = ? AND rowid < ?))"
                          " ORDER BY scan_timestamp DESC, rowid DESC LIMIT 1", (repo_url, cur["scan_timestamp"], cur["scan_timestamp"], cur["rowid"])).fetchone()
        return r["scan_id"] if r else None

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
