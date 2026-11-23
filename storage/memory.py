"""Persistent scan memory (SQLite, deterministic, no embeddings).

* ``finding_state``  per repository + stable finding fingerprint: first/last seen, status, times seen  -> new / persisting / fixed
* ``decisions``      analyst decisions (accepted risk, false positive, suppress) with reason and optional expiry
* ``package_seen``   which packages were seen in how many scans/repositories (context, e.g. for typosquat triage)

Decisions never delete findings: they are shown, flagged, and expire.
"""
from __future__ import annotations

import time
from typing import Any, Iterable, Optional

from storage.database import Database

DECISIONS = ("accepted_risk", "false_positive", "suppress")


def _now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def fingerprint(kind: str, f: dict) -> str:
    """Stable identity of a finding across scans (finding_ids like VULN-001 are per-scan sequence numbers)."""
    if kind == "vulnerability":
        return "|".join(["vuln", f.get("ecosystem") or "", f.get("package_name") or "", f.get("installed_version") or "", f.get("primary_id") or "", f.get("service_dir") or "."])
    if kind == "typosquatting":
        return "|".join(["typo", f.get("ecosystem") or "", f.get("package_name") or "", f.get("similar_to") or ""])
    if kind == "package_risk":
        return "|".join(["pkgrisk", f.get("rule_id") or "", f.get("ecosystem") or "", f.get("subject") or ""])
    if kind == "pipeline":
        return "|".join(["pipe", f.get("rule_id") or "", f.get("file") or "", (f.get("subject") or "")[:80]])
    prev, new = f.get("previous") or {}, f.get("new") or {}
    return "|".join(["lock", f.get("file") or "", f.get("package_name") or "", f.get("change_type") or "", str(prev.get("version") or ""), str(new.get("version") or "")])


def title(kind: str, f: dict) -> str:
    if kind == "vulnerability":
        return f"{f.get('primary_id')} in {f.get('package_name')}@{f.get('installed_version')}"
    if kind == "typosquatting":
        return f"{f.get('package_name')} resembles {f.get('similar_to')}"
    if kind in ("pipeline", "package_risk"):
        return f"{f.get('rule_id')} {f.get('title')}" + (f" ({f.get('file')})" if kind == "pipeline" else "")
    return f"{f.get('change_type')} {f.get('package_name')} in {f.get('file')}"


class Memory:
    def __init__(self, db: Database):
        self.db = db

    # ------------------------------------------------------------------ findings over time
    def record_scan(self, repo_url: str, scan_id: str, scan_ts: str, findings: Iterable[tuple[str, dict, Optional[str]]]) -> dict[str, Any]:
        """Update finding_state with this scan and return the diff against the previous state of the repository."""
        cur = {fingerprint(k, f): (k, f, lab) for k, f, lab in findings}
        with self.db.connect() as c:
            rows = {r["fingerprint"]: dict(r) for r in c.execute("SELECT * FROM finding_state WHERE repo_url=?", (repo_url,)).fetchall()}
            had_history = bool(rows)
            new, persisting, regressed = [], [], []
            for fp, (kind, f, lab) in cur.items():
                old = rows.get(fp)
                t = title(kind, f)
                if old is None:
                    new.append(fp)
                    c.execute("INSERT INTO finding_state(repo_url,fingerprint,kind,title,severity,risk_label,status,first_seen_scan,first_seen_at,last_seen_scan,last_seen_at,times_seen)"
                              " VALUES (?,?,?,?,?,?,'open',?,?,?,?,1)", (repo_url, fp, kind, t, f.get("severity"), lab, scan_id, scan_ts, scan_id, scan_ts))
                else:
                    (regressed if old["status"] == "fixed" else persisting).append(fp)
                    c.execute("UPDATE finding_state SET status='open', fixed_scan=NULL, last_seen_scan=?, last_seen_at=?, times_seen=times_seen+1, severity=?, risk_label=?, title=? "
                              "WHERE repo_url=? AND fingerprint=?", (scan_id, scan_ts, f.get("severity"), lab, t, repo_url, fp))
            fixed = [fp for fp, r in rows.items() if r["status"] == "open" and fp not in cur]
            for fp in fixed:
                c.execute("UPDATE finding_state SET status='fixed', fixed_scan=? WHERE repo_url=? AND fingerprint=?", (scan_id, repo_url, fp))
            fixed_rows = [{"fingerprint": fp, "title": rows[fp]["title"], "kind": rows[fp]["kind"], "severity": rows[fp]["severity"], "first_seen_at": rows[fp]["first_seen_at"]} for fp in fixed]
        return {"baseline": not had_history, "new": new, "persisting": persisting, "regressed": regressed, "fixed": fixed_rows,
                "counts": {"new": len(new), "persisting": len(persisting), "regressed": len(regressed), "fixed": len(fixed_rows)}}

    def state(self, repo_url: str) -> dict[str, dict]:
        with self.db.connect() as c:
            return {r["fingerprint"]: dict(r) for r in c.execute("SELECT * FROM finding_state WHERE repo_url=?", (repo_url,)).fetchall()}

    # ------------------------------------------------------------------ decisions
    def add_decision(self, repo_url: str, fp: str, decision: str, reason: str, title_: str = "", expires_days: Optional[int] = None, author: str = "analyst") -> int:
        if decision not in DECISIONS:
            raise ValueError(f"decision must be one of {DECISIONS}")
        if not reason.strip():
            raise ValueError("a reason is required")
        exp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() + expires_days * 86400)) if expires_days else None
        with self.db.connect() as c:
            cur = c.execute("INSERT INTO decisions(repo_url,fingerprint,decision,reason,title,created_at,expires_at,author) VALUES (?,?,?,?,?,?,?,?)",
                            (repo_url, fp, decision, reason.strip(), title_, _now(), exp, author))
            return int(cur.lastrowid)

    def decisions(self, repo_url: str, include_expired: bool = False) -> dict[str, dict]:
        """fingerprint -> newest decision (expired ones are excluded unless requested)."""
        with self.db.connect() as c:
            rows = [dict(r) for r in c.execute("SELECT * FROM decisions WHERE repo_url=? ORDER BY id", (repo_url,)).fetchall()]
        now = _now()
        newest: dict[str, dict] = {}
        for r in rows:  # rows are ordered by id: the latest decision per finding wins, even if it has expired
            r["expired"] = bool(r["expires_at"] and r["expires_at"] < now)
            newest[r["fingerprint"]] = r
        return {fp: r for fp, r in newest.items() if include_expired or not r["expired"]}

    def remove_decision(self, decision_id: int) -> None:
        with self.db.connect() as c:
            c.execute("DELETE FROM decisions WHERE id=?", (decision_id,))

    # ------------------------------------------------------------------ packages seen
    def record_packages(self, repo_url: str, packages: Iterable[tuple[str, str]]) -> dict[tuple[str, str], int]:
        """Count scans/repos per package; returns {(eco, name): repos_seen_before} for packages already seen in other repositories."""
        prior: dict[tuple[str, str], int] = {}
        now = _now()
        with self.db.connect() as c:
            for eco, name in set(packages):
                r = c.execute("SELECT repos_seen, last_repo FROM package_seen WHERE ecosystem=? AND name=?", (eco, name)).fetchone()
                if r is None:
                    c.execute("INSERT INTO package_seen(ecosystem,name,first_seen_at,last_seen_at,last_repo) VALUES (?,?,?,?,?)", (eco, name, now, now, repo_url))
                else:
                    other = r["last_repo"] != repo_url
                    if other:
                        prior[(eco, name)] = r["repos_seen"]
                    c.execute("UPDATE package_seen SET last_seen_at=?, scans_seen=scans_seen+1, repos_seen=repos_seen+?, last_repo=? WHERE ecosystem=? AND name=?",
                              (now, 1 if other else 0, repo_url, eco, name))
        return prior
