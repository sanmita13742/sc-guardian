"""TTL cache backed by the SQLite ``cache`` table (advisories, registry metadata, KEV, NVD)."""
from __future__ import annotations

import json
import time
from typing import Any, Optional

from storage.database import Database


class Cache:
    def __init__(self, db: Database):
        self.db = db

    def get(self, namespace: str, key: str, ttl: float | None = None, allow_stale: bool = False) -> Optional[Any]:
        with self.db.connect() as c:
            r = c.execute("SELECT payload, fetched_at FROM cache WHERE namespace=? AND key=?", (namespace, key)).fetchone()
        if not r:
            return None
        if ttl is not None and not allow_stale and (time.time() - r["fetched_at"]) > ttl:
            return None
        return json.loads(r["payload"])

    def get_with_time(self, namespace: str, key: str) -> Optional[tuple[Any, float]]:
        with self.db.connect() as c:
            r = c.execute("SELECT payload, fetched_at FROM cache WHERE namespace=? AND key=?", (namespace, key)).fetchone()
        return (json.loads(r["payload"]), r["fetched_at"]) if r else None

    def set(self, namespace: str, key: str, value: Any) -> None:
        with self.db.connect() as c:
            c.execute("INSERT OR REPLACE INTO cache(namespace, key, payload, fetched_at) VALUES (?,?,?,?)",
                      (namespace, key, json.dumps(value, default=str), time.time()))


    # ------------------------------------------------------------------ maintenance
    def stats(self) -> dict:
        """Rows, bytes and age per namespace (for the Settings & Health page)."""
        with self.db.connect() as c:
            rows = c.execute("SELECT namespace, COUNT(*) n, COALESCE(SUM(LENGTH(payload)),0) b, MIN(fetched_at) oldest, MAX(fetched_at) newest FROM cache GROUP BY namespace ORDER BY n DESC").fetchall()
        return {"namespaces": [{"namespace": r["namespace"], "rows": r["n"], "bytes": r["b"], "oldest": r["oldest"], "newest": r["newest"]} for r in rows],
                "total_rows": sum(r["n"] for r in rows), "total_bytes": sum(r["b"] for r in rows)}

    def maintain(self, max_age_days: int = 120, max_rows: int = 2_000_000) -> dict:
        """Purge rows older than ``max_age_days`` and, if still above ``max_rows``, the oldest rows. Cheap enough to call at the start of every scan."""
        cutoff = time.time() - max_age_days * 86400
        with self.db.connect() as c:
            old = c.execute("DELETE FROM cache WHERE fetched_at < ?", (cutoff,)).rowcount
            total = c.execute("SELECT COUNT(*) FROM cache").fetchone()[0]
            over = 0
            if total > max_rows:
                over = c.execute("DELETE FROM cache WHERE rowid IN (SELECT rowid FROM cache ORDER BY fetched_at ASC LIMIT ?)", (total - max_rows,)).rowcount
        return {"purged_old": old, "purged_over_limit": over}

    def clear(self, namespace: str | None = None) -> int:
        with self.db.connect() as c:
            return c.execute("DELETE FROM cache WHERE namespace=?", (namespace,)).rowcount if namespace else c.execute("DELETE FROM cache").rowcount
