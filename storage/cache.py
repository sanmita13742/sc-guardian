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
