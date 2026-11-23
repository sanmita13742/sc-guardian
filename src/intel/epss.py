"""EPSS (Exploit Prediction Scoring System, FIRST.org): probability that a CVE will be exploited in the next 30 days. Public API, no key.

EPSS is a *probability estimate*, not a fact: it is shown as such and only nudges the risk score. Unavailability is reported, never defaulted to 0.
"""
from __future__ import annotations

from typing import Any, Optional

from core.http import HttpClient, NotFound, SourceUnavailable
from storage.cache import Cache

URL = "https://api.first.org/data/v1/epss"
TTL = 24 * 3600


class EpssClient:
    def __init__(self, http: HttpClient, cache: Optional[Cache] = None):
        self.http, self.cache = http, cache
        self.status: dict[str, Any] = {"source": "EPSS (FIRST.org)", "state": "not_queried", "requested": 0, "from_cache": 0, "unavailable": 0, "scored": 0}

    def get_many(self, cves: list[str]) -> dict[str, dict]:
        out: dict[str, dict] = {}
        todo: list[str] = []
        for c in sorted({x for x in cves if x and x.startswith("CVE-")}):
            hit = self.cache.get("epss", c, ttl=TTL) if self.cache else None
            if hit is not None:
                self.status["from_cache"] += 1
                if hit:
                    out[c] = hit
            else:
                todo.append(c)
        for i in range(0, len(todo), 80):
            batch = todo[i:i + 80]
            self.status["requested"] += len(batch)
            try:
                data = self.http.get_json(f"{URL}?cve={','.join(batch)}&limit=100")
            except (NotFound, SourceUnavailable):
                self.status["unavailable"] += len(batch)
                continue
            got = {}
            for r in data.get("data", []) or []:
                try:
                    got[r["cve"]] = {"epss": float(r["epss"]), "percentile": float(r["percentile"]), "date": r.get("date")}
                except (KeyError, ValueError, TypeError):
                    continue
            for c in batch:
                if self.cache:
                    self.cache.set("epss", c, got.get(c, {}))
                if c in got:
                    out[c] = got[c]
        self.status["scored"] = len(out)
        self.status["state"] = "ok" if self.status["unavailable"] == 0 else ("partial" if out or self.status["from_cache"] else "unavailable")
        return out
