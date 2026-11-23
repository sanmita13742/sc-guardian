"""Evidence store: every fact an agent uses is an Evidence record with a stable id; claims must cite ids.

Ids are readable and deterministic (``kind:subject``) so a report line like "reachable [reach:lodash@src/app.js:12]" can be traced back.
The store is per scan and is persisted inside the scan result (``result["evidence_store"]``).
"""
from __future__ import annotations

import hashlib
import json
import time
from dataclasses import asdict, dataclass, field
from typing import Any, Iterable, Optional


@dataclass
class Evidence:
    id: str
    kind: str  # osv | cross-check | reachability | epss | kev | registry | provenance | dockerfile | workflow | lockfile | policy | what-if | sandbox | git
    tool: str
    subject: str  # package / file / finding id
    summary: str
    data: dict[str, Any] = field(default_factory=dict)
    source: Optional[str] = None  # URL or file:line
    retrieved_at: str = field(default_factory=lambda: time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))
    verified: bool = True  # False = inferred (heuristic / AI), True = directly observed from a source

    def to_dict(self) -> dict:
        return asdict(self)


class EvidenceStore:
    def __init__(self) -> None:
        self._items: dict[str, Evidence] = {}

    def add(self, kind: str, tool: str, subject: str, summary: str, data: Optional[dict] = None, source: Optional[str] = None, verified: bool = True) -> str:
        h = hashlib.sha1(json.dumps([kind, subject, summary, data or {}], sort_keys=True, default=str).encode()).hexdigest()[:6]
        eid = f"{kind}:{subject}#{h}"
        if eid not in self._items:
            self._items[eid] = Evidence(eid, kind, tool, subject, summary[:400], data or {}, source, verified=verified)
        return eid

    def get(self, eid: str) -> Optional[Evidence]:
        return self._items.get(eid)

    def for_subject(self, subject: str) -> list[Evidence]:
        return [e for e in self._items.values() if e.subject == subject]

    def many(self, ids: Iterable[str]) -> list[Evidence]:
        return [self._items[i] for i in ids if i in self._items]

    def exists(self, eid: str) -> bool:
        return eid in self._items

    def to_list(self) -> list[dict]:
        return [e.to_dict() for e in self._items.values()]

    @classmethod
    def from_list(cls, rows: list[dict]) -> "EvidenceStore":
        s = cls()
        for r in rows or []:
            s._items[r["id"]] = Evidence(**r)
        return s

    def __len__(self) -> int:
        return len(self._items)
