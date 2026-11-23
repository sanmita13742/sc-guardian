"""Field-level provenance ledger.

Every metadata field of a component records where its value came from. Rules:

* a value from a more trusted source replaces a less trusted one (the displaced value is kept as a *conflict* if it differs)
* a value from a less or equally trusted source never overwrites; if it differs it is recorded as a conflict
* nothing is ever invented: an unknown field stays empty and the engine records *why* it is unknown (``missing_reasons``)

Trust order reflects how directly the source describes *the artifact the repository actually pins*:
lockfile (exact pin) > manifest > registry (authoritative for descriptive data, current not pinned) > scanner > inferred.
"""
from __future__ import annotations

from typing import Any

from core.models import Component

TRUST = {"lockfile": 100, "manifest": 90, "registry": 80, "scanner": 60, "inferred": 20}

# field -> (Component attribute, how to compare/store)
LIST_FIELDS = {"licenses", "hashes", "external_refs"}
FIELDS = ("licenses", "supplier", "description", "scope", "install_script", "deprecated", "published_at", "hashes", "external_refs", "resolved_url", "source_type", "direct_declared")


def _empty(v: Any) -> bool:
    return v is None or v == [] or v == "" or v == {}


def source_class(source: str) -> str:
    return source.split(":", 1)[0]


def trust_of(source: str) -> int:
    return TRUST.get(source_class(source), 0)


def record(c: Component, field: str, source: str, evidence: str = "", confidence: str = "high") -> None:
    c.provenance[field] = {"source": source, "confidence": confidence, "evidence": evidence, "conflicts": c.provenance.get(field, {}).get("conflicts", [])}


def _same(a: Any, b: Any) -> bool:
    if isinstance(a, list) and isinstance(b, list):
        key = lambda x: str(sorted(x.items())) if isinstance(x, dict) else str(x).lower()  # noqa: E731
        return sorted(map(key, a)) == sorted(map(key, b))
    return str(a).strip().lower() == str(b).strip().lower()


def set_field(c: Component, field: str, value: Any, source: str, evidence: str = "", confidence: str = "high") -> bool:
    """Apply ``value`` under the trust rules. Returns True if the component's value changed."""
    if _empty(value):
        return False
    cur = getattr(c, field)
    prov = c.provenance.get(field)
    if _empty(cur):
        setattr(c, field, value)
        record(c, field, source, evidence, confidence)
        return True
    cur_src = (prov or {}).get("source", "scanner")
    if _same(cur, value):
        if prov and trust_of(source) > trust_of(cur_src):  # same value, better witness
            record(c, field, source, evidence, confidence)
        elif prov:
            prov.setdefault("corroborated_by", [])
            if source not in prov["corroborated_by"]:
                prov["corroborated_by"].append(source)
        return False
    conflict = {"source": source, "value": value if not isinstance(value, list) else value[:5]}
    if trust_of(source) > trust_of(cur_src):
        old = {"source": cur_src, "value": cur if not isinstance(cur, list) else cur[:5]}
        setattr(c, field, value)
        record(c, field, source, evidence, confidence)
        c.provenance[field]["conflicts"].append(old)
        return True
    if prov is None:
        record(c, field, cur_src, "", "medium")
        prov = c.provenance[field]
    prov["conflicts"].append(conflict)
    return False


def init_scanner_provenance(c: Component) -> None:
    """Mark values that arrived with the scanner's own SBOM entry so later sources can be ranked against them."""
    tool = (c.sources or ["scanner"])[0]
    for f in FIELDS:
        if not _empty(getattr(c, f, None)) and f not in c.provenance:
            record(c, f, f"scanner:{tool}", "present in the scanner's SBOM entry", "medium")


# ------------------------------------------------------------------ completeness
WEIGHTS = {"licenses": 3, "hashes": 3, "supplier": 1, "description": 1, "external_refs": 1, "scope": 1, "published_at": 1}


def completeness(c: Component) -> float:
    tot = sum(WEIGHTS.values())
    got = sum(w for f, w in WEIGHTS.items() if not _empty(getattr(c, f, None)))
    return round(got / tot, 3)
