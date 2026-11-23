"""Syft CycloneDX adapter: Syft already emits one component per package occurrence with ``syft:location:N:path`` properties."""
from __future__ import annotations

NAME = "syft"


def _prop(c: dict, name: str) -> list[str]:
    return [p.get("value", "") for p in c.get("properties", []) or [] if isinstance(p, dict) and p.get("name") == name]


def canonicalize(raw: dict) -> dict:
    return raw


def locations(c: dict) -> list[str]:
    out = []
    for i in range(20):
        v = _prop(c, f"syft:location:{i}:path")
        if not v:
            break
        out.append(v[0])
    return out


def found_by(c: dict):
    return (_prop(c, "syft:package:foundBy") or [None])[0]
