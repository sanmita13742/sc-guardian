"""Adapter for documents written by the built-in rule engine (``sc-guardian:*`` properties)."""
from __future__ import annotations

NAME = "builtin"


def _prop(c: dict, name: str) -> list[str]:
    return [p.get("value", "") for p in c.get("properties", []) or [] if isinstance(p, dict) and p.get("name") == name]


def canonicalize(raw: dict) -> dict:
    return raw


def locations(c: dict) -> list[str]:
    out = []
    for i in range(20):
        v = _prop(c, f"sc-guardian:location:{i}:path")
        if not v:
            break
        out.append(v[0])
    return out


def found_by(c: dict):
    return (_prop(c, "sc-guardian:package:foundBy") or [None])[0]
