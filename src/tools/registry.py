"""Tool registry: small, typed, READ-ONLY functions that agents (deterministic planner or LLM) may call.

A tool receives a ``ToolContext`` (working tree, scan state, evidence store, HTTP client, cache) plus validated keyword arguments, records the
facts it observed in the evidence store and returns a compact JSON-serialisable result containing the evidence ids. Tools never write to the
repository, never execute repository code, and never receive secrets (the context exposes none).
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Optional

from evidence.store import EvidenceStore


@dataclass
class ToolContext:
    repo_dir: Optional[Path]
    evidence: EvidenceStore
    http: Any = None
    cache: Any = None
    state: Any = None  # agents.specialists.ScanState (read-only use)
    limits: dict = field(default_factory=lambda: {"max_snippet_lines": 40, "max_files": 4000, "max_bytes": 2_000_000})


@dataclass
class Tool:
    name: str
    description: str
    params: dict[str, str]  # arg name -> short type/meaning
    fn: Callable[..., dict]

    def schema(self) -> dict:
        return {"name": self.name, "description": self.description, "params": self.params}


REGISTRY: dict[str, Tool] = {}


def tool(name: str, description: str, params: Optional[dict[str, str]] = None):
    def deco(fn: Callable[..., dict]):
        REGISTRY[name] = Tool(name, description, params or {}, fn)
        return fn
    return deco


def catalogue() -> list[dict]:
    return [t.schema() for t in REGISTRY.values()]


def call(ctx: ToolContext, name: str, args: Optional[dict] = None) -> dict:
    """Validated invocation: unknown tools/arguments are rejected; failures come back as {"error": ...} (a tool never raises into an agent)."""
    t = REGISTRY.get(name)
    if t is None:
        return {"error": f"unknown tool '{name}'", "available": sorted(REGISTRY)}
    args = dict(args or {})
    extra = set(args) - set(t.params)
    if extra:
        return {"error": f"unexpected argument(s) {sorted(extra)} for {name}", "expected": list(t.params)}
    try:
        out = t.fn(ctx, **args)
        json.dumps(out, default=str)
        return out
    except Exception as e:  # noqa: BLE001
        return {"error": f"{type(e).__name__}: {str(e)[:200]}"}
