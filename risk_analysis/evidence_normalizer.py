"""Flatten evidence bundles into a uniform fact list + a text corpus used to ground/validate explanations."""
from __future__ import annotations

import json
from typing import Any


def _flatten(prefix: str, value: Any, out: list[tuple[str, str]]) -> None:
    if value is None or value == "" or value == [] or value == {}:
        return
    if isinstance(value, dict):
        for k, v in value.items():
            _flatten(f"{prefix}.{k}" if prefix else str(k), v, out)
    elif isinstance(value, (list, tuple)):
        for i, v in enumerate(value):
            if isinstance(v, (dict, list)):
                _flatten(f"{prefix}[{i}]", v, out)
            else:
                out.append((prefix, str(v)))
    else:
        out.append((prefix, str(value)))


def normalize_bundle(bundle: dict) -> dict:
    """Return the bundle plus ``facts`` [{id, path, value}] and ``corpus`` (lower-cased text of every fact value)."""
    facts: list[tuple[str, str]] = []
    _flatten("", {k: v for k, v in bundle.items() if k not in ("facts", "corpus")}, facts)
    fl = [{"id": f"F{i + 1:03d}", "path": p, "value": v} for i, (p, v) in enumerate(facts)]
    corpus = "\n".join(f["value"] for f in fl).lower()
    return {**bundle, "facts": fl, "corpus": corpus}


def compact_for_llm(bundle: dict, max_facts: int = 120) -> str:
    """Compact JSON of the bundle for prompts (facts only, no corpus duplication)."""
    b = {k: v for k, v in bundle.items() if k not in ("facts", "corpus")}
    s = json.dumps(b, default=str, ensure_ascii=False)
    return s[:12000]
