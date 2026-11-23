"""Shared UI helpers (kept free of analysis logic)."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Optional

import pandas as pd
import streamlit as st

SEV_COLORS = {"CRITICAL": "#b42318", "HIGH": "#e5601c", "MEDIUM": "#d4a72c", "LOW": "#4c8bf5", "INFORMATIONAL": "#7a8794", "UNKNOWN": "#7a8794", None: "#7a8794"}
RISK_ICON = {"CRITICAL": "🟥", "HIGH": "🟧", "MEDIUM": "🟨", "LOW": "🟦", "INFORMATIONAL": "⬜"}


def badge(label: Optional[str]) -> str:
    return f"{RISK_ICON.get(label, '⬜')} {label or 'n/a'}"


def df(rows: list[dict] | list[list], columns: Optional[list[str]] = None, height: Optional[int] = None, key: Optional[str] = None) -> None:
    d = pd.DataFrame(rows, columns=columns) if columns else pd.DataFrame(rows)
    if d.empty:
        st.info("Nothing to show.")
        return
    for col in d.columns:  # mixed number/text columns (e.g. CVSS "n/a") cannot be Arrow-serialised; show them as text
        vals = [v for v in d[col] if v is not None and v == v]
        if any(isinstance(v, str) for v in vals) and any(isinstance(v, (int, float)) and not isinstance(v, bool) for v in vals):
            d[col] = d[col].map(lambda v: "" if v is None or v != v else str(v))
    if height is None:
        height = "content" if len(d) <= 15 else 420
    elif len(d) <= 8:
        height = "content"
    st.dataframe(d, width="stretch", hide_index=True, height=height, key=key)


def get_result() -> Optional[dict]:
    return st.session_state.get("result")


def require_result() -> Optional[dict]:
    r = get_result()
    if not r or r.get("status") == "failed":
        st.info("Run a scan on the **Repository Scan** page (or load a previous scan from the sidebar) to see results here.")
        return None
    return r


def repo_caption(r: dict) -> None:
    repo = r["repo"]
    st.caption(f"{repo['name']} · commit `{repo['commit_sha'][:40]}` · scanned {repo['scan_timestamp']}"
               + (" · loaded from cache" if r.get("from_cache") else ""))


def risk_by_id(r: dict) -> dict[str, dict]:
    return {a["finding_id"]: a for a in r.get("risk_assessments", [])}


def download_json(label: str, obj: Any, filename: str, key: str) -> None:
    st.download_button(label, json.dumps(obj, indent=2, default=str), file_name=filename, mime="application/json", key=key)


def read_file(path: Optional[str]) -> Optional[bytes]:
    try:
        if path and Path(path).exists():
            return Path(path).read_bytes()
    except OSError:
        pass
    return None


def kv_table(d: dict) -> None:
    df([{"Field": k, "Value": ("" if v is None else (json.dumps(v, default=str) if isinstance(v, (dict, list)) else str(v)))} for k, v in d.items()])
