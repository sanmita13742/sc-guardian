"""Shared UI helpers and reusable components (kept free of analysis logic).

Minimalist, high-density layout components with strict backward compatibility.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Optional

import pandas as pd
import streamlit as st

from ui.state import get_active_scan
from ui.theme import (RISK_ICON, SEV_BG_COLORS, SEV_BORDER_COLORS, SEV_COLORS, SEV_RANK,
                      severity_pill_html, status_pill_html, text_badge)

# Exported backward-compatible aliases
__all__ = [
    "SEV_COLORS",
    "SEV_BG_COLORS",
    "SEV_BORDER_COLORS",
    "SEV_RANK",
    "RISK_ICON",
    "badge",
    "severity_pill_html",
    "status_pill_html",
    "df",
    "get_result",
    "require_result",
    "page_header",
    "repo_caption",
    "empty_state",
    "metric_group",
    "risk_by_id",
    "download_json",
    "read_file",
    "kv_table",
]


def badge(label: Optional[str]) -> str:
    """Text-compatible badge safe for expanders, metrics, and selects."""
    return text_badge(label)


def df(
    rows: list[dict] | list[list],
    columns: Optional[list[str]] = None,
    height: Optional[int] = None,
    key: Optional[str] = None,
    column_config: Optional[dict[str, Any]] = None,
) -> None:
    """Standardized DataFrame viewer with automatic Arrow serialization guards and column_config support."""
    d = pd.DataFrame(rows, columns=columns) if columns else pd.DataFrame(rows)
    if d.empty:
        st.info("Nothing to show.")
        return

    # Mixed number/text columns (e.g. CVSS "n/a") cannot be Arrow-serialised; convert mixed object columns to text
    for col in d.columns:
        vals = [v for v in d[col] if v is not None and v == v]
        if any(isinstance(v, str) for v in vals) and any(
            isinstance(v, (int, float)) and not isinstance(v, bool) for v in vals
        ):
            d[col] = d[col].map(lambda v: "" if v is None or v != v else str(v))

    if height is None:
        height = "content" if len(d) <= 15 else 400
    elif len(d) <= 8:
        height = "content"

    kwargs: dict[str, Any] = {
        "width": "stretch",
        "hide_index": True,
        "height": height,
        "key": key,
    }
    if column_config:
        kwargs["column_config"] = column_config

    st.dataframe(d, **kwargs)


def get_result() -> Optional[dict]:
    """Retrieve active scan result from session state."""
    return get_active_scan()


def empty_state(
    title: str = "No Active Scan Loaded",
    message: str = "Run a scan on Repository Scan or load a saved scan from the sidebar to inspect results.",
) -> None:
    """Minimalist, compact empty state container."""
    st.markdown(
        f"""
        <div style="border:1px dashed #30363d; border-radius:6px; padding:22px 16px; text-align:center; margin:14px 0; background:rgba(22, 27, 34, 0.4);">
            <div style="font-size:22px; margin-bottom:4px;">🛡️</div>
            <div style="font-weight:600; font-size:14px; color:#e6edf3;">{title}</div>
            <div style="color:#8b949e; font-size:12px; margin-top:2px;">{message}</div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def require_result() -> Optional[dict]:
    """Guard function for pages requiring an active scan."""
    r = get_result()
    if not r or r.get("status") == "failed":
        empty_state(
            title="No Scan Results Loaded",
            message="Select a saved scan from the sidebar or start a new scan on the <b>Repository Scan</b> page.",
        )
        return None
    return r


def repo_caption(r: dict) -> None:
    """Render a compact, high-density repository context chip bar."""
    repo = r.get("repo", {})
    summary = r.get("summary", {})
    name = repo.get("name", "Repository")
    sha = repo.get("commit_sha", "")[:8]
    status = r.get("status", "completed")
    cache_tag = " · ⚡ cached" if r.get("from_cache") else ""
    comps = summary.get("components", len(r.get("components", [])))
    vulns = summary.get("vulnerabilities_confirmed", 0)
    crit = summary.get("by_cvss_severity", {}).get("CRITICAL", 0)
    high = summary.get("by_cvss_severity", {}).get("HIGH", 0)

    unconf = summary.get("vulnerabilities_unknown", 0)
    vuln_summary = f"<b>{vulns + unconf}</b> findings" + (f" ({unconf} unconfirmed)" if unconf else "")
    if crit or high:
        vuln_summary += f" · CVSS <span style='color:#f85149; font-weight:600;'>{crit} critical</span> · <span style='color:#f0883e; font-weight:600;'>{high} high</span>"

    st.markdown(
        f"""
        <div style="border:1px solid #30363d; background:#161b22; border-radius:6px; padding:6px 12px; margin:2px 0 12px 0; font-size:12px; color:#c9d1d9; display:flex; justify-content:space-between; align-items:center; flex-wrap:wrap; gap:6px;">
            <div>🛡️ <b>{name}</b> &nbsp;·&nbsp; <code>{sha}</code>{cache_tag} &nbsp;·&nbsp; {status_pill_html(status)}</div>
            <div>{comps} packages &nbsp;·&nbsp; {vuln_summary}</div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def page_header(
    title: str,
    description: Optional[str] = None,
    r: Optional[dict] = None,
    show_context: bool = True,
) -> None:
    """Minimalist page header with compact title and optional repository context chip."""
    st.markdown(f"### {title}")
    if description:
        st.markdown(
            f"<div style='color:#8b949e; font-size:13px; margin-top:-8px; margin-bottom:8px;'>{description}</div>",
            unsafe_allow_html=True,
        )
    if show_context:
        scan = r or get_result()
        if scan and scan.get("repo"):
            repo_caption(scan)


def metric_group(metrics: list[dict[str, Any]]) -> None:
    """Render a structured row of metrics with optional labels and helper captions."""
    if not metrics:
        return
    cols = st.columns(len(metrics))
    for col, m in zip(cols, metrics):
        col.metric(
            label=m.get("label", ""),
            value=m.get("value", 0),
            delta=m.get("delta"),
            help=m.get("help"),
        )


def risk_by_id(r: dict) -> dict[str, dict]:
    """Map finding_id to its deterministic risk assessment, auto-populating if missing."""
    assessments = r.get("risk_assessments", [])
    if not assessments and r.get("vulnerabilities"):
        try:
            from risk_analysis.finding_correlator import correlate_findings
            from risk_analysis.risk_rules import DEFAULT_RULES
            corr = correlate_findings(
                r.get("vulnerabilities", []),
                r.get("typosquatting", []),
                r.get("lockfile_changes", []),
                r.get("rules", DEFAULT_RULES),
                r.get("pipeline_findings", []),
            )
            assessments = corr.get("assessments", [])
            r["risk_assessments"] = assessments
            r["correlations"] = corr.get("correlations", [])
        except Exception:
            assessments = []
    return {a["finding_id"]: a for a in assessments}


def download_json(label: str, obj: Any, filename: str, key: str) -> None:
    """Download button for JSON payloads."""
    st.download_button(
        label,
        json.dumps(obj, indent=2, default=str),
        file_name=filename,
        mime="application/json",
        key=key,
    )


def read_file(path: Optional[str]) -> Optional[bytes]:
    """Safe binary file reader."""
    try:
        if path and Path(path).exists():
            return Path(path).read_bytes()
    except OSError:
        pass
    return None


def kv_table(d: dict) -> None:
    """Key-value table representation."""
    df(
        [
            {
                "Field": k,
                "Value": (
                    ""
                    if v is None
                    else (json.dumps(v, default=str) if isinstance(v, (dict, list)) else str(v))
                ),
            }
            for k, v in d.items()
        ]
    )
