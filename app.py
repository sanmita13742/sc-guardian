"""SC Guardian - Software Supply Chain Security Scanner (Streamlit Entry Point).

Run:  streamlit run app.py
"""
from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import streamlit as st

_REQUIRED = ["rapidfuzz", "pandas", "networkx", "pydantic", "requests", "packaging", "jsonschema", "yaml"]
_missing = [m for m in _REQUIRED if importlib.util.find_spec(m) is None]
if _missing:
    _venv_py = Path(__file__).parent / ".venv" / ("Scripts/python.exe" if sys.platform == "win32" else "bin/python")
    st.set_page_config(page_title="SC Guardian", page_icon="🛡️")
    st.error(f"This Streamlit is running in the wrong Python environment (`{sys.prefix}`). Missing packages: {', '.join(_missing)}.")
    st.markdown("Stop the server (Ctrl+C) and start the app with the project's own environment:")
    st.code(f'"{_venv_py}" -m streamlit run app.py', language="bash")
    st.markdown("or run `run.bat` (Windows) / `./run.sh`. Alternatively: `python -m pip install -r requirements.txt` in the current environment.")
    st.stop()

from ui.pages import (agents_page, graph_page, health_page, monitor_page, pipeline_page, policy_page, reports_page, remediation_page, risk_page,
                      sbom_page, scan_page, suspicious_page, vulns_page)
from ui.state import get_active_scan, list_recent_scans, load_scan_from_db
from ui.theme import status_pill_html

# Page configuration
st.set_page_config(
    page_title="SC Guardian",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# Backward-compatible dictionary mapping
PAGES = {
    "Repository Scan": scan_page,
    "SBOM Explorer": sbom_page,
    "Dependency Graph": graph_page,
    "Vulnerability Findings": vulns_page,
    "Pipeline & Containers": pipeline_page,
    "Suspicious Changes": suspicious_page,
    "Risk & Explainability": risk_page,
    "Remediation": remediation_page,
    "Policy & Gate": policy_page,
    "Monitoring": monitor_page,
    "Agent Activity": agents_page,
    "Reports": reports_page,
}

# Native Streamlit Multi-Page Navigation definition
NAVIGATION_PAGES = {
    "Security Analysis": [
        st.Page(scan_page.render, title="Repository Scan", icon="🛡️", url_path="scan", default=True),
        st.Page(sbom_page.render, title="SBOM Explorer", icon="📦", url_path="sbom"),
        st.Page(graph_page.render, title="Dependency Graph", icon="🕸️", url_path="graph"),
        st.Page(vulns_page.render, title="Vulnerability Findings", icon="🚨", url_path="vulnerabilities"),
        st.Page(pipeline_page.render, title="Pipeline & Containers", icon="🐳", url_path="pipeline"),
        st.Page(suspicious_page.render, title="Suspicious Changes", icon="⚠️", url_path="suspicious"),
        st.Page(risk_page.render, title="Risk & Explainability", icon="🧭", url_path="risk"),
        st.Page(remediation_page.render, title="Remediation", icon="🛠️", url_path="remediation"),
        st.Page(policy_page.render, title="Policy & Gate", icon="🚦", url_path="policy"),
    ],
    "Operations": [
        st.Page(agents_page.render, title="Agent Activity", icon="🤖", url_path="agents"),
        st.Page(reports_page.render, title="Reports & Downloads", icon="📄", url_path="reports"),
        st.Page(monitor_page.render, title="Monitoring", icon="📡", url_path="monitoring"),
        st.Page(health_page.render, title="Settings & Health", icon="⚙️", url_path="health"),
    ],
}


def _render_sidebar_context() -> None:
    """Render global brand header, active scan context, and quick scan switcher."""
    with st.sidebar:
        st.markdown(
            "<div style='font-size:18px; font-weight:700; color:#e6edf3; display:flex; align-items:center; gap:6px;'>"
            "🛡️ SC Guardian"
            "</div>"
            "<div style='font-size:11px; color:#8b949e; margin-bottom:10px;'>"
            "Supply Chain Security Platform"
            "</div>",
            unsafe_allow_html=True,
        )

        r = get_active_scan()
        if r:
            repo = r.get("repo", {})
            sm = r.get("summary", {})
            sha = (repo.get("commit_sha") or "")[:8]
            status = r.get("status", "completed")
            cached = " ⚡" if r.get("from_cache") else ""
            vulns = sm.get("vulnerabilities_confirmed", 0)
            comps = sm.get("components", 0)
            st.markdown(
                f"<div style='border:1px solid #30363d; background:#161b22; border-radius:6px; padding:6px 10px; margin-bottom:8px; font-size:12px; color:#c9d1d9;'>"
                f"<b>{repo.get('name', 'Repository')}</b> <code>{sha}</code>{cached}<br>"
                f"<span style='color:#8b949e;'>{comps} packages · <b>{vulns}</b> vulns</span> · {status_pill_html(status)}"
                f"</div>",
                unsafe_allow_html=True,
            )

        scans = list_recent_scans(10)
        if scans:
            scan_opts = {s["scan_id"]: f"{s['repo_name']} ({s['commit_sha'][:7]})" for s in scans}
            current_id = (r.get("repo", {}).get("scan_id") if r else "")
            picked = st.selectbox(
                "Saved Scans",
                options=list(scan_opts.keys()),
                index=list(scan_opts.keys()).index(current_id) if current_id in scan_opts else 0,
                format_func=lambda sid: scan_opts[sid],
                key="sidebar_scan_picker",
                label_visibility="collapsed",
            )
            if picked and picked != current_id:
                if st.button("Load scan", key="btn_sidebar_load", use_container_width=True):
                    load_scan_from_db(picked)
                    st.rerun()

        st.caption("Static analysis · Code is never executed")


def main() -> None:
    _render_sidebar_context()
    pg = st.navigation(NAVIGATION_PAGES)
    pg.run()


if __name__ == "__main__":
    main()
