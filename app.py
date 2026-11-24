"""SC Guardian - Software Supply Chain Security Scanner (Streamlit Entry Point).

Run:  streamlit run app.py
"""
from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

# Silence harmless WinError 10054 on Windows when browser client disconnects or refreshes
if sys.platform == "win32":
    try:
        from asyncio.proactor_events import _ProactorBasePipeTransport
        _orig_call_connection_lost = _ProactorBasePipeTransport._call_connection_lost

        def _silenced_call_connection_lost(self, exc):
            try:
                _orig_call_connection_lost(self, exc)
            except (ConnectionResetError, OSError):
                try:
                    if self._sock is not None:
                        self._sock.close()
                        self._sock = None
                    if getattr(self, "_server", None) is not None:
                        self._server._detach()
                        self._server = None
                    self._called_connection_lost = True
                except Exception:
                    pass

        _ProactorBasePipeTransport._call_connection_lost = _silenced_call_connection_lost
    except Exception:
        pass

import streamlit as st

sys.path.insert(0, str(Path(__file__).resolve().parent / "src"))  # application packages live in src/

_REQUIRED = ["rapidfuzz", "pandas", "networkx", "pydantic", "requests", "packaging", "jsonschema", "yaml"]
_missing = [m for m in _REQUIRED if importlib.util.find_spec(m) is None]
if _missing:
    _venv_py = Path(__file__).parent / ".venv" / ("Scripts/python.exe" if sys.platform == "win32" else "bin/python")
    st.set_page_config(page_title="SC Guardian", page_icon="🛡️")
    st.error(f"This Streamlit is running in the wrong Python environment (`{sys.prefix}`). Missing packages: {', '.join(_missing)}.")
    st.markdown("Stop the server (Ctrl+C) and start the app with the project's own environment:")
    st.code(f'"{_venv_py}" -m streamlit run app.py', language="bash")
    st.markdown("or run `scripts/run.bat` (Windows) / `scripts/run.sh`. Alternatively: `python -m pip install -r requirements.txt` in the current environment.")
    st.stop()

from ui.pages import (agents_page, graph_page, health_page, monitor_page, architecture_page, pipeline_page, policy_page, reports_page, remediation_page,
                      sbom_page, scan_page, suspicious_page, vulns_page)

# Page configuration
st.set_page_config(
    page_title="SC Guardian",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# Native Streamlit Multi-Page Navigation definition
NAVIGATION_PAGES = {
    "Security Analysis": [
        st.Page(scan_page.render, title="Repository Scan", icon="🛡️", url_path="scan", default=True),
        st.Page(sbom_page.render, title="SBOM Explorer", icon="📦", url_path="sbom"),
        st.Page(graph_page.render, title="Dependency Graph", icon="🕸️", url_path="graph"),
        st.Page(vulns_page.render, title="Vulnerability Findings", icon="🚨", url_path="vulnerabilities"),
        st.Page(pipeline_page.render, title="Pipeline & Containers", icon="🐳", url_path="pipeline"),
        st.Page(suspicious_page.render, title="Suspicious Changes", icon="⚠️", url_path="suspicious"),
        st.Page(remediation_page.render, title="Remediation", icon="🛠️", url_path="remediation"),
        st.Page(policy_page.render, title="Policy & Gate", icon="🚦", url_path="policy"),
    ],
    "Operations": [
        st.Page(agents_page.render, title="Agent Activity", icon="🤖", url_path="agents"),
        st.Page(reports_page.render, title="Reports & Downloads", icon="📄", url_path="reports"),
        st.Page(monitor_page.render, title="Monitoring", icon="📡", url_path="monitoring"),
        st.Page(architecture_page.render, title="Architecture", icon="🏗️", url_path="architecture"),
        st.Page(health_page.render, title="Settings & Health", icon="⚙️", url_path="health"),
    ],
}


def _render_sidebar_context() -> None:
    """Render global brand header and platform note."""
    with st.sidebar:
        st.markdown(
            "<div style='font-size:18px; font-weight:700; color:#e6edf3; display:flex; align-items:center; gap:6px; margin-bottom:12px;'>"
            "🛡️ SC Guardian"
            "</div>",
            unsafe_allow_html=True,
        )
        st.caption("Static analysis · Code is never executed")


def main() -> None:
    _render_sidebar_context()
    pg = st.navigation(NAVIGATION_PAGES)
    pg.run()


if __name__ == "__main__":
    main()
