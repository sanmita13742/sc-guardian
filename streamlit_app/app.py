"""SC Guardian - repository supply chain security scanner (Streamlit entry point).

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

from ui.pages import agents_page, graph_page, reports_page, risk_page, sbom_page, scan_page, suspicious_page, vulns_page

st.set_page_config(page_title="SC Guardian", page_icon="🛡️", layout="wide")

PAGES = {
    "Repository Scan": scan_page,
    "SBOM Explorer": sbom_page,
    "Dependency Graph": graph_page,
    "Vulnerability Findings": vulns_page,
    "Suspicious Changes": suspicious_page,
    "Risk & Explainability": risk_page,
    "Agent Activity": agents_page,
    "Reports": reports_page,
}


def main() -> None:
    with st.sidebar:
        st.title("🛡️ SC Guardian")
        st.caption("Repository supply chain security scanner")
        page = st.radio("Navigation", list(PAGES), key="page", label_visibility="collapsed")
        r = st.session_state.get("result")
        if r and r.get("status") != "failed":
            st.divider()
            st.caption("Current scan")
            st.write(f"**{r['repo']['name']}**  \n`{r['repo']['commit_sha'][:10]}` · {r['status'].replace('_', ' ')}")
            s = r.get("summary", {})
            st.write(f"{s.get('components', 0)} components · {s.get('vulnerabilities_confirmed', 0)} confirmed vulns")
        st.divider()
        st.caption("Static analysis only. Repository code is never executed. No findings ≠ safe.")
    PAGES[page].render()


main()
