"""SC Guardian - repository supply chain security scanner (Streamlit entry point).

Run:  streamlit run app.py
"""
from __future__ import annotations

import streamlit as st

from ui.pages import graph_page, reports_page, risk_page, sbom_page, scan_page, suspicious_page, vulns_page

st.set_page_config(page_title="SC Guardian", page_icon="🛡️", layout="wide")

PAGES = {
    "Repository Scan": scan_page,
    "SBOM Explorer": sbom_page,
    "Dependency Graph": graph_page,
    "Vulnerability Findings": vulns_page,
    "Suspicious Changes": suspicious_page,
    "Risk & Explainability": risk_page,
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
