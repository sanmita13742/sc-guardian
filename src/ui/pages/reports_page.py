"""Page 7: reports and downloads."""
from __future__ import annotations

import streamlit as st

import json

from config.settings import get_settings
from reporting import json_exporter, report_generator
from reporting.sarif import to_sarif
from reporting.vex import to_vex
from storage.database import Database
from storage.memory import Memory
from ui.components.common import page_header, read_file, require_result


def render() -> None:
    page_header("Reports & Downloads", "Export security artifacts, download machine-readable JSON feeds, and preview human-readable reports.")
    r = require_result()
    if not r:
        return

    name = r["repo"]["name"]
    try:
        mem = Memory(Database(get_settings().db_path))
        extras = {"decisions": mem.decisions(r["repo"]["url"]), "approvals": mem.approvals(r["repo"]["url"]), "audit": mem.audit_log(r["repo"]["url"], 30)}
    except Exception:  # noqa: BLE001
        extras = {}
    c1, c2 = st.columns(2)
    sbom = read_file(r.get("sbom_path"))

    with c1:
        if sbom:
            st.download_button("Download CycloneDX SBOM (JSON)", sbom, f"{name}-sbom.cdx.json", "application/json", key="dl_sbom", use_container_width=True)
        else:
            st.caption("CycloneDX SBOM artifact not available.")
        st.download_button("Download Dependency Graph (JSON)", json_exporter.dumps(json_exporter.graph_export(r)), f"{name}-dependency-graph.json", "application/json", key="dl_graph2", use_container_width=True)
        st.download_button("Download Vulnerability Findings (JSON)", json_exporter.dumps(json_exporter.vulnerability_export(r)), f"{name}-vulnerabilities.json", "application/json", key="dl_vuln", use_container_width=True)

    with c2:
        st.download_button("Download Suspicious Changes (JSON)", json_exporter.dumps(json_exporter.suspicious_export(r)), f"{name}-suspicious-changes.json", "application/json", key="dl_susp", use_container_width=True)
        st.download_button("Download Consolidated Report (JSON)", json_exporter.dumps(json_exporter.consolidated_export(r)), f"{name}-consolidated.json", "application/json", key="dl_cons", use_container_width=True)
        md = report_generator.generate_markdown(r, extras)
        st.download_button("Download Guardian Report (Markdown)", md, f"{name}-guardian-report.md", "text/markdown", key="dl_md", use_container_width=True)
        st.download_button("Download Guardian Report (HTML)", report_generator.generate_html(r, extras), f"{name}-guardian-report.html", "text/html", key="dl_html", use_container_width=True)
    st.markdown("**Machine-readable security exchange formats**")
    d1, d2, d3 = st.columns(3)
    d1.download_button("SARIF 2.1.0 (code scanning)", json_exporter.dumps(to_sarif(r)), f"{name}.sarif", "application/sarif+json", key="dl_sarif", use_container_width=True)
    d2.download_button("CycloneDX VEX (exploitability)", json_exporter.dumps(to_vex(r, extras.get("decisions"))), f"{name}.vex.json", "application/json", key="dl_vex", use_container_width=True)
    if r.get("policy_result"):
        d3.download_button("Policy gate result (JSON)", json.dumps(r["policy_result"], indent=2, default=str), f"{name}-policy.json", "application/json", key="dl_pol", use_container_width=True)

    with st.expander("Report Preview", expanded=False):
        st.markdown(md)
