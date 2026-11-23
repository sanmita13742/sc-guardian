"""Page 7: reports and downloads."""
from __future__ import annotations

import streamlit as st

from reporting import json_exporter, report_generator
from ui.components.common import page_header, read_file, require_result


def render() -> None:
    page_header("Reports & Downloads", "Export security artifacts, download machine-readable JSON feeds, and preview human-readable reports.")
    r = require_result()
    if not r:
        return

    name = r["repo"]["name"]
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
        md = report_generator.generate_markdown(r)
        st.download_button("Download Security Report (Markdown)", md, f"{name}-security-report.md", "text/markdown", key="dl_md", use_container_width=True)
        st.download_button("Download Security Report (HTML)", report_generator.generate_html(r), f"{name}-security-report.html", "text/html", key="dl_html", use_container_width=True)

    with st.expander("Report Preview", expanded=False):
        st.markdown(md)
