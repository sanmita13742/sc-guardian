"""Page 7: reports and downloads."""
from __future__ import annotations

import streamlit as st

from reporting import json_exporter, report_generator
from ui.components.common import read_file, repo_caption, require_result


def render() -> None:
    st.header("Reports and Downloads")
    r = require_result()
    if not r:
        return
    repo_caption(r)
    name = r["repo"]["name"]
    st.write("All exports include the repository URL, exact commit SHA, scan timestamp and tool versions.")
    c1, c2 = st.columns(2)
    sbom = read_file(r.get("sbom_path"))
    with c1:
        if sbom:
            st.download_button("⬇ CycloneDX SBOM (JSON, original Syft output)", sbom, f"{name}-sbom.cdx.json", "application/json", key="dl_sbom")
        else:
            st.caption("CycloneDX SBOM: not available for this scan (Syft SBOM missing).")
        st.download_button("⬇ Dependency graph (JSON)", json_exporter.dumps(json_exporter.graph_export(r)), f"{name}-dependency-graph.json", "application/json", key="dl_graph2")
        st.download_button("⬇ Vulnerability findings (JSON)", json_exporter.dumps(json_exporter.vulnerability_export(r)), f"{name}-vulnerabilities.json", "application/json", key="dl_vuln")
    with c2:
        st.download_button("⬇ Suspicious-change findings (JSON)", json_exporter.dumps(json_exporter.suspicious_export(r)), f"{name}-suspicious-changes.json", "application/json", key="dl_susp")
        st.download_button("⬇ Consolidated report (JSON)", json_exporter.dumps(json_exporter.consolidated_export(r)), f"{name}-consolidated.json", "application/json", key="dl_cons")
        md = report_generator.generate_markdown(r)
        st.download_button("⬇ Human-readable report (Markdown)", md, f"{name}-security-report.md", "text/markdown", key="dl_md")
        st.download_button("⬇ Human-readable report (HTML)", report_generator.generate_html(r), f"{name}-security-report.html", "text/html", key="dl_html")
    if r.get("artifacts"):
        with st.expander("Files written on the server"):
            st.json(r["artifacts"])
    with st.expander("Report preview", expanded=True):
        st.markdown(md)
