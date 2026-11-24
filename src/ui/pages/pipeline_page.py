"""Pipeline & Containers: Multi-CI workflows, container assets, base images, and security hygiene."""
from __future__ import annotations

import streamlit as st

from ui.components.common import badge, df, page_header, require_result

SEV_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
ICON = {"CRITICAL": "🟥", "HIGH": "🟧", "MEDIUM": "🟨", "LOW": "🟦", "INFO": "⬜"}
PLATFORM_BADGES = {
    "github_actions": "GitHub Actions",
    "gitlab_ci": "GitLab CI/CD",
    "jenkins": "Jenkins",
    "circleci": "CircleCI",
    "azure_pipelines": "Azure Pipelines",
    "generic_ci": "Generic CI",
}


def render() -> None:
    page_header(
        "Pipeline & Containers",
        "Static multi-CI platform analysis (GitHub Actions, GitLab CI, Jenkins, CircleCI, Azure Pipelines) and container security.",
    )
    r = require_result()
    if not r:
        return
    p = r.get("pipeline") or {}
    sm = p.get("summary") or {}
    if not p or not (p.get("files") or p.get("findings")):
        st.info("No Dockerfile, docker-compose file or CI/CD workflow was found in this repository.")
        return

    c = st.columns(5)
    c[0].metric("Files Analysed", sm.get("files_analysed", 0))
    c[1].metric("Security Findings", sm.get("findings", 0))
    c[2].metric("Critical / High", sum(sm.get("by_severity", {}).get(k, 0) for k in ("CRITICAL", "HIGH")))
    c[3].metric("Container Assets", len(p.get("container_assets") or p.get("images") or []))
    c[4].metric("Actions / Tasks", len(p.get("actions") or []))

    risks = {a["finding_id"]: a for a in r.get("risk_assessments", [])}
    t_find, t_ci, t_containers, t_act, t_files = st.tabs([
        "Findings",
        "Multi-CI Platforms",
        "Container Assets",
        "CI Actions & Tasks",
        "Coverage",
    ])

    with t_find:
        f1, f2, f3 = st.columns([1, 1, 2])
        sev = f1.multiselect("Severity", SEV_ORDER, default=[s for s in SEV_ORDER if s in ("CRITICAL", "HIGH", "MEDIUM")])
        all_ecos = sorted({f.get("ecosystem", "CI") for f in p.get("findings", [])})
        ecos = f2.multiselect("Ecosystem", all_ecos)
        text = f3.text_input("Search rule, file or text", placeholder="e.g. GHA001, GL001, JNK001, Dockerfile ...")

        rows = [
            f for f in p.get("findings", [])
            if (not sev or f.get("severity") in sev)
            and (not ecos or f.get("ecosystem") in ecos)
            and (not text or text.lower() in (f.get("rule_id", "") + f.get("file", "") + f.get("title", "") + f.get("snippet", "")).lower())
        ]
        st.caption(f"Showing {len(rows)} of {len(p.get('findings', []))} findings")
        df(
            [
                {
                    "ID": f["finding_id"],
                    "Severity": f"{ICON.get(f.get('severity', ''), '')} {f.get('severity', '')}",
                    "Platform": f.get("ecosystem", "CI"),
                    "Rule": f.get("rule_id", ""),
                    "Finding": f.get("title", ""),
                    "Where": f"{f.get('file', '')}:{f.get('line', '')}" if f.get("line") else f.get("file", ""),
                    "Risk": (risks.get(f["finding_id"]) or {}).get("label", ""),
                }
                for f in rows
            ],
            height=360,
        )
        if rows:
            pick = st.selectbox(
                "Details",
                [f["finding_id"] for f in rows],
                format_func=lambda i: next(f"{i} - {f['title']}" for f in rows if f["finding_id"] == i),
            )
            f = next(x for x in rows if x["finding_id"] == pick)
            a = risks.get(pick)
            st.markdown(
                f"**{f['title']}**  \n`{f['file']}"
                + (f":{f['line']}" if f.get("line") else "")
                + "`"
                + (f" · risk {badge(a['label'])} (score {a['score']})" if a else "")
            )
            if f.get("snippet"):
                st.code(f["snippet"], language="dockerfile" if f.get("category") == "container" else "yaml")
            st.markdown(f"**Why it matters:** {f.get('why', '')}")
            st.markdown(f"**How to fix:** {f.get('remediation', '')}")
            if f.get("references"):
                st.caption("References: " + " · ".join(f["references"]))
            st.caption(f"Evidence `{f.get('evidence_id')}` · {'directly visible in the file' if f.get('evidence_strength') == 'high' else 'pattern-based (heuristic)'}")

    with t_ci:
        st.markdown("#### Discovered CI/CD Pipelines")
        ci_files = [fi for fi in p.get("files", []) if "pipeline" in fi.get("type", "").lower() or "workflow" in fi.get("type", "").lower() or fi.get("type") == "CI"]
        if not ci_files:
            st.info("No CI/CD pipeline definitions discovered.")
        else:
            col_left, col_right = st.columns([1, 2])
            selected_ci = col_left.radio(
                "Select Pipeline File",
                [fi["file"] for fi in ci_files],
                format_func=lambda path: f"{path} ({next(fi.get('type') for fi in ci_files if fi['file'] == path)})",
            )
            with col_right:
                ci_item = next((fi for fi in ci_files if fi["file"] == selected_ci), None)
                if ci_item:
                    st.markdown(f"### `{selected_ci}`")
                    st.markdown(f"**Platform Type:** `{ci_item.get('type')}` · **Status:** `{ci_item.get('status')}`")

                    # Show associated findings
                    file_findings = [f for f in p.get("findings", []) if f.get("file") == selected_ci]
                    st.markdown(f"**Security Findings:** {len(file_findings)}")
                    for ff in file_findings:
                        st.markdown(f"- {ICON.get(ff.get('severity', ''), '')} **{ff.get('rule_id')}**: {ff.get('title')}")

                    # Show discovered container build directives
                    dbuilds = [b for b in p.get("docker_builds", []) if b.get("ci_file") == selected_ci]
                    if dbuilds:
                        st.markdown("#### Extracted Container Build Directives")
                        df(
                            [
                                {
                                    "Dockerfile": b.get("dockerfile_path"),
                                    "Target Tag": b.get("image_tag") or "(not tagged)",
                                    "Context": b.get("context_path", "."),
                                    "Builder Tool": b.get("builder_tool", "docker"),
                                    "Job": b.get("ci_job", ""),
                                }
                                for b in dbuilds
                            ],
                            height=180,
                        )

    with t_containers:
        st.markdown("#### Discovered Container Assets")
        c_assets = p.get("container_assets") or []
        if not c_assets:
            # Fall back to base images if container_assets not yet present
            imgs = p.get("images") or []
            df(
                [
                    {
                        "Image": i["ref"],
                        "Registry class": i["kind"],
                        "Tag": i.get("tag") or "(none)",
                        "Digest-pinned": "yes" if i.get("digest") else "no",
                        "Where": f"{i['file']}:{i['line']}",
                    }
                    for i in imgs
                ],
                height=300,
            )
        else:
            df(
                [
                    {
                        "Source File": a.get("source_file"),
                        "Source Type": a.get("source_type"),
                        "Target Tag": a.get("image_tag") or "(none)",
                        "Base Image": f"{a.get('base_image', '')}:{a.get('base_image_tag', '')}" if a.get("base_image") else "(none)",
                        "Stages": ", ".join(a.get("stage_names", [])) or "single",
                        "Linked CI Jobs": ", ".join(a.get("associated_ci_jobs", [])) or "none",
                        "Scan Status": a.get("scan_status", "pending"),
                    }
                    for a in c_assets
                ],
                height=320,
            )

        # Show container vulnerabilities if scanned
        cont_findings = p.get("container_findings") or [v for v in r.get("vulnerabilities", []) if v.get("asset_type") == "container_image"]
        if cont_findings:
            st.markdown("#### Container Image Vulnerabilities (Trivy)")
            df(
                [
                    {
                        "ID": cf.get("primary_id"),
                        "Package": cf.get("package_name"),
                        "Installed": cf.get("installed_version"),
                        "Severity": cf.get("severity"),
                        "CVSS": cf.get("cvss_score") or "n/a",
                        "Class": (cf.get("container_details") or {}).get("package_type", "os_pkg"),
                        "Image": (cf.get("container_details") or {}).get("image_name", ""),
                        "Fixed in": ", ".join(cf.get("fixed_versions", [])[:2]) or "none",
                    }
                    for cf in cont_findings
                ],
                height=260,
            )

    with t_act:
        st.markdown("#### CI Actions, Orbs, and External Tasks")
        acts = p.get("actions") or []
        df(
            [
                {
                    "Type": a.get("kind", "action"),
                    "Reference": a.get("name", "") + (a.get("path") or "") or a.get("task", "") or a.get("ref", ""),
                    "Pinned": "yes" if a.get("pinned") else "no",
                    "Job": a.get("job", ""),
                    "File": f"{a.get('file', '')}:{a.get('line', '')}" if a.get("line") else a.get("file", ""),
                }
                for a in acts
            ],
            height=300,
        )

    with t_files:
        st.markdown("#### File Coverage")
        df(p.get("files") or [], height=300)
