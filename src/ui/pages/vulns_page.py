"""Page 4: vulnerability findings."""
from __future__ import annotations

import streamlit as st

from ui.components.common import badge, df, kv_table, page_header, require_result, risk_by_id


def _ground_truth(r: dict) -> None:
    ver = r.get("verification")
    with st.expander("Ground-Truth Verification & Golden Set", expanded=False):
        if ver:
            c = st.columns(4)
            c[0].metric("Cross-Checked", ver["components_checked"])
            c[1].metric("Routes Agree", ver["routes_agree"])
            c[2].metric("Reproduced", f"{ver['findings_cross_verified']}/{ver['findings_checked']}")
            c[3].metric("Disagreements", ver["disagreement_count"])
            if ver["disagreements"]:
                df(ver["disagreements"], height=160)

        if st.button("Run OSV Golden-Set Known-Answer Test", key="run_gt"):
            from config.settings import get_settings
            from core.http import HttpClient
            from storage.cache import Cache
            from storage.database import Database
            from vulnerability.osv_client import OsvClient
            from vulnerability.verification import run_ground_truth
            with st.spinner("Querying OSV golden set..."):
                st.session_state["gt"] = run_ground_truth(OsvClient(HttpClient(), Cache(Database(get_settings().db_path))))

        gt = st.session_state.get("gt")
        if gt:
            c = st.columns(4)
            c[0].metric("Cases Passed", f"{gt['passed']}/{gt['evaluated']}")
            c[1].metric("Precision", gt["precision"])
            c[2].metric("Recall", gt["recall"])
            c[3].metric("FP / FN", f"{gt['fp']} / {gt['fn']}")


def render() -> None:
    page_header("Vulnerability Findings", "Correlated OSV, NVD (CVSS) and CISA KEV findings with local range validation.")
    r = require_result()
    if not r:
        return

    vulns = r.get("vulnerabilities", [])
    risks = risk_by_id(r)
    sm = r["summary"]
    sev = sm.get("by_cvss_severity", {})

    # Consolidated 5 primary security metrics
    c = st.columns(5)
    unconf = sm.get("vulnerabilities_unknown", 0)
    c[0].metric("Total Findings", len(vulns), help=f"{sm.get('vulnerabilities_confirmed', 0)} confirmed, {unconf} unconfirmed" if unconf else "All findings are confirmed affected")
    c[1].metric("Critical · High (CVSS)", f"{sev.get('CRITICAL', 0)} C · {sev.get('HIGH', 0)} H", help="By the advisory's CVSS severity. The contextual risk below also weighs reachability and production impact.")
    c[2].metric("Findings: Direct / Transitive", f"{sm.get('vuln_direct', 0)} / {sm.get('vuln_transitive', 0)}", help="Counts findings, not packages. The Dependency Graph page counts vulnerable packages.")
    c[3].metric("Fix Available", sm.get("with_fix", 0))
    c[4].metric("Known Exploited (KEV)", sm.get("kev", 0))

    br = sm.get("by_risk") or {}
    if br:
        st.caption("Contextual risk: " + " · ".join(f"{br[k]} {k.lower()}" for k in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL") if br.get(k))
                   + (" · priority " + ", ".join(f"{k} {n}" for k, n in sorted((sm.get("by_priority") or {}).items())) if sm.get("by_priority") else ""))

    _ground_truth(r)

    if not vulns:
        st.success("No vulnerability findings were produced for the queried packages.")
        return

    with st.expander("Filter Findings", expanded=False):
        top_c1, top_c2 = st.columns(2)
        f_asset = top_c1.selectbox("Asset Source", ["All Assets", "Source Dependencies (OSV)", "Container Images (Trivy)"])
        f_pkg_class = top_c2.selectbox("Container Package Class", ["All", "OS Packages (Debian/Alpine/RPM)", "Application Libraries"]) if f_asset != "Source Dependencies (OSV)" else "All"

        a, b, d, e = st.columns(4)
        f_sev = a.multiselect("CVSS Severity", ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"])
        f_eco = b.multiselect("Ecosystem", sorted({v["ecosystem"] for v in vulns}))
        f_dep = d.multiselect("Dependency Type", ["direct", "direct_inferred", "transitive", "container_package"])
        f_stat = e.multiselect("Status", ["confirmed_affected", "unknown"])
        c1, c2, c3 = st.columns([1, 1, 1])
        f_pkg = c1.text_input("Package contains", placeholder="e.g. lodash")
        f_id = c2.text_input("Vulnerability ID", placeholder="e.g. CVE-2021-...")
        f_fix = c3.checkbox("Fix available only")

    rows = [
        v for v in vulns
        if (f_asset == "All Assets" or (f_asset.startswith("Source") and v.get("asset_type", "source_dependency") == "source_dependency") or (f_asset.startswith("Container") and v.get("asset_type") == "container_image"))
        and (f_pkg_class == "All" or (f_pkg_class.startswith("OS") and (v.get("container_details") or {}).get("package_type") == "os_pkg") or (f_pkg_class.startswith("App") and (v.get("container_details") or {}).get("package_type") == "lang_pkg"))
        and (not f_sev or (v["severity"] or "UNKNOWN") in f_sev)
        and (not f_eco or v["ecosystem"] in f_eco)
        and (not f_dep or v["dependency_type"] in f_dep)
        and (not f_stat or v["affected_status"] in f_stat)
        and (not f_pkg or f_pkg.lower() in v["package_name"].lower())
        and (not f_id or any(f_id.lower() in i.lower() for i in v["vulnerability_ids"]))
        and (not f_fix or v["fixed_versions"])
    ]

    st.caption(f"Showing {len(rows)} of {len(vulns)} findings")
    df([{"ID": v["primary_id"], "Package": v["package_name"], "Installed": v["installed_version"],
         "Ecosystem": v["ecosystem"], "Severity": v["severity"] or "n/a",
         "CVSS": v["cvss_score"] if v["cvss_score"] is not None else "n/a",
         "Score": f"{risks[v['finding_id']]['score']}/100" if v["finding_id"] in risks and risks[v["finding_id"]].get("score") is not None else "n/a",
         "Priority": risks.get(v["finding_id"], {}).get("priority", "P3"),
         "Risk": risks.get(v["finding_id"], {}).get("label", "n/a"),
         "Fixed in": ", ".join(v["fixed_versions"][:2]) or "none",
         "Type": v["dependency_type"], "Source Pkg": ", ".join(v["source_packages"][:2]) or "self",
         "Verdict": (v.get("verdict") or "").replace("_", " "), "EPSS": f"{v['epss']:.1%}" if v.get("epss") is not None else "n/a"} for v in rows], height=380)

    if rows:
        st.markdown("#### Finding Detail")
        pick = st.selectbox(
            "Select finding to inspect",
            [v["finding_id"] for v in rows],
            format_func=lambda i: next(f"{v['primary_id']} · {v['package_name']}@{v['installed_version']} ({v['severity'] or 'n/a'})" for v in rows if v["finding_id"] == i),
            label_visibility="collapsed",
        )
        v = next(x for x in rows if x["finding_id"] == pick)
        a = risks.get(v["finding_id"], {})
        score_val = a.get("score")
        score_str = f"{score_val}/100" if score_val is not None else "n/a"

        st.markdown(f"**{v['primary_id']}** · `{v['package_name']}@{v['installed_version']}` · {v['ecosystem']}")
        if v.get("summary"):
            st.caption(v["summary"])

        m = st.columns(4)
        m[0].metric("Severity", v["severity"] or "n/a", help=f"CVSS {v['cvss_score'] if v['cvss_score'] is not None else 'n/a'} · source: {v.get('severity_source') or 'n/a'}")
        m[1].metric("Risk", a.get("label") or "n/a", help="Contextual risk: advisory severity combined with reachability and production impact")
        m[2].metric("Score", score_str)
        m[3].metric("Priority", a.get("priority", "P3"))

        t_over, t_risk, t_inv, t_ref = st.tabs(["Overview", "Risk breakdown", "Investigation", "References"])

        with t_over:
            o1, o2 = st.columns(2)
            o1.markdown(f"**CVSS** `{v['cvss_score'] if v['cvss_score'] is not None else 'n/a'}`  \n**Status** `{v['affected_status']}`  \n**Dependency type** `{v['dependency_type']}`")
            o2.markdown(f"**Fixed in** `{', '.join(v['fixed_versions']) or 'none'}`  \n**Introduced by** `{', '.join(v['source_packages'][:3]) or 'this package'}`")
            path0 = next((p for e_ in v.get("exposures", []) for p in e_.get("paths", [])), [])
            if path0:
                st.markdown("**Dependency path**")
                st.code(" → ".join(path0), language="text")
            if v.get("asset_type") == "container_image":
                cd = v.get("container_details") or {}
                st.markdown("**Container asset**")
                df([{"Image": cd.get("image_name", "n/a"), "Layer": cd.get("target", "n/a"),
                     "Package type": "Operating system package" if cd.get("package_type") == "os_pkg" else "Application library",
                     "Dockerfile": cd.get("source_file", "n/a")}], height="content")
            if v.get("remediation"):
                st.markdown("**Recommended fix**")
                st.markdown(v["remediation"])

        with t_risk:
            dims = a.get("dimensions") or {}
            if not dims:
                st.caption("No risk breakdown is available for this finding.")
            else:
                def _fmt(d: dict) -> str:
                    n = d.get("normalized_score")
                    return f"{n:.0f}/100" if isinstance(n, (int, float)) else "unknown"
                labels = [("C", "Advisory severity", "15%", "CVSS severity of the advisory, normalised to 0-100"),
                          ("A", "Application reachability", "20%", "Whether application code imports or calls the vulnerable package"),
                          ("P", "Production reachability", "35%", "Whether it ships in a production entry point, container or deployment"),
                          ("I", "Function impact", "30%", "Responsibility, data sensitivity, trust boundary and exposure of the code that uses it")]
                df([{"Factor": name, "Weight": w, "Score": _fmt(dims.get(k, {})), "Measures": desc} for k, name, w, desc in labels], height="content")
                st.caption(f"Result: **{a.get('label', 'UNKNOWN')}** · {score_str} · priority {a.get('priority', 'P3')}"
                           + (" · provisional, some evidence is missing" if a.get("provisional") or a.get("is_provisional") else ""))
                if a.get("confidence"):
                    st.caption("Confidence basis: " + "; ".join(a["confidence"].get("basis", [])))

        with t_inv:
            inv = (r.get("investigations") or {}).get(v["finding_id"])
            if not inv:
                st.caption("This finding was not investigated (investigation disabled or not required).")
            else:
                ic = st.columns(3)
                ic[0].metric("Verdict", inv["verdict"].replace("_", " "))
                ic[1].metric("Confidence", f"{inv['confidence']['label']} ({inv['confidence']['score']})")
                ic[2].metric("Reasoned by", "AI (grounded)" if inv.get("ai_assisted") else "Rules")
                st.markdown(inv["rationale"])
                llm = inv.get("llm")
                if llm and llm.get("status") == "rejected":
                    st.warning("An AI proposal for this finding was rejected by the grounding gate: " + "; ".join(llm.get("problems", [])))
                elif llm and llm.get("status") == "error":
                    st.caption(f"AI reasoning unavailable for this finding ({llm.get('error')}); deterministic result shown.")
                with st.expander("Tool trace and evidence"):
                    df([{"Step": n + 1, "Tool": s["tool"], "By": s.get("by", "planner"), "Arguments": ", ".join(f"{k}={val}" for k, val in s["args"].items()), "Evidence": s.get("evidence_id") or (s.get("error") or "")}
                        for n, s in enumerate(inv["steps"])], height="content")
                    store = {e["id"]: e for e in r.get("evidence_store", [])}
                    for eid in inv["evidence_ids"]:
                        e = store.get(eid)
                        if e:
                            st.markdown(f"- `{eid}` · {e['summary']}" + (f" ({e['source']})" if e.get("source") else "") + ("" if e.get("verified", True) else " *(inferred)*"))

        with t_ref:
            urls = (v.get("advisory_urls", []) + [x["url"] for x in v.get("references", [])])[:8]
            if urls:
                for u in urls:
                    st.markdown(f"- {u}")
            else:
                st.caption("No advisory links recorded.")
