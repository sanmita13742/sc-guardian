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
    c[0].metric("Total Findings", len(vulns))
    c[1].metric("Critical · High", f"{sev.get('CRITICAL', 0)} C · {sev.get('HIGH', 0)} H")
    c[2].metric("Direct / Transitive", f"{sm.get('vuln_direct', 0)} / {sm.get('vuln_transitive', 0)}")
    c[3].metric("Fix Available", sm.get("with_fix", 0))
    c[4].metric("Known Exploited (KEV)", sm.get("kev", 0))

    _ground_truth(r)

    if not vulns:
        st.success("No vulnerability findings were produced for the queried packages.")
        return

    with st.expander("Filter Findings", expanded=False):
        a, b, d, e = st.columns(4)
        f_sev = a.multiselect("CVSS Severity", ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"])
        f_eco = b.multiselect("Ecosystem", sorted({v["ecosystem"] for v in vulns}))
        f_dep = d.multiselect("Dependency Type", ["direct", "direct_inferred", "transitive"])
        f_stat = e.multiselect("Status", ["confirmed_affected", "unknown"])
        c1, c2, c3 = st.columns([1, 1, 1])
        f_pkg = c1.text_input("Package contains", placeholder="e.g. lodash")
        f_id = c2.text_input("Vulnerability ID", placeholder="e.g. CVE-2021-...")
        f_fix = c3.checkbox("Fix available only")

    rows = [v for v in vulns if (not f_sev or (v["severity"] or "UNKNOWN") in f_sev)
            and (not f_eco or v["ecosystem"] in f_eco)
            and (not f_dep or v["dependency_type"] in f_dep)
            and (not f_stat or v["affected_status"] in f_stat)
            and (not f_pkg or f_pkg.lower() in v["package_name"].lower())
            and (not f_id or any(f_id.lower() in i.lower() for i in v["vulnerability_ids"]))
            and (not f_fix or v["fixed_versions"])]

    st.caption(f"Showing {len(rows)} of {len(vulns)} findings")
    df([{"ID": v["primary_id"], "Package": v["package_name"], "Installed": v["installed_version"],
         "Ecosystem": v["ecosystem"], "Severity": v["severity"] or "n/a",
         "CVSS": v["cvss_score"] if v["cvss_score"] is not None else "n/a",
         "Fixed in": ", ".join(v["fixed_versions"][:2]) or "none",
         "Type": v["dependency_type"], "Source Pkg": ", ".join(v["source_packages"][:2]) or "self",
         "Verdict": (v.get("verdict") or "").replace("_", " "), "EPSS": f"{v['epss']:.1%}" if v.get("epss") is not None else "n/a",
         "Priority": risks.get(v["finding_id"], {}).get("priority", ""), "Risk": risks.get(v["finding_id"], {}).get("label", "n/a")} for v in rows], height=380)

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

        st.markdown(f"**{v['primary_id']}** — `{v['package_name']}@{v['installed_version']}` ({v['ecosystem']})")
        if v.get("summary"):
            st.caption(v["summary"])

        m1, m2, m3 = st.columns(3)
        m1.markdown(f"**CVSS:** `{v['cvss_score'] or 'n/a'}` ({badge(v['severity'])})  \n**Source:** {v.get('severity_source') or 'n/a'}")
        m2.markdown(f"**Project Risk:** {badge(a.get('label'))} (score {a.get('score', 0)})  \n**Status:** `{v['affected_status']}`")
        m3.markdown(f"**Type:** `{v['dependency_type']}`  \n**Fixed in:** `{', '.join(v['fixed_versions']) or 'None'}`")

        # Dependency path
        path0 = next((p for e_ in v.get("exposures", []) for p in e_.get("paths", [])), [])
        if path0:
            st.markdown(f"**Path:** `{' → '.join(path0)}`")

        inv = (r.get("investigations") or {}).get(v["finding_id"])
        if inv:
            st.markdown("#### Investigation")
            ic = st.columns(4)
            ic[0].metric("Verdict", inv["verdict"].replace("_", " "))
            ic[1].metric("Confidence", f"{inv['confidence']['label']} ({inv['confidence']['score']})")
            ic[2].metric("Priority", a.get("priority", "n/a"))
            ic[3].metric("Reasoned by", "AI (grounded)" if inv.get("ai_assisted") else "rules (deterministic)")
            st.markdown(inv["rationale"])
            llm = inv.get("llm")
            if llm and llm.get("status") == "rejected":
                st.warning("An AI proposal for this finding was rejected by the grounding gate: " + "; ".join(llm.get("problems", [])))
            elif llm and llm.get("status") == "error":
                st.caption(f"AI reasoning unavailable for this finding ({llm.get('error')}); deterministic result shown.")
            with st.expander("How this was determined (tool trace and evidence)"):
                df([{"Step": i + 1, "Tool": s["tool"], "By": s.get("by", "planner"), "Arguments": ", ".join(f"{k}={v}" for k, v in s["args"].items()), "Evidence": s.get("evidence_id") or (s.get("error") or "")}
                    for i, s in enumerate(inv["steps"])], height="content")
                store = {e["id"]: e for e in r.get("evidence_store", [])}
                for eid in inv["evidence_ids"]:
                    e = store.get(eid)
                    if e:
                        st.markdown(f"- `{eid}` - {e['summary']}" + (f" ({e['source']})" if e.get("source") else "") + ("" if e.get("verified", True) else " *(inferred)*"))
                if a.get("confidence"):
                    st.caption("Confidence basis: " + "; ".join(a["confidence"].get("basis", [])))

        if v.get("remediation"):
            st.markdown(f"**Remediation:** {v['remediation']}")

        with st.expander("Advisory References & Raw Fields", expanded=False):
            for u in (v.get("advisory_urls", []) + [x["url"] for x in v.get("references", [])])[:5]:
                st.markdown(f"• {u}")
