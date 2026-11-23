"""Page 4: vulnerability findings."""
from __future__ import annotations

import streamlit as st

from ui.components.common import badge, df, kv_table, repo_caption, require_result, risk_by_id


def render() -> None:
    st.header("Vulnerability Findings")
    r = require_result()
    if not r:
        return
    repo_caption(r)
    vulns = r.get("vulnerabilities", [])
    risks = risk_by_id(r)
    sm = r["summary"]
    c = st.columns(6)
    sev = sm.get("by_cvss_severity", {})
    c[0].metric("Total", len(vulns))
    c[1].metric("Critical", sev.get("CRITICAL", 0))
    c[2].metric("High", sev.get("HIGH", 0))
    c[3].metric("Medium", sev.get("MEDIUM", 0))
    c[4].metric("Low", sev.get("LOW", 0))
    c[5].metric("No severity", sev.get("UNKNOWN", 0))
    c = st.columns(5)
    c[0].metric("Direct", sm.get("vuln_direct", 0))
    c[1].metric("Transitive", sm.get("vuln_transitive", 0))
    c[2].metric("Fix available", sm.get("with_fix", 0))
    c[3].metric("Known exploited (KEV)", sm.get("kev", 0))
    c[4].metric("Unconfirmed applicability", sm.get("vulnerabilities_unknown", 0))
    st.caption("Severity shown here is the advisory's CVSS severity. Project-specific **risk** (deterministic rules) is on the Risk page and in the Risk column.")
    cov = r.get("vuln_coverage", {})
    st.info(f"Queried {cov.get('queried_unique_packages', 0)} unique packages. Not queried: {cov.get('unscanned_components', 0)} components "
            f"(unsupported ecosystem or no version). Unreachable queries: {cov.get('packages_query_unavailable', 0)}.")
    stt = r.get("source_status", {}).get("OSV", {})
    if stt.get("state") not in ("ok", None):
        st.error(f"OSV status: {stt.get('state')} — results are incomplete. {stt.get('errors', [''])[:1]}")
    if not vulns:
        st.success("No vulnerability findings were produced for the queried packages. This does not prove the repository is free of vulnerabilities.")
        return

    with st.expander("Filters", expanded=True):
        a, b, d, e = st.columns(4)
        f_sev = a.multiselect("CVSS severity", ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"])
        f_eco = b.multiselect("Ecosystem", sorted({v["ecosystem"] for v in vulns}))
        f_dep = d.multiselect("Dependency type", ["direct", "direct_inferred", "transitive", "unknown"])
        f_stat = e.multiselect("Affected status", ["confirmed_affected", "unknown"])
        a, b, d = st.columns(3)
        f_pkg = a.text_input("Package contains")
        f_id = b.text_input("Vulnerability ID (CVE/GHSA)")
        f_fix = d.checkbox("Fix available only")
        f_kev = d.checkbox("Known exploited only")
    rows = [v for v in vulns if (not f_sev or (v["severity"] or "UNKNOWN") in f_sev) and (not f_eco or v["ecosystem"] in f_eco)
            and (not f_dep or v["dependency_type"] in f_dep) and (not f_stat or v["affected_status"] in f_stat)
            and (not f_pkg or f_pkg.lower() in v["package_name"].lower())
            and (not f_id or any(f_id.lower() in i.lower() for i in v["vulnerability_ids"])) and (not f_fix or v["fixed_versions"]) and (not f_kev or v["kev"])]
    st.caption(f"{len(rows)} of {len(vulns)} findings")
    df([{"Finding": v["finding_id"], "ID": v["primary_id"], "CVE": ", ".join(v["cve_ids"]), "Package": v["package_name"], "Installed": v["installed_version"],
         "Ecosystem": v["ecosystem"], "CVSS sev.": v["severity"] or "n/a", "CVSS": v["cvss_score"] if v["cvss_score"] is not None else "n/a",
         "Status": v["affected_status"], "Fixed in": ", ".join(v["fixed_versions"][:3]) or "none recorded", "Dependency": v["dependency_type"],
         "Root": v["root_component"], "KEV": "yes" if v["kev"] else "", "Risk": risks.get(v["finding_id"], {}).get("label", ""),
         "Sources": ", ".join(v["sources"])} for v in rows], height=420)

    if rows:
        st.subheader("Finding details")
        pick = st.selectbox("Finding", [v["finding_id"] for v in rows],
                            format_func=lambda i: next(f"{i} · {v['primary_id']} · {v['package_name']}@{v['installed_version']}" for v in rows if v["finding_id"] == i))
        v = next(x for x in rows if x["finding_id"] == pick)
        a = risks.get(v["finding_id"], {})
        st.markdown(f"### {v['primary_id']} — {v['package_name']} {v['installed_version']}")
        st.write(v.get("summary") or "_No summary in the advisory._")
        c1, c2, c3 = st.columns(3)
        c1.markdown(f"**CVSS severity:** {badge(v['severity'])}  \n**CVSS:** {v['cvss_score'] if v['cvss_score'] is not None else 'n/a'} {('(' + v['cvss_vector'] + ')') if v.get('cvss_vector') else ''}  \n"
                    f"**Severity source:** {v.get('severity_source') or 'n/a'}")
        c2.markdown(f"**Project risk:** {badge(a.get('label'))} (score {a.get('score')})  \n**Affected status:** {v['affected_status']}  \n**Known exploited:** {'yes' if v['kev'] else 'no/unknown'}")
        c3.markdown(f"**Dependency:** {v['dependency_type']}  \n**Service:** {v['service_dir']}  \n**Recommended fix:** {v['recommended_fix'] or 'none recorded'}")
        st.markdown("**All identifiers:** " + ", ".join(v["vulnerability_ids"]))
        st.markdown("**Affected ranges:** " + ("; ".join(v["affected_ranges"]) or "n/a") + f"  \n**Fixed versions:** {', '.join(v['fixed_versions']) or 'none recorded'}")
        st.markdown("**Dependency paths** (relative to each root)")
        for e in v["exposures"]:
            st.write(f"*{e['root']}* — **{e['relationship']}**, depth {e['depth']}; immediate parent(s): {', '.join(e['immediate_parents']) or '—'}")
            for p in e["paths"][:6]:
                st.code(" → ".join(p), language="text")
        if not v["exposures"]:
            st.info("No path from a service root is recorded for this component.")
        st.markdown("**Remediation**  \n" + v["remediation"])
        for n in v["notes"]:
            st.caption("ℹ️ " + n)
        st.markdown("**Advisory sources and references**  \nRetrieved: " + str(v.get("retrieved_at")) + " · Sources: " + ", ".join(v["sources"]))
        for u in (v["advisory_urls"] + [x["url"] for x in v["references"]])[:8]:
            st.markdown(f"- {u}")
        with st.expander("CVSS sources and raw fields"):
            df(v["cvss_sources"])
            kv_table({k: v[k] for k in ("component_ref", "component_refs", "purl", "published", "modified", "scan_timestamp", "affected_status_reason")})
