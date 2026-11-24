"""Page 6: risk overview and explainability with Contextual Risk Scoring v2.0."""
from __future__ import annotations

import streamlit as st

from risk_analysis.risk_rules import DEFAULT_RULES
from ui.components.common import badge, df, page_header, require_result
from ui.components.memory_panel import LABELS, active_decisions, decisions_panel

ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"]


def render() -> None:
    page_header(
        "Risk & Explainability",
        "Deterministic 4-factor contextual risk scoring (R = 0.15C + 0.20A + 0.35P + 0.30I) and evidence-grounded explanations.",
    )
    r = require_result()
    if not r:
        return

    assess = r.get("risk_assessments", [])
    counts = {l: sum(1 for a in assess if a["label"] == l) for l in ORDER}

    cols = st.columns(5)
    for c, l in zip(cols, ORDER):
        c.metric(badge(l), counts[l])

    vuln_assess = [a for a in assess if a.get("kind") == "vulnerability"]
    elevated = [
        a for a in vuln_assess
        if (a.get("cvss_severity") in ("MEDIUM", "LOW") and a.get("label") in ("CRITICAL", "HIGH"))
        or (a.get("influence_tier") == "heavy" and a.get("priority") in ("P0", "P1"))
    ]
    deprioritized = [
        a for a in vuln_assess
        if a.get("cvss_severity") in ("CRITICAL", "HIGH") and a.get("label") in ("MEDIUM", "LOW", "INFORMATIONAL")
    ]
    heavy_influence = [
        a for a in vuln_assess
        if a.get("influence_tier") == "heavy" or a.get("app_files", 0) >= 5
    ]
    provisional_count = sum(1 for a in vuln_assess if a.get("is_provisional"))

    st.markdown("##### 🎯 Contextual Analysis & Reachability Impact")
    m1, m2, m3, m4 = st.columns(4)
    m1.metric("🔥 Elevated Contextual Risk", len(elevated), help="Low/Medium CVSS elevated to High/Critical due to production presence and high impact")
    m2.metric("💤 Deprioritized (Zero App Usage)", len(deprioritized), help="Critical/High CVSS findings deprioritized due to lack of application or production execution")
    m3.metric("📦 Heavy Production Usage", len(heavy_influence), help="Packages imported across 5+ application files or primary entry points")
    m4.metric("⚠️ Provisional (Missing Evidence)", provisional_count, help="Assessments flagged with incomplete reachability or production evidence (Unknown is not zero)")

    if not assess:
        st.success("No findings to assess.")
        return

    rb = r.get("risk_by_root", [])
    if rb:
        st.markdown("#### Risk by Application Root")
        df([
            {
                "Root": x["root"],
                "Findings": x["findings"],
                "Direct": x["direct"],
                "Transitive": x["transitive"],
                **{l.title(): x["by_risk"][l] for l in ORDER[:4]},
            }
            for x in rb
        ], height=180)

    if r.get("correlations"):
        for corr in r["correlations"]:
            st.warning(f"⚠️ {corr['note']} ({', '.join(corr['finding_ids'])})")

    decided = active_decisions(r)
    st.markdown("#### Finding Risk Explanations")
    a, b, c_inf, d = st.columns([1, 1, 1, 1])
    f_label = a.multiselect("Risk Level", ORDER, default=["CRITICAL", "HIGH"])
    f_kind = b.multiselect("Finding Type", ["vulnerability", "typosquatting", "lockfile_change", "pipeline", "package_risk"])
    f_inf = c_inf.selectbox("Context Filter", ["All Findings", "Elevated by Context", "Deprioritized (Unused)", "Heavy Usage (>=5 files)", "Provisional Assessments"])
    text = d.text_input("Search finding ID or package", placeholder="e.g. lodash...")

    expl = r.get("explanations", {})
    sel = [
        x for x in sorted(assess, key=lambda x: (ORDER.index(x["label"]), -x["score"]))
        if (not f_label or x["label"] in f_label) and (not f_kind or x["kind"] in f_kind)
        and (
            f_inf == "All Findings"
            or (f_inf == "Elevated by Context" and x in elevated)
            or (f_inf == "Deprioritized (Unused)" and x in deprioritized)
            or (f_inf == "Heavy Usage (>=5 files)" and (x.get("influence_tier") == "heavy" or x.get("app_files", 0) >= 5))
            or (f_inf == "Provisional Assessments" and x.get("is_provisional"))
        )
        and (not text or text.lower() in (x["finding_id"] + expl.get(x["finding_id"], {}).get("headline", "")).lower())
    ]

    st.caption(f"Showing {len(sel[:30])} of {len(sel)} finding(s)")
    for a_ in sel[:30]:
        e = expl.get(a_["finding_id"])
        if not e:
            continue
        d_ = decided.get(a_["finding_id"])
        tag = f" · 🔕 {LABELS[d_['decision']]}" if d_ else ""
        inf_tag = ""
        if a_.get("kind") == "vulnerability":
            if a_ in elevated or (a_.get("influence_tier") == "heavy" and a_.get("cvss_severity") in ("MEDIUM", "LOW")):
                inf_tag = " · 🔥 ELEVATED"
            elif a_ in deprioritized or a_.get("influence_tier") == "not_imported":
                inf_tag = " · 💤 DEPRIORITIZED"
            elif a_.get("is_provisional"):
                inf_tag = " · ⚠️ PROVISIONAL"
            elif a_.get("influence_tier") == "heavy":
                inf_tag = f" · 🔥 Heavy Use ({a_.get('app_files', 0)} files)"

        with st.expander(
            f"{badge(a_['label'])} · {a_.get('priority', '')} · {a_['finding_id']} · {e['headline'].split(' - ', 1)[-1]} "
            f"(Score {a_['score']}, confidence {(a_.get('confidence') or {}).get('label', 'n/a')}){inf_tag}{tag}",
            expanded=False,
        ):
            if d_:
                st.info(f"{LABELS[d_['decision']]}: {d_['reason']}" + (f" (expires {d_['expires_at'][:10]})" if d_["expires_at"] else ""))

            if a_.get("kind") == "vulnerability":
                cvss_sev = a_.get("cvss_severity")
                lbl = a_["label"]
                prio = a_.get("priority", "P3")
                app_cnt = a_.get("app_files", 0)

                # Contextual Shift Highlights
                if a_ in elevated or (cvss_sev in ("MEDIUM", "LOW") and lbl in ("CRITICAL", "HIGH")):
                    st.warning(f"⚡ **Elevated by Contextual Risk**: Raw CVSS is **{cvss_sev or 'MEDIUM'}**, but active production presence and high function criticality elevated score to **{a_['score']}/100 ({lbl}, {prio})**.")
                elif a_ in deprioritized or (cvss_sev in ("CRITICAL", "HIGH") and lbl in ("MEDIUM", "LOW")):
                    st.info(f"🛡️ **Deprioritized via Reachability**: Raw CVSS is **{cvss_sev}**, but no application or production execution paths were identified. Risk deprioritized to **{a_['score']}/100 ({lbl}, {prio})**.")

                # Provisional Warning
                if a_.get("is_provisional"):
                    st.warning(f"⚠️ **Incomplete Evidence**: Assessed provisionally using available evidence. Missing dimension(s): **{', '.join(a_.get('missing_dimensions', []))}**. *Unknown is not zero.*")

                # Threat Intelligence Escalations
                if a_.get("threat_intel_escalations"):
                    st.markdown("##### 🚨 Threat Intelligence & Escalation Triggers")
                    for esc in a_["threat_intel_escalations"]:
                        st.caption(f"• {esc}")

                # Contextual 4-Dimension Cards
                dims = a_.get("dimensions") or {}
                if dims:
                    st.markdown("##### 📐 Four-Factor Contextual Model: $R = 0.15C + 0.20A + 0.35P + 0.30I$")
                    c1, c2, c3, c4 = st.columns(4)
                    c_dim = dims.get("C", {})
                    a_dim = dims.get("A", {})
                    p_dim = dims.get("P", {})
                    i_dim = dims.get("I", {})

                    c1.metric("CVSS Severity (C: 15%)", f"{c_dim.get('normalized_score', 0):.1f}/100", help="Raw technical severity normalized (10 x CVSS)")
                    c2.metric("App Reachability (A: 20%)", f"{a_dim.get('normalized_score', 'Unknown')}" + ("/100" if a_dim.get('normalized_score') is not None else ""), help="Application code static import & symbol reachability")
                    c3.metric("Prod Reachability (P: 35%)", f"{p_dim.get('normalized_score', 'Unknown')}" + ("/100" if p_dim.get('normalized_score') is not None else ""), help="Production entry point, container, and deployment execution path")
                    c4.metric("Function Impact (I: 30%)", f"{i_dim.get('normalized_score', 'Unknown')}" + ("/100" if i_dim.get('normalized_score') is not None else ""), help="Function-level responsibility, data sensitivity, boundary, and exposure")

                    # Dimension Table
                    dim_table_data = []
                    for k, d_info in dims.items():
                        norm = d_info.get("normalized_score")
                        norm_str = f"{norm:.1f}" if norm is not None else "Unknown (Missing)"
                        contrib_str = f"{d_info.get('weighted_contribution', 0.0):.1f} pts"
                        dim_table_data.append({
                            "Dimension": f"{k} ({d_info.get('name')})",
                            "Weight": f"{int(d_info.get('weight', 0) * 100)}%",
                            "Normalized (0-100)": norm_str,
                            "Contribution": contrib_str,
                            "Status": d_info.get("status", "unknown"),
                            "Evidence": "; ".join(d_info.get("evidence", [])[:2]),
                        })
                    df(dim_table_data, height=160)

                # Expandable Sub-Factors for Dimension I
                impact = a_.get("impact_breakdown")
                if impact:
                    with st.expander("🔎 Inspect Dimension I Sub-Factors: $I = 0.25F + 0.25S + 0.20B + 0.20D + 0.10X$", expanded=False):
                        r_dict = impact.get("rationale", {})
                        f1, f2, f3 = st.columns(3)
                        f1.metric("Criticality (F: 25%)", f"{impact.get('function_criticality_F', 0):.0f}/100")
                        f2.metric("Data Sensitivity (S: 25%)", f"{impact.get('data_sensitivity_S', 0):.0f}/100")
                        f3.metric("Privilege Boundary (B: 20%)", f"{impact.get('privilege_boundary_B', 0):.0f}/100")

                        f4, f5, _ = st.columns(3)
                        f4.metric("Downstream Impact (D: 20%)", f"{impact.get('downstream_impact_D', 0):.0f}/100")
                        f5.metric("Production Exposure (X: 10%)", f"{impact.get('production_exposure_X', 0):.0f}/100")

                        st.markdown("**Sub-Factor Rationales:**")
                        for k_name, desc in [
                            ("F (Criticality)", r_dict.get("F")),
                            ("S (Data Sensitivity)", r_dict.get("S")),
                            ("B (Privilege Boundary)", r_dict.get("B")),
                            ("D (Downstream Impact)", r_dict.get("D")),
                            ("X (Production Exposure)", r_dict.get("X")),
                        ]:
                            if desc:
                                st.caption(f"• **{k_name}:** {desc}")

            sec = e.get("sections", {})
            st.markdown(f"**Impact:** {sec.get('impact', 'n/a')}")
            st.markdown(f"**How Entered:** {sec.get('how_entered', 'n/a')} ({sec.get('direct_transitive', 'n/a')})")
            st.markdown(f"**Remediation:** {sec.get('remediation', 'n/a')}")

            if a_.get("kind") != "vulnerability" and a_.get("factors"):
                st.markdown("**Scoring Factors**")
                df([{"Factor": f["factor"], "Points": f["points"], "Detail": f["detail"]} for f in a_["factors"]], height=140)

    with st.expander("History & analyst decisions", expanded=False):
        decisions_panel(r)

    with st.expander("Scoring Rules Reference (Contextual Model v2.0)", expanded=False):
        st.json(DEFAULT_RULES)
