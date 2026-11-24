"""Page 5: Suspicious Changes & Autonomous Forensic Investigations.

Integrates Person 2 (Phases 1, 2, 3):
- Layer 1: Deterministic Forensic Evidence (29 findings across Git Diff, Manifests, Lifecycle Scripts, Dependency Sources, CI/CD, Containers, Typosquatting).
- Layer 2: Correlated Attack Chains (Multi-vector scenario synthesis).
- Layer 3: Autonomous AI Investigations (LangGraph tool-using investigator with Grounding Gate).
- Backward-compatible support for core package risk signals and live repository scans.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List
import streamlit as st

from ui.components.common import badge, df, get_result, page_header, require_result, risk_by_id


def render() -> None:
    page_header(
        "Suspicious Changes & Forensic Investigation",
        "Multi-layer supply chain anomaly detection beyond conventional CVE/NVD databases (Person 2 - Phases 1, 2 & 3)."
    )

    r = get_result()

    # Load Phase 2/3 multi-layer investigation artifact
    susp_file = Path("suspicious_changes.json")
    susp_data: Dict[str, Any] = {}
    if r and r.get("suspicious_changes"):
        susp_data = r["suspicious_changes"]
    elif susp_file.exists():
        try:
            susp_data = json.loads(susp_file.read_text(encoding="utf-8"))
        except Exception:
            susp_data = {}

    findings: List[Dict[str, Any]] = susp_data.get("findings", [])
    scenarios: List[Dict[str, Any]] = susp_data.get("correlated_scenarios", [])
    ai_invs: List[Dict[str, Any]] = susp_data.get("ai_investigations", [])
    metrics: Dict[str, Any] = susp_data.get("metrics", {})

    if not r and not susp_data:
        require_result()
        return

    # Build fast lookup map for AI investigations
    ai_map: Dict[str, Dict[str, Any]] = {inv["finding_id"]: inv for inv in ai_invs if "finding_id" in inv}

    # Extract legacy signals if available
    risks = risk_by_id(r) if r else {}
    pkg = (r.get("package_risk") or {}) if r else {}
    pkg_findings = pkg.get("findings", [])

    # --------------------------------------------------------------------------------------------------
    # Top Metrics Banner
    # --------------------------------------------------------------------------------------------------
    total_count = len(findings) if findings else len(pkg_findings)
    introduced_count = sum(1 for f in findings if f.get("change_origin") == "INTRODUCED_IN_RANGE")
    high_crit_count = sum(1 for f in findings if f.get("severity") in ("CRITICAL", "HIGH"))
    scenarios_count = len(scenarios)
    ai_count = len(ai_invs)

    benign_ai = sum(1 for inv in ai_invs if inv.get("verdict") == "BENIGN_EXPLANATION")
    anomaly_ai = sum(1 for inv in ai_invs if inv.get("verdict") == "CONFIRMED_ANOMALY")
    attack_ai = sum(1 for inv in ai_invs if inv.get("verdict") == "SUSPECTED_SUPPLY_CHAIN_ATTACK")

    m_cols = st.columns(5)
    m_cols[0].metric("Total Findings", total_count, help="All deterministic forensic indicators discovered across diffs, manifests, scripts, CI/CD and sources.")
    m_cols[1].metric("Introduced in Diff", introduced_count, help="Findings introduced in the analyzed Git commit range vs pre-existing in baseline.")
    m_cols[2].metric("High / Critical", high_crit_count, help="Findings with high or critical potential supply chain impact.")
    m_cols[3].metric("Correlated Scenarios", scenarios_count, help="Multi-vector attack chains synthesizing disparate indicators.")
    m_cols[4].metric("AI Disambiguated", ai_count, f"{benign_ai} Safe · {anomaly_ai} Anomaly · {attack_ai} Attack", help="Findings autonomously investigated by AI agent.")

    st.markdown("---")

    # --------------------------------------------------------------------------------------------------
    # Multi-Layer Tabs Definition
    # --------------------------------------------------------------------------------------------------
    tab_titles = [
        f"🌟 Unified View ({total_count})",
        f"🤖 Autonomous AI Investigations ({ai_count})",
        f"⛓️ Correlated Attack Chains ({scenarios_count})",
        f"🔬 Deterministic Forensic Evidence ({total_count})",
    ]
    if pkg_findings:
        tab_titles.append(f"📦 Package Risk Signals ({len(pkg_findings)})")

    tabs = st.tabs(tab_titles)
    tab_unified = tabs[0]
    tab_ai = tabs[1]
    tab_corr = tabs[2]
    tab_det = tabs[3]
    tab_pkg = tabs[4] if len(tabs) > 4 else None

    # ==================================================================================================
    # TAB 1: Unified Multi-Layer View
    # ==================================================================================================
    with tab_unified:
        st.markdown("#### Complete Multi-Layer Supply Chain Findings")
        st.caption("Consolidates Layer 1 deterministic facts, Layer 2 correlated attack chains, and Layer 3 autonomous AI verdicts.")

        # Interactive Filters
        f_col1, f_col2, f_col3, f_col4 = st.columns([2, 1, 1, 1])
        search_query = f_col1.text_input("🔍 Search findings (ID, file, code, or explanation)", "", key="uni_search")

        categories = ["All"] + sorted(list({f.get("category", "") for f in findings if f.get("category")}))
        cat_filter = f_col2.selectbox("Category", categories, key="uni_cat")

        severities = ["All", "HIGH", "MEDIUM", "LOW"]
        sev_filter = f_col3.selectbox("Severity", severities, key="uni_sev")

        verdicts = ["All", "BENIGN_EXPLANATION", "CONFIRMED_ANOMALY", "SUSPECTED_SUPPLY_CHAIN_ATTACK", "NOT_INVESTIGATED"]
        verdict_filter = f_col4.selectbox("AI Verdict", verdicts, key="uni_verdict")

        # Apply Filters
        filtered = []
        for f in findings:
            fid = f.get("id", "")
            f_cat = f.get("category", "")
            f_sev = f.get("severity", "")
            f_file = f.get("affected_file", "")
            f_ev = str(f.get("evidence", ""))
            f_exp = str(f.get("explanation") or f.get("technical_explanation") or "")
            ai_data = ai_map.get(fid)
            ai_v = ai_data.get("verdict") if ai_data else "NOT_INVESTIGATED"

            if search_query:
                sq = search_query.lower()
                if not (sq in fid.lower() or sq in f_file.lower() or sq in f_ev.lower() or sq in f_exp.lower()):
                    continue
            if cat_filter != "All" and f_cat != cat_filter:
                continue
            if sev_filter != "All" and f_sev != sev_filter:
                continue
            if verdict_filter != "All":
                if verdict_filter == "NOT_INVESTIGATED" and ai_data:
                    continue
                if verdict_filter != "NOT_INVESTIGATED" and ai_v != verdict_filter:
                    continue
            filtered.append(f)

        st.caption(f"Showing **{len(filtered)}** of **{len(findings)}** findings matching filters.")

        # Summary Dataframe
        if filtered:
            table_rows = []
            for f in filtered:
                fid = f.get("id", "")
                ai_data = ai_map.get(fid)
                table_rows.append({
                    "Finding ID": fid,
                    "Category": f.get("category", ""),
                    "Initial Static Severity": f.get("severity", ""),
                    "Target File": f"{f.get('affected_file', '')}:{f.get('line_number', 1)}",
                    "Origin": f.get("change_origin", "PRE_EXISTING"),
                    "Autonomous AI Verdict": ai_data.get("verdict", "—") if ai_data else "— (Uninvestigated)",
                    "AI Confidence": ai_data.get("confidence", "—") if ai_data else "—",
                })
            df(table_rows, height=280)

            # Detailed Finding Cards
            st.markdown("##### Detailed Forensic Evidence & AI Analysis")
            for f in filtered:
                fid = f.get("id", "")
                f_title = f.get("title", fid)
                f_sev = f.get("severity", "MEDIUM")
                f_cat = f.get("category", "")
                f_orig = f.get("change_origin", "PRE_EXISTING")
                ai_data = ai_map.get(fid)

                # Clear status badge explaining Static Scan vs AI Disambiguation
                if ai_data:
                    v = ai_data.get("verdict")
                    if v == "BENIGN_EXPLANATION":
                        status_tag = f"🟢 [DISAMBIGUATED SAFE] (Static: {f_sev})"
                    elif v == "SUSPECTED_SUPPLY_CHAIN_ATTACK":
                        status_tag = f"🔴 [SUSPECTED ATTACK] (Static: {f_sev})"
                    else:
                        status_tag = f"🟡 [CONFIRMED ANOMALY] (Static: {f_sev})"
                    exp_title = f"{status_tag} `{fid}` · {f_title}"
                else:
                    icon = "🔴" if f_sev == "HIGH" else "🟡" if f_sev == "MEDIUM" else "🔵"
                    exp_title = f"{icon} [{f_sev}] `{fid}` · {f_title}"

                with st.expander(exp_title, expanded=False):
                    c1, c2, c3 = st.columns(3)
                    c1.markdown(f"**Category:** `{f_cat}`")
                    c2.markdown(f"**Target:** `{f.get('affected_file')}:{f.get('line_number')}`")
                    c3.markdown(f"**Origin:** `{'INTRODUCED IN COMMIT RANGE' if f_orig == 'INTRODUCED_IN_RANGE' else 'PRE-EXISTING IN REPOSITORY'}`")

                    # Evidence snippet
                    ev = f.get("evidence")
                    if ev:
                        st.markdown("**Deterministic Forensic Evidence Excerpt:**")
                        st.code(ev if isinstance(ev, str) else "\n".join(ev), language="text")

                    # Technical explanations
                    exp_text = f.get("technical_explanation") or f.get("explanation")
                    if exp_text:
                        st.markdown(f"**Technical Explanation:** {exp_text}")
                    if f.get("potential_impact"):
                        st.markdown(f"**Potential Supply Chain Impact:** {f.get('potential_impact')}")
                    if f.get("recommended_action"):
                        st.info(f"**Recommended Action / Remediation:** {f.get('recommended_action')}")

                    # AI Investigation Layer (if investigated)
                    if ai_data:
                        st.markdown("---")
                        st.markdown("#### 🤖 Autonomous AI Investigator Judgement (Layer 3)")
                        v = ai_data.get("verdict", "UNCONFIRMED")
                        conf = ai_data.get("confidence", "UNKNOWN")
                        planner = ai_data.get("planner", "deterministic")

                        if v == "BENIGN_EXPLANATION":
                            st.success(f"**AI Verdict: SAFE / LEGITIMATE ({v})** ({conf} Confidence) · Verified by Grounding Gate")
                            st.info(f"💡 **False Alarm Resolved by AI:** The deterministic static scanner flagged this pattern as **{f_sev}** severity based on generic heuristic rules. The autonomous AI investigated the actual codebase, imports, and package history, proving this is a legitimate safe dependency and eliminating the false alarm.")
                        elif v == "SUSPECTED_SUPPLY_CHAIN_ATTACK":
                            st.error(f"**AI Verdict: SUSPECTED SUPPLY CHAIN ATTACK ({v})** ({conf} Confidence) · Elevated from Static `{f_sev}`")
                        else:
                            st.warning(f"**AI Verdict: CONFIRMED ANOMALY ({v})** ({conf} Confidence) · Non-Standard Configuration")

                        st.markdown(f"**Investigator Rationale:** {ai_data.get('rationale')}")

                        if ai_data.get("attack_scenario"):
                            st.warning(f"**Suspected Attack Scenario:** {ai_data.get('attack_scenario')}")

                        # Supporting vs Contradicting Factors
                        col_sup, col_con = st.columns(2)
                        with col_sup:
                            st.markdown("**Supporting Evidence (Suspicion Indicators):**")
                            for se in ai_data.get("supporting_evidence", []):
                                st.markdown(f"• **{se.get('factor')}:** {se.get('detail')}")
                        with col_con:
                            st.markdown("**Contradicting Evidence (Safe / Legitimate Indicators):**")
                            for ce in ai_data.get("contradicting_evidence", []):
                                st.markdown(f"• **{ce.get('factor')}:** {ce.get('detail')}")

                        # Collapsible Tool Execution Trace
                        steps = ai_data.get("investigation_steps", [])
                        if steps:
                            with st.expander(f"🔍 Autonomous Investigation Steps ({len(steps)} steps)", expanded=False):
                                for s_idx, stp in enumerate(steps, 1):
                                    st.markdown(f"**Step {s_idx}: `{stp.get('tool')}`**")
                                    args_str = json.dumps(stp.get("args", {}), indent=2)
                                    st.caption(f"Inputs: `{args_str}`")
                                    res_str = str(stp.get("result", ""))
                                    if len(res_str) > 300:
                                        res_str = res_str[:300] + "... [truncated]"
                                    st.code(res_str, language="json" if "{" in res_str else "text")

    # ==================================================================================================
    # TAB 2: Autonomous AI Investigations (Layer 3)
    # ==================================================================================================
    with tab_ai:
        st.markdown("#### Autonomous AI Investigations (LangGraph Agent)")
        st.caption(
            f"**{len(ai_invs)}** high-priority findings investigated autonomously using read-only Git, AST, and filesystem tools. "
            "All findings pass a strict Grounding Gate: zero unverified host breach claims, citations must match observed files, "
            "and verdicts strictly follow allowed vocabulary."
        )

        if ai_invs:
            ai_table = []
            for inv in ai_invs:
                ai_table.append({
                    "Finding ID": inv.get("finding_id"),
                    "Target": f"{inv.get('affected_file')}:{inv.get('line_number')}",
                    "Verdict": inv.get("verdict"),
                    "Confidence": inv.get("confidence"),
                    "Planner Model": inv.get("planner", "Gemini 2.5 Flash Lite"),
                    "Supporting Factors": len(inv.get("supporting_evidence", [])),
                    "Contradicting Factors": len(inv.get("contradicting_evidence", [])),
                })
            df(ai_table, height=280)

            st.markdown("##### Detailed Investigation Cards")
            for inv in ai_invs:
                v = inv.get("verdict", "UNCONFIRMED")
                fid = inv.get("finding_id", "")
                conf = inv.get("confidence", "UNKNOWN")
                icon = "🟢" if v == "BENIGN_EXPLANATION" else "🔴" if v == "SUSPECTED_SUPPLY_CHAIN_ATTACK" else "🟡"

                with st.expander(f"{icon} `{fid}` · {v} ({conf} Confidence)", expanded=False):
                    c1, c2 = st.columns(2)
                    c1.markdown(f"**Target File:** `{inv.get('affected_file')}:{inv.get('line_number')}`")
                    c2.markdown(f"**Planner Model:** `{inv.get('planner', 'Gemini 2.5 Flash Lite')}`")

                    st.markdown(f"**Autonomous Rationale:** {inv.get('rationale')}")

                    if inv.get("attack_scenario"):
                        st.error(f"**Suspected Attack Scenario:** {inv.get('attack_scenario')}")

                    cs1, cs2 = st.columns(2)
                    with cs1:
                        st.markdown("**Supporting Evidence (Suspicion Factors):**")
                        for se in inv.get("supporting_evidence", []):
                            st.markdown(f"• **{se.get('factor')}:** {se.get('detail')}")
                    with cs2:
                        st.markdown("**Contradicting Evidence (Safe / Legitimate Factors):**")
                        for ce in inv.get("contradicting_evidence", []):
                            st.markdown(f"• **{ce.get('factor')}:** {ce.get('detail')}")

                    # Collapsible Tool Execution Trace
                    steps = inv.get("investigation_steps", [])
                    if steps:
                        with st.expander(f"🔍 Autonomous Investigation Steps ({len(steps)} steps)", expanded=False):
                            for s_idx, stp in enumerate(steps, 1):
                                st.markdown(f"**Step {s_idx}: `{stp.get('tool')}`**")
                                st.caption(f"Inputs: `{json.dumps(stp.get('args', {}))}`")
                                res_str = str(stp.get("result", ""))
                                if len(res_str) > 300:
                                    res_str = res_str[:300] + "... [truncated]"
                                st.code(res_str, language="text")

                    if inv.get("recommended_action"):
                        st.info(f"**Recommended Action:** {inv.get('recommended_action')}")
        else:
            st.info("No autonomous AI investigations available.")

    # ==================================================================================================
    # TAB 3: Correlated Attack Chains (Layer 2)
    # ==================================================================================================
    with tab_corr:
        st.markdown("#### Correlated Attack Chains (Multi-Vector Scenarios)")
        st.caption(
            f"**{len(scenarios)}** multi-vector attack scenarios synthesized by correlating disparate indicators "
            "(e.g., combining Docker base image drift, unpinned CI actions, and unverified registry mirrors)."
        )

        if scenarios:
            for sc in scenarios:
                with st.expander(f"⚠️ `{sc.get('composite_id')}` · {sc.get('scenario_name')} ({sc.get('severity')})", expanded=True):
                    st.markdown(f"**MITRE ATT&CK Technique:** `{sc.get('attack_technique')}`")
                    st.markdown(f"**Suspected Scenario Narrative:** {sc.get('suspected_scenario')}")
                    st.markdown(f"**Contributing Findings:** `{', '.join(sc.get('primary_finding_ids', []))}`")

                    if sc.get("reasoning_chain"):
                        st.markdown("**Step-by-Step Reasoning Chain:**")
                        for step_no, step in enumerate(sc.get("reasoning_chain", []), 1):
                            st.markdown(f"{step_no}. {step}")
        else:
            st.info("No correlated attack chains synthesized for this scan.")

    # ==================================================================================================
    # TAB 4: Deterministic Forensic Evidence (Layer 1)
    # ==================================================================================================
    with tab_det:
        st.markdown("#### Layer 1 Deterministic Forensic Evidence")
        st.caption("Direct static findings from repository diffs, manifest verifiers, AST lifecycle scripts, CI/CD linters, and typosquatting detectors.")

        cat_names = sorted(list({f.get("category", "") for f in findings if f.get("category")}))
        if cat_names:
            sub_tabs = st.tabs([f"{cat} ({sum(1 for f in findings if f.get('category') == cat)})" for cat in cat_names])
            for idx, cat in enumerate(cat_names):
                with sub_tabs[idx]:
                    cat_findings = [f for f in findings if f.get("category") == cat]
                    cat_rows = []
                    for cf in cat_findings:
                        cat_rows.append({
                            "ID": cf.get("id"),
                            "Severity": cf.get("severity"),
                            "Target": f"{cf.get('affected_file')}:{cf.get('line_number')}",
                            "Origin": cf.get("change_origin"),
                            "Confidence": cf.get("confidence"),
                        })
                    df(cat_rows, height=240)

                    for cf in cat_findings:
                        with st.expander(f"[{cf.get('severity')}] {cf.get('id')} · {cf.get('title')}", expanded=False):
                            st.markdown(f"**File:** `{cf.get('affected_file')}:{cf.get('line_number')}`")
                            st.markdown(f"**Explanation:** {cf.get('technical_explanation') or cf.get('explanation')}")
                            if cf.get("evidence"):
                                st.code(cf.get("evidence"), language="text")
                            if cf.get("recommended_action"):
                                st.info(f"**Remediation:** {cf.get('recommended_action')}")
        else:
            st.info("No deterministic forensic findings recorded.")

    # ==================================================================================================
    # TAB 5: Package Risk Signals (Legacy / Core Scanner)
    # ==================================================================================================
    if tab_pkg and pkg_findings:
        with tab_pkg:
            st.markdown("#### Core Scanner Package Risk Signals")
            st.caption("Registry integrity, install-script presence, and deprecation signals from the core scan pipeline.")

            pv = pkg.get("provenance") or {}
            if pv:
                st.caption(f"Build provenance published for {pv.get('attested', 0)} of {pv.get('with_registry_data', 0)} packages with registry data.")

            pkg_rows = []
            for pf in pkg_findings:
                fid = pf.get("finding_id") or pf.get("id")
                pkg_rows.append({
                    "ID": fid,
                    "Severity": pf.get("severity"),
                    "Signal": pf.get("rule_id") or pf.get("category"),
                    "Target": pf.get("subject") or pf.get("affected_file"),
                    "Finding": pf.get("title"),
                    "Risk": risks.get(fid, {}).get("label", pf.get("severity", ""))
                })
            df(pkg_rows, height=280)

            for pf in pkg_findings[:20]:
                fid = pf.get("finding_id") or pf.get("id")
                rid = pf.get("rule_id") or pf.get("category")
                with st.expander(f"{fid} · {rid} · {pf.get('title')}", expanded=False):
                    st.markdown(f"**Why it matters:** {pf.get('why') or pf.get('explanation')}")
                    if pf.get("remediation"):
                        st.markdown(f"**What to do:** {pf.get('remediation')}")
                    if pf.get("evidence"):
                        st.code(pf.get("evidence"))
