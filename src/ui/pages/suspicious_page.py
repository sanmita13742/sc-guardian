"""Page 5: suspicious changes (typosquatting + modified lockfiles + autonomous AI investigations)."""
from __future__ import annotations

import json
from pathlib import Path
import streamlit as st

from ui.components.common import badge, df, get_result, page_header, require_result, risk_by_id


def render() -> None:
    page_header("Suspicious Changes", "Forensic threat signals: typosquatting package detection, lockfile modifications, and autonomous AI investigations.")
    r = get_result()

    # Load Phase 2/3 multi-layer investigation artifact if available
    susp_file = Path("suspicious_changes.json")
    susp_data = {}
    if susp_file.exists():
        try:
            susp_data = json.loads(susp_file.read_text(encoding="utf-8"))
        except Exception:
            pass

    scenarios = susp_data.get("correlated_scenarios", [])
    ai_invs = susp_data.get("ai_investigations", [])
    findings = susp_data.get("findings", [])

    if not r and not susp_data:
        require_result()
        return

    if not r and susp_data:
        st.info(f"Displaying results from active forensic scan artifact (`suspicious_changes.json` — {len(findings)} findings). Run a live scan on the **Repository Scan** page to refresh session state.")
        r = {
            "typosquatting": [f for f in findings if f.get("category") == "Typosquatting"],
            "lockfile_changes": [f for f in findings if "lock" in f.get("affected_file", "").lower() or f.get("category") == "Repository Diff"],
            "package_risk": {"findings": [f for f in findings if f.get("category") in ("Lifecycle Script", "Dependency Source", "Docker & CI/CD")]}
        }

    risks = risk_by_id(r) if r else {}
    pkg = (r.get("package_risk") or {}) if r else {}

    tab_titles = [
        f"Typosquatting ({len(r.get('typosquatting', []))})",
        f"Modified Lockfiles ({len(r.get('lockfile_changes', []))})",
        f"Package risk signals ({len(pkg.get('findings', []))})"
    ]
    if ai_invs:
        tab_titles.append(f"Autonomous AI Investigations ({len(ai_invs)})")
    if scenarios:
        tab_titles.append(f"Correlated Scenarios ({len(scenarios)})")

    tabs = st.tabs(tab_titles)
    tab1, tab2, tab3 = tabs[0], tabs[1], tabs[2]
    tab_ai = tabs[3] if len(tabs) > 3 and ai_invs else None
    tab_corr = tabs[4] if len(tabs) > 4 and scenarios else (tabs[3] if len(tabs) > 3 and not ai_invs and scenarios else None)

    with tab3:
        pv = pkg.get("provenance") or {}
        if pv:
            st.caption(f"Build provenance (npm provenance / SLSA attestations) is published for {pv.get('attested', 0)} of {pv.get('with_registry_data', 0)} packages with registry data. "
                       "Presence only - signatures are not cryptographically verified here.")
        pf = pkg.get("findings", [])
        if not pf:
            st.success("No integrity, install-script, recency, deprecation or dependency-confusion signals.")
        else:
            df([{"ID": f.get("finding_id") or f.get("id"), "Severity": f.get("severity"), "Signal": f.get("rule_id") or f.get("category"), "Target": f.get("subject") or f.get("affected_file"), "Finding": f.get("title"), "Risk": risks.get(f.get("finding_id") or f.get("id"), {}).get("label", f.get("severity", ""))} for f in pf], height=300)
            for f in pf[:25]:
                fid = f.get("finding_id") or f.get("id")
                rid = f.get("rule_id") or f.get("category")
                with st.expander(f"{fid} · {rid} · {f.get('title')}", expanded=False):
                    st.markdown(f"**Why it matters / Explanation:** {f.get('why') or f.get('explanation') or f.get('technical_explanation')}")
                    if f.get("remediation") or f.get("recommended_action"):
                        st.markdown(f"**What to do:** {f.get('remediation') or f.get('recommended_action')}")
                    ev = f.get("evidence")
                    if ev:
                        st.code(ev)
                    st.caption(f"Evidence `{f.get('evidence_id') or f.get('evidence_type', 'HEURISTIC')}` · {'directly observed' if f.get('evidence_strength') == 'high' or f.get('evidence_type') == 'OBSERVED_CHANGE' else 'heuristic signal, not proof'}")

    with tab1:
        meta = r.get("typosquatting_meta", {})
        stats = meta.get("stats", {})
        if stats:
            st.caption(f"Checked {stats.get('unique_packages_checked', 0)} packages · {stats.get('candidates', 0)} candidates · {stats.get('suppressed_established', 0)} suppressed (established packages)")

        typo_items = r.get("typosquatting", [])
        if typo_items:
            rows = []
            for t in typo_items:
                rows.append({
                    "Finding": t.get("finding_id") or t.get("id"),
                    "Suspicious Package": t.get("package_name") or t.get("title"),
                    "Target File": t.get("affected_file") or "manifest",
                    "Evidence": t.get("evidence_strength") or t.get("evidence_type", "HEURISTIC"),
                    "Severity": t.get("severity", "MEDIUM")
                })
            df(rows, height=320)

            for t in typo_items:
                fid = t.get("finding_id") or t.get("id")
                pkg_name = t.get("package_name") or t.get("title")
                with st.expander(f"{fid} · {pkg_name}", expanded=False):
                    st.write(t.get("why_flagged") or t.get("explanation") or t.get("technical_explanation"))
                    ev = t.get("evidence")
                    if isinstance(ev, list):
                        for e in ev:
                            st.markdown(f"• {e}")
                    elif isinstance(ev, str):
                        st.code(ev)
        else:
            st.success("No typosquatting candidates detected.")

    with tab2:
        la = r.get("lockfile_analysis", {})
        sm = la.get("summary") or {}
        if sm:
            c = st.columns(5)
            c[0].metric("Commits Inspected", sm.get("commits_analysed", 0))
            c[1].metric("Normal Updates", sm.get("normal_update", 0))
            c[2].metric("Unexplained", sm.get("unexplained_change", 0))
            c[3].metric("Suspicious", sm.get("potentially_suspicious", 0))
            c[4].metric("Baseline Gaps", sm.get("insufficient_baseline", 0))

        changes = la.get("changes", [])
        if changes:
            show_all = st.checkbox("Show normal updates", False)
            rows = [c_ for c_ in changes if show_all or c_["classification"] != "normal_update"]
            st.caption(f"Showing {len(rows)} change(s) of {len(changes)}")
            df([{"Commit": c_["commit"][:8], "Package": c_["package_name"], "Change": c_["change_type"],
                 "Prev": (c_["previous"] or {}).get("version") or "-", "New": (c_["new"] or {}).get("version") or "-",
                 "Classification": c_["classification"].replace("_", " ").title(),
                 "Evidence": c_["evidence_strength"],
                 "Risk": risks.get(c_["finding_id"], {}).get("label", "")} for c_ in rows], height=300)

            for c_ in rows[:20]:
                with st.expander(f"{c_['finding_id']} · {c_['package_name']} ({c_['classification'].replace('_', ' ').title()})", expanded=False):
                    ci = c_.get("commit_info") or {}
                    st.markdown(f"**Commit:** `{c_['commit'][:10]}` — {ci.get('subject', '')} ({ci.get('author', '')})")
                    for why in c_.get("reasons", []):
                        st.markdown(f"• {why}")
                    if c_.get("diff_excerpt"):
                        st.code("\n".join(c_["diff_excerpt"]), language="diff")
        else:
            lock_items = r.get("lockfile_changes", [])
            if lock_items:
                df([{"ID": l.get("id"), "Severity": l.get("severity"), "Title": l.get("title"), "File": l.get("affected_file"), "Origin": l.get("change_origin")} for l in lock_items], height=300)
                for l in lock_items:
                    with st.expander(f"{l.get('id')} · {l.get('title')}", expanded=False):
                        st.markdown(f"**Explanation:** {l.get('explanation')}")
                        st.code(l.get("evidence", ""))
            else:
                st.info("No lockfile change anomalies detected.")

    if tab_ai:
        with tab_ai:
            st.caption(f"LangGraph tool-using autonomous AI investigations ({len(ai_invs)} findings examined). Strictly grounded with zero unverified host breach claims.")
            df([{"Finding ID": inv["finding_id"], "Target File": f"{inv.get('affected_file')}:{inv.get('line_number')}",
                 "Verdict": inv.get("verdict"), "Confidence": inv.get("confidence"),
                 "Planner": inv.get("planner", "deterministic"), "Supporting": len(inv.get("supporting_evidence", [])),
                 "Contradicting": len(inv.get("contradicting_evidence", []))} for inv in ai_invs], height=300)

            for inv in ai_invs:
                v = inv.get("verdict", "UNCONFIRMED")
                v_icon = "🟢" if v == "BENIGN_EXPLANATION" else "🔴" if v == "SUSPECTED_SUPPLY_CHAIN_ATTACK" else "🟡"
                with st.expander(f"{v_icon} {inv['finding_id']} · {v} ({inv.get('confidence')} Confidence)", expanded=False):
                    st.markdown(f"**Rationale:** {inv.get('rationale')}")
                    if inv.get("attack_scenario"):
                        st.markdown(f"**Suspected Attack Narrative:** {inv.get('attack_scenario')}")

                    c1, c2 = st.columns(2)
                    with c1:
                        st.markdown("**Supporting Evidence (Suspicion Factors):**")
                        for se in inv.get("supporting_evidence", []):
                            st.markdown(f"• **{se.get('factor')}:** {se.get('detail')}")
                    with c2:
                        st.markdown("**Contradicting Evidence (Benign Factors):**")
                        for ce in inv.get("contradicting_evidence", []):
                            st.markdown(f"• **{ce.get('factor')}:** {ce.get('detail')}")

                    steps = inv.get("investigation_steps", [])
                    if steps:
                        st.caption(f"Autonomous Tool Trace: {' ➔ '.join([s.get('tool') for s in steps])}")
                    if inv.get("recommended_action"):
                        st.info(f"**Recommended Action:** {inv.get('recommended_action')}")

    if tab_corr:
        with tab_corr:
            st.caption(f"Phase 2 Cross-Signal Multi-Vector Attack Chains ({len(scenarios)} composite scenarios synthesized).")
            for sc in scenarios:
                with st.expander(f"⚠️ {sc.get('composite_id')} · {sc.get('scenario_name')} ({sc.get('severity')})", expanded=True):
                    st.markdown(f"**MITRE ATT&CK Technique:** `{sc.get('attack_technique')}`")
                    st.markdown(f"**Suspected Threat Scenario:** {sc.get('suspected_scenario')}")
                    st.markdown(f"**Contributing Findings:** {', '.join(sc.get('primary_finding_ids', []))}")
                    if sc.get("reasoning_chain"):
                        st.markdown("**Reasoning Chain:**")
                        for step in sc.get("reasoning_chain", []):
                            st.markdown(f"1. {step}")

    if tab_ai:
        with tab_ai:
            st.caption(f"LangGraph tool-using autonomous AI investigations ({len(ai_invs)} findings examined). Strictly grounded with zero unverified host breach claims.")
            df([{"Finding ID": inv["finding_id"], "Target File": f"{inv.get('affected_file')}:{inv.get('line_number')}",
                 "Verdict": inv.get("verdict"), "Confidence": inv.get("confidence"),
                 "Planner": inv.get("planner", "deterministic"), "Supporting": len(inv.get("supporting_evidence", [])),
                 "Contradicting": len(inv.get("contradicting_evidence", []))} for inv in ai_invs], height=300)

            for inv in ai_invs:
                v = inv.get("verdict", "UNCONFIRMED")
                v_icon = "🟢" if v == "BENIGN_EXPLANATION" else "🔴" if v == "SUSPECTED_SUPPLY_CHAIN_ATTACK" else "🟡"
                with st.expander(f"{v_icon} {inv['finding_id']} · {v} ({inv.get('confidence')} Confidence)", expanded=False):
                    st.markdown(f"**Rationale:** {inv.get('rationale')}")
                    if inv.get("attack_scenario"):
                        st.markdown(f"**Suspected Attack Narrative:** {inv.get('attack_scenario')}")

                    c1, c2 = st.columns(2)
                    with c1:
                        st.markdown("**Supporting Evidence (Suspicion Factors):**")
                        for se in inv.get("supporting_evidence", []):
                            st.markdown(f"• **{se.get('factor')}:** {se.get('detail')}")
                    with c2:
                        st.markdown("**Contradicting Evidence (Benign Factors):**")
                        for ce in inv.get("contradicting_evidence", []):
                            st.markdown(f"• **{ce.get('factor')}:** {ce.get('detail')}")

                    steps = inv.get("investigation_steps", [])
                    if steps:
                        st.caption(f"Autonomous Tool Trace: {' ➔ '.join([s.get('tool') for s in steps])}")
                    if inv.get("recommended_action"):
                        st.info(f"**Recommended Action:** {inv.get('recommended_action')}")

    if tab_corr:
        with tab_corr:
            st.caption(f"Phase 2 Cross-Signal Multi-Vector Attack Chains ({len(scenarios)} composite scenarios synthesized).")
            for sc in scenarios:
                with st.expander(f"⚠️ {sc.get('composite_id')} · {sc.get('scenario_name')} ({sc.get('severity')})", expanded=True):
                    st.markdown(f"**MITRE ATT&CK Technique:** `{sc.get('attack_technique')}`")
                    st.markdown(f"**Suspected Threat Scenario:** {sc.get('suspected_scenario')}")
                    st.markdown(f"**Contributing Findings:** {', '.join(sc.get('primary_finding_ids', []))}")
                    if sc.get("reasoning_chain"):
                        st.markdown("**Reasoning Chain:**")
                        for step in sc.get("reasoning_chain", []):
                            st.markdown(f"1. {step}")
