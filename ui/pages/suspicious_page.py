"""Page 5: suspicious changes (typosquatting + modified lockfiles)."""
from __future__ import annotations

import streamlit as st

from ui.components.common import badge, df, page_header, require_result, risk_by_id


def render() -> None:
    page_header("Suspicious Changes", "Forensic threat signals: typosquatting package detection and lockfile modifications across Git history.")
    r = require_result()
    if not r:
        return

    risks = risk_by_id(r)
    pkg = (r.get("package_risk") or {})
    tab1, tab2, tab3 = st.tabs([f"Typosquatting ({len(r['typosquatting'])})", f"Modified Lockfiles ({len(r['lockfile_changes'])})", f"Package risk signals ({len(pkg.get('findings', []))})"])

    with tab3:
        pv = pkg.get("provenance") or {}
        if pv:
            st.caption(f"Build provenance (npm provenance / SLSA attestations) is published for {pv.get('attested', 0)} of {pv.get('with_registry_data', 0)} packages with registry data. "
                       "Presence only - signatures are not cryptographically verified here.")
        pf = pkg.get("findings", [])
        if not pf:
            st.success("No integrity, install-script, recency, deprecation or dependency-confusion signals.")
        else:
            df([{"ID": f["finding_id"], "Severity": f["severity"], "Signal": f["rule_id"], "Package": f["subject"], "Finding": f["title"], "Risk": risks.get(f["finding_id"], {}).get("label", "")} for f in pf], height=300)
            for f in pf[:25]:
                with st.expander(f"{f['finding_id']} · {f['rule_id']} · {f['title']}", expanded=False):
                    st.markdown(f"**Why it matters:** {f['why']}")
                    st.markdown(f"**What to do:** {f['remediation']}")
                    st.caption(f"Evidence `{f.get('evidence_id')}` · {'directly observed' if f['evidence_strength'] == 'high' else 'heuristic signal, not proof'}")

    with tab1:
        meta = r.get("typosquatting_meta", {})
        stats = meta.get("stats", {})
        st.caption(f"Checked {stats.get('unique_packages_checked', 0)} packages · {stats.get('candidates', 0)} candidates · {stats.get('suppressed_established', 0)} suppressed (established packages)")

        if r["typosquatting"]:
            df([{"Finding": t["finding_id"], "Suspicious Package": t["package_name"], "Similar To": t["similar_to"],
                 "Similarity": f"{t['similarity_score']}%", "Edit Distance": t["edit_distance"],
                 "Techniques": ", ".join(t["techniques"]), "Evidence": t["evidence_strength"],
                 "Risk": risks.get(t["finding_id"], {}).get("label", "")} for t in r["typosquatting"]], height=320)

            for t in r["typosquatting"]:
                with st.expander(f"{t['finding_id']} · {t['package_name']} ≈ {t['similar_to']} ({t['similarity_score']}%)", expanded=False):
                    st.write(t["why_flagged"])
                    for e in t["evidence"]:
                        st.markdown(f"• {e}")
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

        show_all = st.checkbox("Show normal updates", False)
        changes = la.get("changes", [])
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
