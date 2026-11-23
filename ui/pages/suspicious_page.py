"""Page 5: suspicious changes (typosquatting + modified lockfiles)."""
from __future__ import annotations

import streamlit as st

from ui.components.common import badge, df, repo_caption, require_result, risk_by_id


def render() -> None:
    st.header("Suspicious Changes")
    r = require_result()
    if not r:
        return
    repo_caption(r)
    st.caption("Both detectors report **signals with evidence**. Neither name similarity nor a lockfile modification proves malicious intent.")
    risks = risk_by_id(r)
    tab1, tab2 = st.tabs([f"Typosquatting ({len(r['typosquatting'])})", f"Modified lockfiles ({len(r['lockfile_changes'])})"])
    with tab1:
        meta = r.get("typosquatting_meta", {})
        st.write(f"Checked {meta.get('stats', {}).get('unique_packages_checked', 0)} unique packages against curated popular-package lists "
                 f"(`{meta.get('stats', {}).get('reference_version')}`); {meta.get('stats', {}).get('candidates', 0)} similarity candidates, "
                 f"{meta.get('stats', {}).get('suppressed_established', 0)} suppressed because registry data shows an established package.")
        if r["typosquatting"]:
            df([{"Finding": t["finding_id"], "Suspicious package": t["package_name"], "Ecosystem": t["ecosystem"], "Similar known package": t["similar_to"],
                 "Similarity": f"{t['similarity_score']}%", "Edit distance": t["edit_distance"], "Techniques": ", ".join(t["techniques"]), "Evidence": t["evidence_strength"],
                 "Dependency": t["dependency_type"], "Risk": risks.get(t["finding_id"], {}).get("label", "")} for t in r["typosquatting"]])
            for t in r["typosquatting"]:
                with st.expander(f"{t['finding_id']} · {t['package_name']} ≈ {t['similar_to']} · {t['evidence_strength']} evidence"):
                    st.write(t["why_flagged"])
                    st.markdown("**Evidence**")
                    for e in t["evidence"]:
                        st.markdown(f"- {e}")
                    st.markdown(f"**Reference set:** {t['reference_source']}  \n**Versions:** {', '.join(t['versions'])}  \n**Services:** {', '.join(t['services'])}")
                    for cv in t["caveats"]:
                        st.caption("⚠️ " + cv)
        else:
            st.success("No typosquatting candidates were flagged (this is a name-similarity check against a curated list, not a guarantee).")
        if meta.get("suppressed"):
            with st.expander(f"Suppressed candidates ({len(meta['suppressed'])})"):
                df(meta["suppressed"])
    with tab2:
        la = r.get("lockfile_analysis", {})
        for lim in la.get("limitations", []):
            st.warning(lim)
        sm = la.get("summary") or {}
        if sm:
            c = st.columns(5)
            c[0].metric("Commits analysed", sm.get("commits_analysed", 0))
            c[1].metric("Normal updates", sm.get("normal_update", 0))
            c[2].metric("Unexplained", sm.get("unexplained_change", 0))
            c[3].metric("Potentially suspicious", sm.get("potentially_suspicious", 0))
            c[4].metric("Insufficient baseline", sm.get("insufficient_baseline", 0))
        st.markdown("**Comparison baseline(s)**")
        df([{"Commit": c_["commit"][:12], "Baseline": (c_["baseline"] or "—")[:12], "Mode": c_["mode"], "Status": c_["status"],
             "Lockfiles changed": ", ".join(c_.get("lockfiles_changed", [])), "Manifests changed": ", ".join(c_.get("manifests_changed", []))} for c_ in la.get("comparisons", [])])
        show_all = st.checkbox("Also show normal updates", False)
        changes = la.get("changes", [])
        rows = [c_ for c_ in changes if show_all or c_["classification"] != "normal_update"]
        st.caption(f"{len(rows)} change(s) shown of {len(changes)}")
        df([{"ID": c_["finding_id"], "Commit": c_["commit"][:10], "File": c_["file"], "Package": c_["package_name"], "Change": c_["change_type"],
             "Previous": (c_["previous"] or {}).get("version"), "New": (c_["new"] or {}).get("version"), "Classification": c_["classification"],
             "Evidence": c_["evidence_strength"], "Risk": risks.get(c_["finding_id"], {}).get("label", ""), "Why": (c_["reasons"] or [""])[0]} for c_ in rows], height=300)
        for c_ in rows[:60]:
            with st.expander(f"{c_['finding_id']} · {c_['package_name']} · {c_['classification'].replace('_', ' ')}"):
                ci = c_.get("commit_info") or {}
                st.markdown(f"**Commit** `{c_['commit']}` — {ci.get('subject', '')} ({ci.get('author', '')}, {ci.get('date', '')})  \n**Baseline** `{c_['baseline']}` ({c_['baseline_mode']})  \n**File** `{c_['file']}`")
                st.markdown(f"**Previous:** `{c_['previous']}`  \n**New:** `{c_['new']}`")
                st.markdown("**Why this classification**")
                for why in c_["reasons"]:
                    st.markdown(f"- {why}")
                st.markdown(f"Manifest changed in the same commit: **{'yes' if c_['manifest_changed'] else 'no'}** {c_['manifest_files_changed'] or ''}")
                if c_["diff_excerpt"]:
                    st.code("\n".join(c_["diff_excerpt"]), language="diff")
