"""Page 6: risk overview and explainability."""
from __future__ import annotations

import streamlit as st

from risk_analysis.risk_rules import DEFAULT_RULES
from ui.components.common import badge, df, page_header, require_result
from ui.components.memory_panel import LABELS, active_decisions, decisions_panel

ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"]


def render() -> None:
    page_header("Risk & Explainability", "Deterministic, transparent risk scoring and evidence-grounded natural language explanations.")
    r = require_result()
    if not r:
        return

    assess = r.get("risk_assessments", [])
    counts = {l: sum(1 for a in assess if a["label"] == l) for l in ORDER}

    cols = st.columns(5)
    for c, l in zip(cols, ORDER):
        c.metric(badge(l), counts[l])

    if not assess:
        st.success("No findings to assess.")
        return

    rb = r.get("risk_by_root", [])
    if rb:
        st.markdown("#### Risk by Application Root")
        df([{"Root": x["root"], "Findings": x["findings"], "Direct": x["direct"], "Transitive": x["transitive"],
             **{l.title(): x["by_risk"][l] for l in ORDER[:4]}} for x in rb], height=180)

    if r.get("correlations"):
        for corr in r["correlations"]:
            st.warning(f"⚠️ {corr['note']} ({', '.join(corr['finding_ids'])})")

    decided = active_decisions(r)
    st.markdown("#### Finding Risk Explanations")
    a, b, d = st.columns([1, 1, 2])
    f_label = a.multiselect("Risk Level", ORDER, default=["CRITICAL", "HIGH"])
    f_kind = b.multiselect("Finding Type", ["vulnerability", "typosquatting", "lockfile_change", "pipeline"])
    text = d.text_input("Search finding ID or package", placeholder="e.g. lodash...")

    expl = r.get("explanations", {})
    sel = [x for x in sorted(assess, key=lambda x: (ORDER.index(x["label"]), -x["score"]))
           if (not f_label or x["label"] in f_label) and (not f_kind or x["kind"] in f_kind)
           and (not text or text.lower() in (x["finding_id"] + expl.get(x["finding_id"], {}).get("headline", "")).lower())]

    st.caption(f"Showing {len(sel[:30])} of {len(sel)} finding(s)")
    for a_ in sel[:30]:
        e = expl.get(a_["finding_id"])
        if not e:
            continue
        d_ = decided.get(a_["finding_id"])
        tag = f" · 🔕 {LABELS[d_['decision']]}" if d_ else ""
        with st.expander(f"{badge(a_['label'])} · {a_['finding_id']} · {e['headline'].split(' - ', 1)[-1]} (Score {a_['score']}){tag}", expanded=False):
            if d_:
                st.info(f"{LABELS[d_['decision']]}: {d_['reason']}" + (f" (expires {d_['expires_at'][:10]})" if d_["expires_at"] else ""))
            sec = e.get("sections", {})
            st.markdown(f"**Impact:** {sec.get('impact', 'n/a')}")
            st.markdown(f"**How Entered:** {sec.get('how_entered', 'n/a')} ({sec.get('direct_transitive', 'n/a')})")
            st.markdown(f"**Remediation:** {sec.get('remediation', 'n/a')}")

            if a_.get("factors"):
                st.markdown("**Scoring Factors**")
                df([{"Factor": f["factor"], "Points": f["points"], "Detail": f["detail"]} for f in a_["factors"]], height=140)

    with st.expander("History & analyst decisions", expanded=False):
        decisions_panel(r)

    with st.expander("Scoring Rules Reference", expanded=False):
        st.json(DEFAULT_RULES)
