"""Page 6: risk overview and explainability."""
from __future__ import annotations

import streamlit as st

from risk_analysis.risk_rules import DEFAULT_RULES
from ui.components.common import badge, df, repo_caption, require_result

ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"]


def _finding(r: dict, fid: str):
    for key in ("vulnerabilities", "typosquatting", "lockfile_changes"):
        for f in r.get(key, []):
            if f["finding_id"] == fid:
                return f
    return None


def render() -> None:
    st.header("Risk and Explainability")
    r = require_result()
    if not r:
        return
    repo_caption(r)
    st.caption("Risk labels come from a transparent rule engine (not an LLM) and are separate from CVSS severity. "
               "Explanations only restate collected evidence; unknowns are listed explicitly.")
    assess = r.get("risk_assessments", [])
    counts = {l: sum(1 for a in assess if a["label"] == l) for l in ORDER}
    cols = st.columns(5)
    for c, l in zip(cols, ORDER):
        c.metric(badge(l), counts[l])
    if not assess:
        st.success("No findings to assess. This does not prove the repository is safe — see Coverage and limitations.")
        return
    st.bar_chart(counts)

    st.subheader("Affected application roots")
    rb = r.get("risk_by_root", [])
    df([{"Root": x["root"], "Vulnerability findings": x["findings"], "Direct": x["direct"], "Transitive": x["transitive"],
         **{l.title(): x["by_risk"][l] for l in ORDER[:4]}} for x in rb])
    if r.get("correlations"):
        st.subheader("Correlated detections")
        for c in r["correlations"]:
            st.warning(c["note"] + f" ({', '.join(c['finding_ids'])})")

    st.subheader("Findings")
    a, b, d = st.columns(3)
    f_label = a.multiselect("Risk label", ORDER, default=["CRITICAL", "HIGH"])
    f_kind = b.multiselect("Kind", ["vulnerability", "typosquatting", "lockfile_change"])
    text = d.text_input("Search (id or package)")
    expl = r.get("explanations", {})
    sel = [x for x in sorted(assess, key=lambda x: (ORDER.index(x["label"]), -x["score"]))
           if (not f_label or x["label"] in f_label) and (not f_kind or x["kind"] in f_kind)
           and (not text or text.lower() in (x["finding_id"] + expl.get(x["finding_id"], {}).get("headline", "")).lower())]
    st.caption(f"{len(sel)} finding(s); showing up to 50")
    for a_ in sel[:50]:
        e = expl.get(a_["finding_id"])
        if not e:
            continue
        with st.expander(f"{badge(a_['label'])} · {a_['finding_id']} · {e['headline'].split(' - ', 1)[-1]}"):
            st.markdown(f"**Risk: {badge(a_['label'])}** (score {a_['score']}) — rules v{a_['rules_version']}"
                        + (f" · CVSS severity: {a_['cvss_severity']}" if a_.get("cvss_severity") else ""))
            st.markdown("**Why this risk label (deterministic factors)**")
            df([{"Factor": f["factor"], "Points": f["points"], "Detail": f["detail"]} for f in a_["factors"]])
            sec = e["sections"]
            for key, title in (("what", "What was detected"), ("why", "Why it was flagged"), ("package", "Affected package"), ("how_entered", "How it entered the application"),
                               ("direct_transitive", "Direct or transitive"), ("impact", "Potential impact"), ("evidence", "Supporting evidence"),
                               ("remediation", "Recommended remediation"), ("unknown", "What remains unknown")):
                st.markdown(f"**{title}**")
                st.text(sec[key]) if "\n" in sec[key] else st.write(sec[key])
            v = e["validation"]
            st.caption(f"Explanation source: {e['source']} · grounding check: {v.get('checked')}"
                       + (f" · sections replaced by templates: {[x['section'] for x in v['removed_sections']]}" if v.get("removed_sections") else ""))
            ev = r.get("evidence", {}).get(a_["finding_id"])
            if ev:
                with st.expander("Evidence bundle (raw)"):
                    st.json({k: v_ for k, v_ in ev.items() if k != "facts"})
    with st.expander("Scoring rules in effect"):
        st.json(DEFAULT_RULES)
        st.caption("Documented in docs/RISK_SCORING.md. Rules can be overridden with a JSON file passed to the scanner.")
