"""UI for the Memory Agent: finding history banner and analyst decisions (accept risk / false positive / suppress)."""
from __future__ import annotations

import streamlit as st

from config.settings import get_settings
from storage.database import Database
from storage.memory import DECISIONS, Memory

LABELS = {"accepted_risk": "Accepted risk", "false_positive": "False positive", "suppress": "Suppressed"}


def _mem() -> Memory:
    return Memory(Database(get_settings().db_path))


def active_decisions(r: dict) -> dict[str, dict]:
    """finding_id -> active decision for this scan's repository (decisions are looked up by stable fingerprint)."""
    fps = (r.get("memory") or {}).get("fingerprints") or {}
    if not fps:
        return {}
    try:
        dec = _mem().decisions(r["repo"]["url"])
    except Exception:
        return {}
    return {fid: dec[fp] for fid, fp in fps.items() if fp in dec}


def history_banner(r: dict) -> None:
    diff = (r.get("memory") or {}).get("diff")
    if not diff:
        return
    if diff.get("baseline"):
        st.caption("History: first scan of this repository - this scan is the baseline for future comparisons.")
        return
    c = diff["counts"]
    cols = st.columns(4)
    cols[0].metric("New since last scan", c["new"])
    cols[1].metric("Persisting", c["persisting"])
    cols[2].metric("Fixed", c["fixed"])
    cols[3].metric("Reappeared", c["regressed"])
    if diff.get("fixed"):
        with st.expander(f"{len(diff['fixed'])} finding(s) fixed since the previous scan"):
            for f in diff["fixed"][:25]:
                st.markdown(f"- ~~{f['title']}~~ ({f.get('severity') or 'n/a'})")


def decisions_panel(r: dict) -> None:
    mem_info = r.get("memory") or {}
    fps, titles = mem_info.get("fingerprints") or {}, mem_info.get("titles") or {}
    repo_url = r["repo"]["url"]
    if not fps:
        st.caption("No findings to decide on.")
        return
    try:
        mem = _mem()
        current = mem.decisions(repo_url)
    except Exception as e:  # database problems must not break the page
        st.warning(f"Decision memory unavailable: {e}")
        return
    st.caption("Decisions are remembered per repository, shown next to the finding (never hidden), and can expire. They do not change the risk score.")
    with st.form("decision_form", clear_on_submit=True):
        c1, c2, c3 = st.columns([3, 1.4, 1])
        pick = c1.selectbox("Finding", list(fps), format_func=lambda fid: f"{fid} - {titles.get(fid, '')}")
        kind = c2.selectbox("Decision", DECISIONS, format_func=lambda d: LABELS[d])
        days = c3.number_input("Expires in (days, 0 = never)", 0, 365, 30)
        reason = st.text_input("Reason (required)")
        if st.form_submit_button("Record decision"):
            try:
                mem.add_decision(repo_url, fps[pick], kind, reason, titles.get(pick, ""), int(days) or None)
                st.success("Decision recorded.")
                st.rerun()
            except ValueError as e:
                st.error(str(e))
    if current:
        st.markdown("**Active decisions**")
        for fp, d in current.items():
            a, b = st.columns([6, 1])
            a.markdown(f"**{LABELS[d['decision']]}** · {d.get('title') or fp} - _{d['reason']}_ ({'expires ' + d['expires_at'][:10] if d['expires_at'] else 'no expiry'})")
            if b.button("Remove", key=f"rm{d['id']}"):
                mem.remove_decision(d["id"])
                st.rerun()
