"""Monitoring: watch list and alerts for newly disclosed / newly exploited vulnerabilities in stored inventories."""
from __future__ import annotations

import streamlit as st

from config.settings import get_settings
from monitor.watch import acknowledge, add_watch, events, remove_watch, run_monitor, watchlist
from storage.database import Database
from ui.components.common import df, page_header

SEV_ICON = {"CRITICAL": "🟥", "HIGH": "🟧", "MEDIUM": "🟨", "LOW": "🟦"}
KIND = {"new_vulnerability": "New advisory", "now_exploited": "Now exploited (KEV)", "epss_rise": "Exploit probability rose"}


def render() -> None:
    page_header("Continuous Monitoring", "Re-assess stored inventories against newly disclosed vulnerabilities - no re-clone, no re-scan.")
    s = get_settings()
    db = Database(s.db_path)
    repos = []
    seen = set()
    for x in db.list_scans(300):
        if x["status"] != "failed" and not x["repo_url"].startswith(("local:", "local-fixture")) and x["repo_url"] not in seen:
            seen.add(x["repo_url"])
            repos.append(x)
    wl = {w["repo_url"]: w for w in watchlist(db)}

    c1, c2 = st.columns([2, 1])
    with c1:
        st.markdown("**Watch list**")
        df([{"Repository": x["repo_url"], "Last scan": x["scan_timestamp"], "Commit": x["commit_sha"][:8], "Watched": "yes" if x["repo_url"] in wl else "no", "Last monitor run": (wl.get(x["repo_url"]) or {}).get("last_run") or ""} for x in repos], height=220)
    with c2:
        pick = st.selectbox("Repository", [x["repo_url"] for x in repos] or [""], key="mon_pick")
        a, b = st.columns(2)
        if pick and a.button("Watch", use_container_width=True):
            add_watch(db, pick)
            st.rerun()
        if pick and b.button("Unwatch", use_container_width=True):
            remove_watch(db, pick)
            st.rerun()

    scope = st.radio("Run against", ["Watched repositories (or all if none watched)", "Selected repository only"], horizontal=True)
    if st.button("Run monitor now", type="primary"):
        with st.spinner("Re-querying OSV, CISA KEV and EPSS for stored inventories..."):
            out = run_monitor(s, db, repo_url=pick if scope.startswith("Selected") else None)
        st.session_state["mon_out"] = out
    out = st.session_state.get("mon_out")
    if out:
        st.success(f"Checked {out['repos_checked']} repository inventory(ies) at {out['checked_at']}: {len(out['alerts'])} new alert(s). Sources: {out['sources']}") if not out["errors"] else st.warning("; ".join(out["errors"][:3]))

    st.markdown("#### Alerts")
    ev = events(db)
    open_ev = [e for e in ev if not e["acknowledged"]]
    m = st.columns(3)
    m[0].metric("Unacknowledged", len(open_ev))
    m[1].metric("Total recorded", len(ev))
    m[2].metric("Watched", len(wl))
    if not ev:
        st.info("No alerts yet. Alerts appear when an advisory is disclosed (or a CVE becomes known-exploited) after a stored scan.")
        return
    for e in ev[:40]:
        with st.container(border=True):
            l, r_ = st.columns([6, 1])
            l.markdown(f"{SEV_ICON.get(e['severity'], '⬜')} **{KIND.get(e['kind'], e['kind'])}** · {e['title']}  \n<span style='opacity:.7'>{e['repo_url']} · {e['at']}</span>", unsafe_allow_html=True)
            if not e["acknowledged"] and r_.button("Acknowledge", key=f"ack{e['id']}"):
                acknowledge(db, e["id"])
                st.rerun()
    st.caption("Schedule it: `python guardian.py monitor` (exit code 1 when there are new alerts) from cron / Task Scheduler / `.github/workflows/guardian.yml`.")
