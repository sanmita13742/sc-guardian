"""Page: Agent Activity - who did what, what each agent decided and why."""
from __future__ import annotations

import streamlit as st

from agents.runtime import STEPS
from ui.components.common import df, repo_caption, require_result

ICON = {"pending": "⚪", "running": "🔵", "done": "✅", "skipped": "⏭️", "error": "❌"}
KIND_ICON = {"start": "▶", "progress": "•", "done": "✔", "skip": "⏭", "decision": "🧭", "observation": "👁", "warning": "⚠️", "error": "❌"}


def render() -> None:
    st.header("Agent Activity")
    r = require_result()
    if not r:
        return
    repo_caption(r)
    trace, agents = r.get("agent_trace", []), r.get("agents", [])
    if not trace:
        st.info("This scan was stored before agent tracing existed.")
        return
    st.markdown(
        "The scan is executed by a **Supervisor** and eight **specialist agents**. Each agent owns pipeline steps, uses tools (Git, Syft, OSV, NVD, KEV, NetworkX), "
        "writes what it *observed* and what it *decided* (and why) to a shared trace, and the Supervisor adapts the run: fallback inventory when Syft fails, "
        "OSV retry, NVD prioritisation, escalation of correlated detections. Reasoning is rule-based and deterministic; an LLM is used only to phrase "
        "explanations (Risk Agent) when an API key is configured, and its output is validated against evidence.")
    c = st.columns(4)
    c[0].metric("Agents", len(agents))
    c[1].metric("Pipeline steps", len(STEPS))
    c[2].metric("Decisions recorded", sum(a["decisions"] for a in agents))
    c[3].metric("Total time", f"{r.get('total_seconds', '?')} s")

    t1, t2, t3, t4 = st.tabs(["Agents and steps", "Decisions", "Full timeline", "Plan and workspace"])
    with t1:
        for a in agents:
            with st.expander(f"**{a['agent']}** - {a['decisions']} decisions, {a['observations']} observations, {a['warnings']} warnings", expanded=False):
                st.caption(a["role"])
                df([{"": ICON[s["status"]], "Step": s["label"], "Status": s["status"], "Seconds": s["seconds"]} for s in a["steps"]])
    with t2:
        dec = [e for e in trace if e["kind"] == "decision"]
        st.caption(f"{len(dec)} decisions. Each shows the agent, what it decided and the reason.")
        df([{"t (s)": e["t"], "Agent": e["agent"], "Decision": e["message"], "Reason": e["detail"].get("reason", "")} for e in dec], height=420)
    with t3:
        a, b = st.columns(2)
        f_agent = a.multiselect("Agent", [x["agent"] for x in agents])
        kinds = sorted({e["kind"] for e in trace})
        f_kind = b.multiselect("Event type", kinds, default=[k for k in kinds if k != "progress"])
        rows = [e for e in trace if (not f_agent or e["agent"] in f_agent) and e["kind"] in f_kind]
        df([{"t (s)": e["t"], "Progress": f"{int(e['progress'] * 100)}%", "Agent": e["agent"], "Type": f"{KIND_ICON.get(e['kind'], '')} {e['kind']}", "Message": e["message"]} for e in rows], height=500)
    with t4:
        st.markdown("**Analysis plan** (decided by the Supervisor after reconnaissance)")
        for p in r.get("plan", []):
            st.markdown(f"- {p}")
        ws = r.get("workspace") or {}
        st.markdown("**Where the repository was stored**")
        st.markdown(f"- Isolated workspace: `{ws.get('location')}`  \n- Clone: `{ws.get('clone_path')}`  \n- Kept: **{ws.get('kept')}**, deleted after scan: **{ws.get('removed')}**  \n- {ws.get('note', '')}")
        st.markdown("**Safety rules enforced by every agent:** nothing from the repository is executed; no package installs; no Dockerfile builds; "
                    "subprocesses use argument lists (no shell); symlinks are skipped; file reads are size-capped and path-checked.")
