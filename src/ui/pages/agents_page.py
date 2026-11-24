"""Page: Agent Activity - who did what, what each agent decided and why."""
from __future__ import annotations

import streamlit as st

from agents.runtime import STEPS
from ui.components.common import df, page_header, require_result
from ui.components.live_progress import _is_noisy

ICON = {"pending": "⚪", "running": "🔵", "done": "✅", "skipped": "⏭️", "error": "❌"}
KIND_ICON = {"start": "▶", "progress": "•", "done": "✔", "skip": "⏭", "decision": "🧭", "observation": "👁", "warning": "⚠️", "error": "❌"}


def render() -> None:
    page_header("Agent Activity", "Supervisor orchestration plan, 8 specialist agents, autonomous decisions, and complete execution trace.")
    from config.settings import get_settings
    s = get_settings()
    if not s.llm_api_key:
        st.warning("⚠️ **LLM Provider API Key Missing**: Please add an LLM provider API key in `.env` (e.g. `LLM_API_KEY=gsk_...` for Groq, `AIza...` for Gemini, `sk-ant-...` for Anthropic, or `sk-...` for OpenAI) since requirements for this phase require an active LLM for autonomous investigator reasoning.")

    r = require_result()
    if not r:
        return

    trace, agents = r.get("agent_trace", []), r.get("agents", [])
    if not trace:
        st.info("No agent trace available for this scan.")
        return

    c = st.columns(4)
    c[0].metric("Agents", len(agents))
    c[1].metric("Pipeline Steps", len(STEPS))
    c[2].metric("Decisions", sum(a["decisions"] for a in agents))
    c[3].metric("Duration", f"{r.get('total_seconds', '?')}s")

    t1, t2, t3, t4 = st.tabs(["Agents & Steps", "Decisions", "Full Timeline", "Execution Plan"])

    with t1:
        for a in agents:
            with st.expander(f"**{a['agent']}** — {a['decisions']} decisions, {a['observations']} observations", expanded=False):
                st.caption(a["role"])
                df([{"": ICON[s["status"]], "Step": s["label"], "Status": s["status"], "Seconds": s["seconds"]} for s in a["steps"]], height=160)

    with t2:
        dec = [e for e in trace if e["kind"] == "decision"]
        st.caption(f"{len(dec)} autonomous agent decision(s) recorded")
        df([{"Time (s)": e["t"], "Agent": e["agent"], "Decision": e["message"], "Reason": e["detail"].get("reason", "")} for e in dec], height=380)

    with t3:
        a, b, c_min = st.columns([2, 2, 2])
        f_agent = a.multiselect("Agent", [x["agent"] for x in agents])
        kinds = sorted({e["kind"] for e in trace})
        f_kind = b.multiselect("Event Type", kinds, default=[k for k in kinds if k != "progress"])
        hide_telemetry = c_min.checkbox("Minimalist View", value=True, help="Hide raw internal telemetry counts and debug observations")
        rows = [
            e for e in trace
            if (not f_agent or e["agent"] in f_agent)
            and e["kind"] in f_kind
            and (not hide_telemetry or not _is_noisy(e.get("message", "")))
        ]
        df([{"Time (s)": e["t"], "Agent": e["agent"], "Type": f"{KIND_ICON.get(e['kind'], '')} {e['kind']}", "Message": e["message"]} for e in rows], height=420)

    with t4:
        st.markdown("**Supervisor Analysis Plan**")
        for p in r.get("plan", []):
            st.markdown(f"• {p}")
        st.caption("Safety rules: Static reads only · No repo code executed · No installs or builds")

        orch = r.get("orchestration") or {}
        if orch:
            st.markdown("**Orchestration** (LangGraph state graph)")
            st.caption(f"Engine: {orch.get('engine')} · executed nodes: {' → '.join(orch.get('trail', []))}")
            with st.expander("Graph definition (Mermaid)"):
                st.code(orch.get("graph", ""), language="text")
            if orch.get("callback_errors"):
                st.warning(f"{orch['callback_errors']} UI callback error(s) occurred while streaming progress (scan unaffected).")
