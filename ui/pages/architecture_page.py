"""Architecture overview: agents, tools, data sources, AI interaction points, approval points and evidence storage."""
from __future__ import annotations

import streamlit as st

from agents.runtime import AGENT_ROLES, STEPS
from ecosystems.registry import capability_matrix
from tools.registry import catalogue
from orchestration.pipeline import workflow_payload
from ui.components.common import df, page_header
from ui.visualizations.graphs import render_workflow_graph


def render() -> None:
    page_header("Architecture", "Agents, tools, data sources, AI interaction points, approval points and evidence storage.")
    t_flow, t_agents, t_eco, t_ai = st.tabs(["Agent workflow", "Agents & tools", "Ecosystems", "AI, approvals & safety"])
    with t_flow:
        st.caption("The real LangGraph pipeline (generated from the compiled graph). Click an agent for its role, steps and safety notes.")
        render_workflow_graph(workflow_payload(), 460)
        st.caption("Artifacts flow left to right: repository -> components (SBOM) -> dependency graph -> findings -> verdicts -> remediation proposals -> reports / policy gate.")
    with t_agents:
        steps_by_agent: dict[str, list[str]] = {}
        for sid, ag, lab in STEPS:
            steps_by_agent.setdefault(ag, []).append(f"{sid}: {lab}")
        df([{"Agent": a, "Role": AGENT_ROLES.get(a, ""), "Steps": " | ".join(steps_by_agent.get(a, []))} for a in AGENT_ROLES], height=420)
        st.markdown("**Read-only tool registry** (used by the deterministic planner and, if enabled, the LLM planner)")
        df([{"Tool": t["name"], "Description": t["description"], "Arguments": ", ".join(f"{k}: {v}" for k, v in t["params"].items())} for t in catalogue()], height=260)
    with t_eco:
        st.markdown("**Ecosystem capability matrix** (computed from the plugin registry, never hand-written)")
        df(capability_matrix(), height=420)
    with t_ai:
        st.markdown("""
**Where AI is used (all optional, off unless `LLM_API_KEY` is set):** Investigator reasoning (bounded tool loop), explanation phrasing. Everything else - detection, version matching, scoring, reachability, EPSS/KEV, what-if simulation, policy - is deterministic.

**How hallucination is controlled**
- the model may only call *read-only* tools; every fact it can use is an **evidence record with an id**
- its answer is accepted only if it cites existing evidence ids, mentions only advisory ids/facts present in the evidence, and does not contradict hard evidence (e.g. "no import" while an import exists)
- rejected proposals are kept and shown; the deterministic verdict stays; AI-assisted conclusions are labelled

**Human approval points:** every remediation (approve / reject / needs review, reason required) before a patch or PR text can be exported; optional sandbox build/test run needs a second explicit confirmation. Nothing is applied, pushed or merged automatically.

**Source code and secrets:** repository code is only *read* (never executed, except inside the opt-in Docker sandbox). Only package names, advisory facts and <= 11-line import snippets can leave the machine, and only to the configured LLM provider; secret-shaped strings are redacted; every call is logged (size + hash) in the report's disclosure section. Subprocesses never receive API keys.
""")
        st.markdown("**Evidence storage:** every scan keeps its evidence store (`result.evidence_store`), tool traces and decision log in SQLite (`data/scanner.db`); approvals and the audit trail live in `approvals` / `audit_log`.")
