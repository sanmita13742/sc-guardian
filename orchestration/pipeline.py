"""LangGraph state graph that runs the agent pipeline.

  discover -> classify -> plan -> lockfiles -> sbom_generate -> sbom_validate -> sbom_quality
        -> (conditional) sbom_second_pass -> graph
  graph -> [ vulnerability -> verification ]  ||  [ typosquat -> lockfile_history ]     (parallel branches)
        -> risk (joins both) -> explain -> assemble -> summary -> export -> finalize

Design rules
* Agents stay deterministic and rule-based; the graph only decides order, branching and parallelism.
* The LangGraph state is thin (scan id + trail of executed nodes). Heavy objects (NetworkX graph, components, results) live in the
  in-process ``ScanState`` registered under the scan id, so checkpoints stay small.
* Every node is wrapped: it never raises into the graph (an exception becomes a recorded step error) and it is skipped with a recorded
  limitation when a step it depends on has failed.
* The graph runs in a worker thread; events are queued and delivered to the caller's ``on_event`` from the calling thread, so UI
  frameworks that need their own thread (Streamlit) keep working while the Threat and Vulnerability agents run in parallel.
* Checkpoints (SQLite) record the trail per node for audit; they are not used to resume a half-finished scan.
"""
from __future__ import annotations

import operator
import queue
import threading
import traceback
from pathlib import Path
from typing import Annotated, Any, Callable, Optional, TypedDict

from langgraph.checkpoint.sqlite import SqliteSaver
from langgraph.graph import END, START, StateGraph

from agents.runtime import Runtime
from agents.memory_agent import MemoryAgent
from agents.specialists import (AnalystAgent, GraphAgent, ReconAgent, RiskAgent, SBOMAgent, ScanState, ThreatAgent, VerificationAgent,
                                VulnerabilityAgent)
from core import git_manager as gm
from orchestration import supervisor as sup
from reporting import json_exporter


class GraphState(TypedDict):
    scan_id: str
    trail: Annotated[list[str], operator.add]


_REG: dict[str, tuple[ScanState, Runtime, Optional[Path]]] = {}

# node -> (callable(st, rt, workspace), runtime steps owned by the node, steps that must not have failed)
NODES: dict[str, tuple[Callable, tuple[str, ...], tuple[str, ...]]] = {}

memory = MemoryAgent()
recon, sbom, graph_agent, vuln, ver, threat, risk, analyst = (ReconAgent(), SBOMAgent(), GraphAgent(), VulnerabilityAgent(), VerificationAgent(),
                                                             ThreatAgent(), RiskAgent(), AnalystAgent())


def _register(name: str, fn: Callable, steps: tuple[str, ...] = (), requires: tuple[str, ...] = ()) -> None:
    NODES[name] = (fn, steps, requires)


def _export(st: ScanState, rt: Runtime, ws: Optional[Path]) -> None:
    sup.finalize(st, rt)
    analyst.export(st, rt)


def _finalize(st: ScanState, rt: Runtime, ws: Optional[Path]) -> None:
    sup.cleanup(rt, ws, st.options.keep_workspace, st.result)
    sup.finalize(st, rt, final=True)


_register("discover", lambda st, rt, ws: recon.discover(st, rt), ("discover",))
_register("classify", lambda st, rt, ws: recon.classify(st, rt), ("classify",))
_register("plan", lambda st, rt, ws: sup.plan(st, rt), ("plan",))
_register("lockfiles", lambda st, rt, ws: sbom.lockfiles(st, rt), ("lockfiles",))
_register("sbom_generate", lambda st, rt, ws: sbom.generate(st, rt), ("sbom_generate",))
_register("sbom_validate", lambda st, rt, ws: sbom.validate(st, rt), ("sbom_validate",))
_register("sbom_quality", lambda st, rt, ws: sbom.quality(st, rt), ("quality",))
_register("sbom_second_pass", lambda st, rt, ws: sbom.second_pass(st, rt), ("quality",))
_register("graph", lambda st, rt, ws: graph_agent.build(st, rt), ("graph",))
_register("vulnerability", lambda st, rt, ws: vuln.run(st, rt), ("osv", "enrich", "trace"))
_register("verification", lambda st, rt, ws: ver.run(st, rt), ("verify",))
_register("typosquat", lambda st, rt, ws: threat.typosquat(st, rt), ("typosquat",), ("graph",))
_register("lockfile_history", lambda st, rt, ws: threat.lockfile_history(st, rt), ("lockfile_history",))
_register("risk", lambda st, rt, ws: risk.score(st, rt), ("risk",))
_register("explain", lambda st, rt, ws: risk.explain(st, rt), ("explain",), ("risk",))
_register("memory", lambda st, rt, ws: memory.run(st, rt), ("memory",))
_register("assemble", lambda st, rt, ws: sup.assemble(st, rt, ws))
_register("summary", lambda st, rt, ws: analyst.summarize(st, rt), ("summary",), ("risk",))
_register("export", _export, ("export",))
_register("finalize", _finalize, ("cleanup",))


def _wrap(name: str) -> Callable[[GraphState], dict]:
    fn, steps, requires = NODES[name]

    def run(state: GraphState) -> dict:
        st, rt, ws = _REG[state["scan_id"]]
        failed = [r for r in requires if rt.status.get(r) == "error"]
        try:
            if failed:
                for sid in steps:
                    if rt.status.get(sid) == "pending":
                        rt.skip(sid, f"skipped: required step '{failed[0]}' failed")
                st.result.setdefault("limitations", []).append(f"'{name}' was skipped because '{failed[0]}' failed; related sections are empty.")
            else:
                fn(st, rt, ws)
        except Exception as e:  # a node must never take the pipeline down
            sid = next((x for x in steps if rt.status.get(x) in ("running", "pending")), steps[0] if steps else None)
            if sid:
                rt.fail(sid, f"{type(e).__name__}: {str(e)[:300]}")
                rt.errors[-1]["trace"] = traceback.format_exc()[-500:]
            else:
                rt.errors.append({"stage": name, "error": f"{type(e).__name__}: {str(e)[:300]}"})
            st.result.setdefault("limitations", []).append(f"Stage '{name}' failed ({type(e).__name__}); its results are missing or partial.")
        return {"trail": [name]}

    run.__name__ = name
    return run


def build_graph() -> StateGraph:
    g = StateGraph(GraphState)
    for name in NODES:
        g.add_node(name, _wrap(name))
    chain = ["discover", "classify", "plan", "lockfiles", "sbom_generate", "sbom_validate", "sbom_quality"]
    g.add_edge(START, chain[0])
    for a, b in zip(chain, chain[1:]):
        g.add_edge(a, b)

    def route_quality(state: GraphState) -> str:
        return "sbom_second_pass" if SBOMAgent.wants_second_pass(_REG[state["scan_id"]][0]) else "graph"

    g.add_conditional_edges("sbom_quality", route_quality, {"sbom_second_pass": "sbom_second_pass", "graph": "graph"})
    g.add_edge("sbom_second_pass", "graph")
    g.add_edge("graph", "vulnerability")  # parallel branch A
    g.add_edge("graph", "typosquat")  # parallel branch B
    g.add_edge("vulnerability", "verification")
    g.add_edge("typosquat", "lockfile_history")
    g.add_edge(["verification", "lockfile_history"], "risk")  # join: waits for both branches
    for a, b in (("risk", "explain"), ("explain", "memory"), ("memory", "assemble"), ("assemble", "summary"), ("summary", "export"), ("export", "finalize"), ("finalize", END)):
        g.add_edge(a, b)
    return g


def mermaid() -> str:
    try:
        return build_graph().compile().get_graph().draw_mermaid()
    except Exception:
        return ""


def run_pipeline(st: ScanState, rt: Runtime, workspace: Optional[Path]) -> dict[str, Any]:
    """Execute the graph for one scan and return the assembled result (always a full-schema dict)."""
    s, db, info = st.ctx.s, st.ctx.db, st.info
    _REG[info.scan_id] = (st, rt, workspace)
    deliver = rt.on_event
    q: "queue.Queue[Any]" = queue.Queue()
    rt.on_event = q.put  # worker-thread events are replayed to the caller's callback from the caller's thread
    box: dict[str, Any] = {}

    def worker() -> None:
        try:
            with SqliteSaver.from_conn_string(str(s.data_dir / "checkpoints.db")) as cp:
                app = build_graph().compile(checkpointer=cp)
                out = app.invoke({"scan_id": info.scan_id, "trail": []}, {"configurable": {"thread_id": info.scan_id}})
                box["trail"] = out.get("trail", [])
        except BaseException as e:  # noqa: BLE001 - surfaced to the caller below
            box["error"] = e
        finally:
            q.put(None)

    t = threading.Thread(target=worker, name=f"scan-{info.scan_id}", daemon=True)
    t.start()
    try:
        while True:
            ev = q.get()
            if ev is None:
                break
            if deliver:
                try:
                    deliver(ev)
                except Exception:
                    rt.callback_errors += 1
    finally:
        rt.on_event = deliver
        t.join()
        _REG.pop(info.scan_id, None)
    res = st.result
    if "error" in box:  # the graph machinery itself failed (not an agent): return what exists, flagged
        rt.errors.append({"stage": "orchestration", "error": f"{type(box['error']).__name__}: {str(box['error'])[:300]}"})
        res.setdefault("limitations", []).append("The orchestration engine failed; the result is partial.")
        sup.assemble(st, rt, workspace)
        sup.cleanup(rt, workspace, st.options.keep_workspace, res)
        sup.finalize(st, rt, final=True)
    res["orchestration"] = {"engine": "langgraph", "trail": box.get("trail", []), "checkpoint_thread": info.scan_id,
                            "callback_errors": rt.callback_errors, "graph": mermaid()}
    try:
        json_exporter.write_all(res, s.artifacts_dir / "scans", st.prefix)
        db.save_scan(res)
        for old in db.prune_repo(info.url, s.keep_scans_per_repo):
            gm.remove_artifacts(s, old)
    except Exception as e:  # never silent: the user must know the result was not persisted
        res.setdefault("errors", []).append({"stage": "persist", "error": f"{type(e).__name__}: {str(e)[:300]}"})
        res["status"] = "completed_with_errors"
        res["limitations"].append("The result could not be saved to the database/artifacts; it is shown for this session only.")
    return res
