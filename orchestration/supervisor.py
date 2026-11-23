"""Supervisor helpers executed as graph nodes: analysis plan, result assembly, finalisation and workspace clean-up."""
from __future__ import annotations

import platform
import time
from pathlib import Path
from typing import Optional

import networkx as nx

from agents.runtime import AGENT_ROLES, AGENTS, STEPS, Runtime
from agents.specialists import ScanState
from core import git_manager as gm
from core.repository_inspector import headline_languages
from risk_analysis.risk_rules import RULES_VERSION

SCANNER_VERSION = "2.1.0"


def plan(st: ScanState, rt: Runtime) -> None:
    """Supervisor: turn the Recon findings into an explicit analysis plan (recorded as decisions)."""
    with rt.step("plan") as b:
        insp, o = st.insp, st.options
        plan: list[str] = []

        def decide(msg: str, why: str) -> None:
            plan.append(msg)
            rt.decide("plan", msg, reason=why, agent="Supervisor")

        by_eco: dict[str, list[str]] = {}
        for m in insp.manifests:
            by_eco.setdefault(m.ecosystem, []).append(m.name)
        if not by_eco:
            decide("Rely on the SBOM scanner alone for inventory", "No manifests or lockfiles were found, so lockfile parsing has nothing to cross-check.")
        for eco, names in sorted(by_eco.items()):
            has_lock = any(n in ("package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml", "poetry.lock", "uv.lock", "Pipfile.lock", "go.mod",
                                 "go.sum", "Cargo.lock", "composer.lock", "packages.lock.json", "gradle.lockfile") or n.startswith("requirements") for n in names)
            decide(f"{eco}: " + ("parse lockfiles for an independent inventory and direct/transitive flags" if has_lock
                                 else "manifest only - versions may be unresolved; rely on the SBOM scanner and report unpinned dependencies"),
                   f"Found {', '.join(sorted(set(names)))}")
        if insp.unsupported:
            decide("Report unsupported ecosystems instead of guessing", "; ".join(insp.unsupported))
        if insp.dockerfiles or insp.container_files or insp.ci_files:
            decide("Analyse Dockerfiles, compose files and CI/CD workflows statically (Pipeline Agent)", "Container and pipeline definitions are part of the supply chain: unpinned bases/actions, root containers, remote scripts, injectable workflows. Nothing is built or executed.")
        if st.git_history:
            decide(f"Compare lockfiles for the last {o.lockfile_commits} commit(s) against their parents" + (f" (explicit baseline {o.baseline})" if o.baseline else ""),
                   "Git history is available" + (" but shallow (depth-limited); missing parents are reported, not guessed" if st.info.shallow else ""))
        else:
            decide("Skip Git-history lockfile analysis", "The scanned path is not the top level of a Git repository.")
        decide("Query OSV.dev (ground truth), validate ranges locally, then re-verify by PURL" + (", enrich with NVD" if o.use_nvd else "") + (" and CISA KEV" if o.use_kev else ""),
               "Matching uses ecosystem + name + version, never name alone.")
        st.result["plan"] = plan
        b["message"] = f"{len(plan)} planning decisions"


def assemble(st: ScanState, rt: Runtime, workspace: Optional[Path]) -> None:
    res = st.result
    res["inspection"] = {**st.insp.model_dump(), "headline_languages": headline_languages(st.insp)}
    res["lockfile_dependencies"] = [d.model_dump() for d in st.lock_deps]
    res["lockfile_errors"] = st.lock_errors
    res["sbom_tool"] = st.sbom_tool
    res["metadata_fusion"] = st.fusion or None
    res["sbom_files"] = st.sbom_files or ([{"label": f"{st.inventory_source} (raw scanner output)", "path": st.sbom_path}] if st.sbom_path else [])
    res["syft"] = st.syft.to_dict() if (st.syft is not None and st.inventory_source == "syft") else None  # kept for stored scans / API compatibility
    res["inventory_source"], res["sbom_path"] = st.inventory_source, st.sbom_path
    res.setdefault("sbom", {"path": st.sbom_path, "validation": {"valid": False, "errors": ["SBOM not generated"], "warnings": [], "stats": {}}})
    res.setdefault("enrichment", None)
    res["components"] = [c.model_dump() for c in st.components]
    res["quality"] = st.quality
    res.setdefault("graph", {"nodes": [], "edges": [], "roots": [], "validation": {}, "relationships": {}})
    res.setdefault("vuln_coverage", {})
    res.setdefault("source_status", {})
    res["vulnerabilities"] = st.vulns
    res["typosquatting_meta"] = {"suppressed": st.typo["suppressed"], "stats": st.typo["stats"]}
    res["lockfile_analysis"] = {k: v for k, v in st.lres.items() if k != "findings"}
    res["lockfile_changes"] = st.lres["findings"]
    res["limitations"].extend(st.lres.get("limitations", []))
    res["risk_rules_version"] = RULES_VERSION
    res["workspace"] = {"location": str(workspace) if workspace else None, "clone_path": str(st.repo_dir), "kept": bool(st.options.keep_workspace),
                        "removed": False, "note": "Temporary, isolated, git-ignored; deleted after the scan unless 'keep clone' is ticked."}
    res["tool_versions"] = {"scanner": SCANNER_VERSION, "sbom_scanner": st.inventory_source if st.inventory_source != "none" else "unavailable",
                            "sbom_scanner_version": (st.syft.version if st.syft else None) or ("rule engine 1.0" if st.inventory_source == "builtin" else "n/a"),
                            "python": platform.python_version(), "networkx": nx.__version__}
    res["limitations"] = list(dict.fromkeys(res["limitations"] + (st.quality.get("limitations", []) if st.quality else [])))
    # full-schema defaults: a failed or skipped stage must never leave a key missing for the UI/reports
    from agents.specialists import _summary, source_package_view
    res.setdefault("summary", _summary(st, res))
    res.setdefault("analyst", {"headline": "Analysis incomplete - see limitations and errors.", "paragraphs": [], "priorities": []})
    res.setdefault("risk_assessments", st.risk.get("assessments", []))
    res.setdefault("correlations", st.risk.get("correlations", []))
    res.setdefault("risk_by_root", [])
    res.setdefault("explanations", {})
    res.setdefault("evidence", {})
    res.setdefault("typosquatting", [f.model_dump() for f in st.typo["findings"]])
    res.setdefault("source_package_view", [])
    res.setdefault("memory", {"diff": None, "fingerprints": {}, "titles": {}})
    res["pipeline"] = st.pipe
    res.setdefault("investigations", {})
    res["evidence_store"] = st.evidence.to_list()
    if res["source_status"].get("OSV", {}).get("state") in ("unavailable", "partial", "failed"):
        res["limitations"].append(f"OSV was {res['source_status']['OSV']['state']}: vulnerability results are incomplete (see coverage).")


def finalize(st: ScanState, rt: Runtime, final: bool = False) -> None:
    res = st.result
    res["errors"] = [{k: v for k, v in e.items() if k != "trace"} for e in rt.errors]
    res["timings"] = dict(rt.timings)
    res["status"] = "completed" if not rt.errors else "completed_with_errors"
    res["agent_trace"] = rt.trace()
    res["agents"] = _agent_summary(rt)
    if final:
        res["total_seconds"] = round(time.time() - rt.t0, 1)


def _agent_summary(rt: Runtime) -> list[dict]:
    out = []
    for a in AGENTS:
        steps = [{"id": sid, "label": lab, "status": rt.status[sid], "seconds": rt.timings.get(sid)} for sid, ag, lab in STEPS if ag == a]
        evs = [e for e in rt.events if e.agent == a]
        out.append({"agent": a, "role": AGENT_ROLES[a], "steps": steps, "decisions": sum(e.kind == "decision" for e in evs),
                    "observations": sum(e.kind == "observation" for e in evs), "warnings": sum(e.kind == "warning" for e in evs)})
    return out


def cleanup(rt: Runtime, ws: Optional[Path], keep: bool, result: dict) -> None:
    if rt.status["cleanup"] != "pending":
        return
    if ws is None:
        rt.skip("cleanup", "no temporary workspace")
        return
    if keep:
        rt.skip("cleanup", f"clone kept for inspection at {ws}")
        return
    rt.begin("cleanup", f"Deleting the temporary clone {ws}")
    gone = gm.cleanup(ws)
    if gone:
        rt.done("cleanup", "workspace removed")
    else:
        rt.warn("cleanup", f"Could not delete {ws} (files in use); it will be removed by the next scan's start-up sweep.")
        rt.done("cleanup", "workspace NOT fully removed")
    if isinstance(result, dict) and result.get("workspace"):
        result["workspace"]["removed"] = gone
