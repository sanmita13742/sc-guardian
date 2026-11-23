"""Supervisor: runs the multi-agent scan pipeline.

The Supervisor validates input, owns the isolated workspace, builds the plan from what Recon discovers, runs the
specialist agents in order, observes each result and adapts (fallback inventory when Syft fails, OSV retry, NVD
prioritisation, escalation of correlated detections) and finally cleans up. Every observation and decision is recorded
in ``result["agent_trace"]`` and streamed to ``on_event`` for the live progress UI.
"""
from __future__ import annotations

import platform
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Optional

import networkx as nx

from agents.runtime import AGENT_ROLES, AGENTS, STEPS, Runtime
from agents.specialists import (AnalystAgent, GraphAgent, ReconAgent, RiskAgent, SBOMAgent, ScanState, ThreatAgent, VerificationAgent,
                                VulnerabilityAgent)
from config.settings import Settings, get_settings
from core import git_manager as gm
from core.http import HttpClient
from core.models import RepoInfo
from core.repository_inspector import headline_languages
from core.url_validator import validate_github_url, validate_ref
from reporting import json_exporter
from risk_analysis.risk_rules import RULES_VERSION, load_rules
from storage.cache import Cache
from storage.database import Database

SCANNER_VERSION = "2.0.0"
STAGES = [s[0] for s in STEPS]  # kept for UI compatibility

OnEvent = Callable[[dict], None]


@dataclass
class ScanOptions:
    url: str = ""
    ref: Optional[str] = None
    use_nvd: bool = True
    use_kev: bool = True
    enrich_metadata: bool = False
    registry_checks: bool = True
    lockfile_commits: int = 1
    baseline: Optional[str] = None
    keep_workspace: bool = False
    reuse_cached: bool = True
    use_llm: bool = False
    rules_path: Optional[str] = None


def _now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _safe_name(s: str) -> str:
    return "".join(ch if ch.isalnum() or ch in "-_." else "-" for ch in s)[:60]


class _Ctx:
    def __init__(self, settings: Settings, db: Database):
        self.s, self.db = settings, db
        self.cache = Cache(db)
        self.http = HttpClient(timeout=settings.http_timeout_s, retries=settings.http_retries)


def resolve_remote_sha(url: str, ref: str | None) -> Optional[str]:
    try:
        out = gm.run_git(["ls-remote", "--", url, ref or "HEAD"], timeout=30).stdout.split()
        return out[0] if out else None
    except gm.GitError:
        return None


# ============================================================================================ entry points
def run_scan(options: ScanOptions, settings: Settings | None = None, db: Database | None = None,
             on_event: Optional[OnEvent] = None) -> dict[str, Any]:
    """Scan a public GitHub repository with the agent pipeline."""
    s = settings or get_settings()
    db = db or Database(s.db_path)
    rt = Runtime(on_event)
    rt.begin("validate", "Validating the repository URL (HTTPS GitHub only, no credentials, no local paths)")
    try:
        repo_ref = validate_github_url(options.url)
        ref = validate_ref(options.ref)
    except Exception as e:
        rt.fail("validate", str(e))
        raise
    rt.done("validate", f"Accepted {repo_ref.web_url}" + (f" @ {ref}" if ref else ""))
    if options.reuse_cached:
        sha = resolve_remote_sha(repo_ref.clone_url, ref)
        cached = db.find_scan(repo_ref.web_url, sha) if sha else None
        res = db.load_scan(cached) if cached else None
        if res:
            rt.decide("validate", f"Reuse the stored scan of commit {sha[:10]}", reason="Identical commit already analysed; untick 'Reuse cached scan' to force a rescan.", agent="Supervisor")
            for step in rt.status:
                if rt.status[step] == "pending":
                    rt.skip(step, "reused stored result")
            res["from_cache"] = True
            return res
    scan_id, ws = gm.new_workspace(s)
    ctx = _Ctx(s, db)
    result: dict[str, Any] = {}
    try:
        with rt.step("clone", f"git clone --depth {s.clone_depth} (no submodules, no hooks) into {ws}") as b:
            repo_dir = gm.clone_repository(repo_ref, ws, ref, s)
            b["message"] = f"cloned into isolated workspace {repo_dir}"
        if rt.status["clone"] == "error":
            for step in rt.status:
                if rt.status[step] == "pending":
                    rt.skip(step, "clone failed")
            gm.cleanup(ws)
            return {"status": "failed", "error": f"Clone failed: {rt.errors[-1]['error']}", "agent_trace": rt.trace(),
                    "repo": {"scan_id": scan_id, "url": repo_ref.web_url, "name": repo_ref.name, "ref": ref, "commit_sha": "", "scan_timestamp": _now()}}
        info = RepoInfo(scan_id=scan_id, url=repo_ref.web_url, name=repo_ref.name, owner=repo_ref.owner, ref=ref,
                        branch=gm.current_branch(repo_dir) or ref, commit_sha=gm.head_sha(repo_dir), scan_timestamp=_now(),
                        shallow=gm.is_shallow(repo_dir), source="github")
        rt.observe("clone", f"Commit {info.commit_sha[:12]} on branch {info.branch}; shallow clone: {info.shallow}; stored at {ws}")
        result = analyze(repo_dir, info, options, ctx, rt, git_history=True, workspace=ws)
        return result
    finally:
        if rt.status["cleanup"] == "pending":
            _cleanup(rt, ws, options.keep_workspace, result)


def scan_local_directory(path: Path, options: ScanOptions | None = None, settings: Settings | None = None, db: Database | None = None,
                         on_event: Optional[OnEvent] = None, name: str | None = None) -> dict[str, Any]:
    """Analyse an existing local directory (developer/CLI use only; never reachable from the UI URL box)."""
    options = options or ScanOptions()
    s = settings or get_settings()
    db = db or Database(s.db_path)
    rt = Runtime(on_event)
    path = Path(path).resolve()
    top = gm.run_git(["rev-parse", "--show-toplevel"], cwd=path, check=False).stdout.strip()
    is_top = bool(top) and Path(top).resolve() == path
    sha = gm.run_git(["rev-parse", "HEAD"], cwd=path, check=False).stdout.strip() if top else ""
    info = RepoInfo(scan_id=uuid.uuid4().hex[:12], url=f"local-fixture:{path.name}", name=name or path.name, ref=options.ref,
                    branch=gm.current_branch(path) if is_top else None,
                    commit_sha=(sha if is_top else (sha + " (enclosing repository HEAD; scanned path is a subdirectory)" if sha else "unversioned")),
                    scan_timestamp=_now(), shallow=gm.is_shallow(path) if is_top else False, source="local-fixture")
    info.local_path = str(path)
    rt.done("validate", "local directory (developer mode)")
    rt.skip("clone", "scanning an existing local directory")
    return analyze(path, info, options, _Ctx(s, db), rt, git_history=is_top, workspace=None)


# ============================================================================================ pipeline
def analyze(repo_dir: Path, info: RepoInfo, options: ScanOptions, ctx: _Ctx, rt: Runtime, git_history: bool, workspace: Optional[Path]) -> dict[str, Any]:
    s, db = ctx.s, ctx.db
    st = ScanState(repo_dir=repo_dir, info=info, options=options, ctx=ctx, rules=load_rules(options.rules_path), git_history=git_history)
    st.prefix = f"{info.scan_id}-{_safe_name(info.name)}"
    st.result = {"status": "running", "repo": info.model_dump(), "from_cache": False, "limitations": []}
    res = st.result

    recon, sbom, graph, vuln, ver, threat, risk, analyst = (ReconAgent(), SBOMAgent(), GraphAgent(), VulnerabilityAgent(), VerificationAgent(),
                                                           ThreatAgent(), RiskAgent(), AnalystAgent())
    recon.discover(st, rt)
    recon.classify(st, rt)
    _plan(st, rt)
    sbom.lockfiles(st, rt)
    sbom.syft(st, rt)
    sbom.validate(st, rt)
    sbom.quality(st, rt)
    graph.build(st, rt)
    vuln.run(st, rt)
    ver.run(st, rt)
    threat.typosquat(st, rt)
    threat.lockfile_history(st, rt)
    risk.score(st, rt)
    risk.explain(st, rt)
    _assemble(st, rt, workspace)
    analyst.summarize(st, rt)
    _finalize(st, rt)
    analyst.export(st, rt)
    _finalize(st, rt)
    _cleanup(rt, workspace, options.keep_workspace, res)
    _finalize(st, rt, final=True)
    try:
        json_exporter.write_all(res, s.artifacts_dir / "scans", st.prefix)
        db.save_scan(res)
    except Exception:
        pass
    return res


def _plan(st: ScanState, rt: Runtime) -> None:
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
            decide("Rely on Syft alone for inventory", "No manifests or lockfiles were found, so lockfile parsing has nothing to cross-check.")
        for eco, names in sorted(by_eco.items()):
            has_lock = any(n in ("package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml", "poetry.lock", "uv.lock", "Pipfile.lock", "go.mod",
                                 "go.sum", "Cargo.lock", "composer.lock", "packages.lock.json", "gradle.lockfile") or n.startswith("requirements") for n in names)
            decide(f"{eco}: " + ("parse lockfiles for an independent inventory and direct/transitive flags" if has_lock
                                 else "manifest only - versions may be unresolved; rely on Syft and report unpinned dependencies"),
                   f"Found {', '.join(sorted(set(names)))}")
        if insp.unsupported:
            decide("Report unsupported ecosystems instead of guessing", "; ".join(insp.unsupported))
        if insp.dockerfiles or insp.container_files:
            decide("Record container files as context only", "Images are never built or scanned in this MVP.")
        if st.git_history:
            decide(f"Compare lockfiles for the last {o.lockfile_commits} commit(s) against their parents" + (f" (explicit baseline {o.baseline})" if o.baseline else ""),
                   "Git history is available" + (" but shallow (depth-limited); missing parents are reported, not guessed" if st.info.shallow else ""))
        else:
            decide("Skip Git-history lockfile analysis", "The scanned path is not the top level of a Git repository.")
        decide("Query OSV.dev (ground truth), validate ranges locally, then re-verify by PURL" + (", enrich with NVD" if o.use_nvd else "") + (" and CISA KEV" if o.use_kev else ""),
               "Matching uses ecosystem + name + version, never name alone.")
        st.result["plan"] = plan
        b["message"] = f"{len(plan)} planning decisions"


def _assemble(st: ScanState, rt: Runtime, workspace: Optional[Path]) -> None:
    res = st.result
    res["inspection"] = {**st.insp.model_dump(), "headline_languages": headline_languages(st.insp)}
    res["lockfile_dependencies"] = [d.model_dump() for d in st.lock_deps]
    res["lockfile_errors"] = st.lock_errors
    res["syft"] = st.syft.to_dict() if st.syft is not None else None
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
    res["tool_versions"] = {"scanner": SCANNER_VERSION, "syft": (st.syft.version if st.syft else None) or "unavailable",
                            "python": platform.python_version(), "networkx": nx.__version__}
    res["limitations"] = list(dict.fromkeys(res["limitations"] + (st.quality.get("limitations", []) if st.quality else [])))
    if res["source_status"].get("OSV", {}).get("state") in ("unavailable", "partial", "failed"):
        res["limitations"].append(f"OSV was {res['source_status']['OSV']['state']}: vulnerability results are incomplete (see coverage).")


def _finalize(st: ScanState, rt: Runtime, final: bool = False) -> None:
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


def _cleanup(rt: Runtime, ws: Optional[Path], keep: bool, result: dict) -> None:
    if rt.status["cleanup"] != "pending":
        return
    if ws is None:
        rt.skip("cleanup", "no temporary workspace")
        return
    if keep:
        rt.skip("cleanup", f"clone kept for inspection at {ws}")
        return
    rt.begin("cleanup", f"Deleting the temporary clone {ws}")
    gm.cleanup(ws)
    rt.done("cleanup", "workspace removed")
    if isinstance(result, dict) and result.get("workspace"):
        result["workspace"]["removed"] = True
