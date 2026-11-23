"""Supervisor: runs the multi-agent scan pipeline.

The Supervisor validates input, owns the isolated workspace, builds the plan from what Recon discovers, runs the
specialist agents in order, observes each result and adapts (fallback inventory when Syft fails, OSV retry, NVD
prioritisation, escalation of correlated detections) and finally cleans up. Every observation and decision is recorded
in ``result["agent_trace"]`` and streamed to ``on_event`` for the live progress UI.
"""
from __future__ import annotations

import calendar
import hashlib
import json
import platform
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Optional

import networkx as nx

from agents.runtime import AGENT_ROLES, AGENTS, STEPS, Runtime
from agents.specialists import ScanState
from config.settings import Settings, get_settings
from core import git_manager as gm
from core.http import HttpClient
from core.models import RepoInfo
from core.repository_inspector import headline_languages
from core.url_validator import validate_github_url, validate_ref
from reporting import json_exporter
from orchestration.supervisor import SCANNER_VERSION, cleanup as _cleanup
from risk_analysis.risk_rules import RULES_VERSION, load_rules
from storage.cache import Cache
from storage.database import Database


OnEvent = Callable[[dict], None]


@dataclass
class ScanOptions:
    url: str = ""
    ref: Optional[str] = None
    use_nvd: bool = True
    use_kev: bool = True
    registry_checks: bool = True
    lockfile_commits: int = 1
    baseline: Optional[str] = None
    keep_workspace: bool = False
    reuse_cached: bool = True
    use_llm: bool = False
    rules_path: Optional[str] = None
    sbom_scanner: str = "auto"  # auto | syft | trivy | builtin
    remediate: bool = True  # Remediation + Validator agents
    investigate: bool = True  # Investigator Agent: reachability + EPSS + verdicts
    metadata_registry: bool = True  # fill missing metadata / verify digests against package registries


_FP_FIELDS = ("use_nvd", "use_kev", "investigate", "remediate", "metadata_registry", "registry_checks", "lockfile_commits", "baseline", "use_llm", "rules_path")


def options_fingerprint(o: "ScanOptions") -> str:
    """Hash of every option that changes the analysis result (not of url/ref/keep/reuse/scanner choice)."""
    return hashlib.sha256(json.dumps({k: getattr(o, k) for k in _FP_FIELDS}, sort_keys=True, default=str).encode()).hexdigest()[:16]


def _age_s(ts: str) -> float:
    try:
        return time.time() - calendar.timegm(time.strptime(ts, "%Y-%m-%dT%H:%M:%SZ"))
    except (ValueError, TypeError):
        return float("inf")


def reusable(res: Optional[dict], options: "ScanOptions", s: Settings) -> tuple[bool, str]:
    """A stored scan may be reused only if it is fresh and was produced by the same code, rules and options."""
    if not res:
        return False, "no stored scan"
    if res.get("status") == "failed":
        return False, "stored scan failed"
    age = _age_s((res.get("repo") or {}).get("scan_timestamp", ""))
    if age > s.scan_cache_ttl_s:
        return False, f"stored scan is older than {s.scan_cache_ttl_s // 3600}h (new advisories may exist)"
    if (res.get("tool_versions") or {}).get("scanner") != SCANNER_VERSION or res.get("risk_rules_version") != RULES_VERSION:
        return False, "scanner or risk-rule version changed"
    if res.get("options_fp") != options_fingerprint(options):
        return False, "scan options differ"
    tool = res.get("sbom_tool") or {}
    if not (tool.get("used") and res.get("sbom_path") and Path(res["sbom_path"]).exists()):
        return False, "stored scan has no SBOM file"
    if options.sbom_scanner not in ("auto", None) and tool.get("used") != options.sbom_scanner:
        return False, "a different SBOM scanner was used"
    return True, f"{int(age // 60)} min old"


def _now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _safe_name(s: str) -> str:
    return "".join(ch if ch.isalnum() or ch in "-_." else "-" for ch in s)[:60]


class _Ctx:
    def __init__(self, settings: Settings, db: Database):
        self.s, self.db = settings, db
        self.cache = Cache(db)
        self.http = HttpClient(timeout=settings.http_timeout_s, retries=settings.http_retries)


def friendly_clone_error(raw: str, ref: Optional[str]) -> str:
    """Translate raw git failures into actionable messages."""
    low = raw.lower()
    if "timed out" in low:
        return "The clone timed out. The repository is probably too large for the 3-minute clone limit; try a smaller repository or a specific branch."
    if "remote branch" in low and "not found" in low:
        return f"Branch or tag '{ref}' does not exist in this repository. Leave the branch field empty to use the default branch."
    if any(k in low for k in ("not found", "could not read username", "authentication failed", "terminal prompts disabled", "repository access blocked")):
        return "Repository not found, or it is private. Only public GitHub repositories are supported (check the owner/name spelling)."
    if any(k in low for k in ("could not resolve host", "unable to access", "connection", "ssl", "tls")):
        return "GitHub could not be reached (network problem). Check your internet connection or proxy and try again."
    if "size limit" in low:
        return raw
    return "Clone failed: " + raw[:300]


def resolve_remote_sha(url: str, ref: str | None) -> Optional[str]:
    try:
        out = gm.run_git(["ls-remote", "--", url, ref or "HEAD"], timeout=30).stdout.split()
        return out[0] if out else None
    except gm.GitError:
        return None


# ============================================================================================ entry points
def _legacy_progress(progress: Optional[Callable]) -> Optional[OnEvent]:
    """Adapter so callers written for the old ``progress(stage, fraction, message)`` callback keep working."""
    if progress is None:
        return None
    return lambda e: progress(e["step"], e["progress"], e["message"])


def run_scan(options: ScanOptions, settings: Settings | None = None, db: Database | None = None,
             on_event: Optional[OnEvent] = None, progress: Optional[Callable] = None, **_ignored: Any) -> dict[str, Any]:
    """Scan a public GitHub repository with the agent pipeline (``progress`` is a deprecated alias of ``on_event``)."""
    on_event = on_event or _legacy_progress(progress)
    s = settings or get_settings()
    db = db or Database(s.db_path)
    rt = Runtime(on_event)
    rt.begin("validate", "Validating the repository URL (HTTPS GitHub only, no credentials, no local paths)")
    try:
        repo_ref = validate_github_url(options.url)
        ref = validate_ref(options.ref) or repo_ref.ref
    except Exception as e:
        rt.fail("validate", str(e))
        raise
    rt.done("validate", f"Accepted {repo_ref.web_url}" + (f" @ {ref}" if ref else ""))
    if options.reuse_cached:
        sha = resolve_remote_sha(repo_ref.clone_url, ref)
        cached = db.find_scan(repo_ref.web_url, sha) if sha else None
        res = db.load_scan(cached) if cached else None
        ok, why = reusable(res, options, s)
        if cached and not ok:
            rt.observe("validate", f"A stored scan of this commit exists but is not reused: {why}")
        if ok:
            rt.decide("validate", f"Reuse the stored scan of commit {sha[:10]} ({why})", reason="Identical commit, same scanner/rules/options and still fresh; untick 'Reuse cached scan' to force a rescan.", agent="Supervisor")
            for step in rt.status:
                if rt.status[step] == "pending":
                    rt.skip(step, "reused stored result")
            res["from_cache"] = True
            return res
    gm.reap_stale_workspaces(s)
    try:
        Cache(db).maintain(s.cache_max_age_days, s.cache_max_rows)
    except Exception:
        pass  # cache upkeep must never block a scan
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
            return {"status": "failed", "error": friendly_clone_error(rt.errors[-1]["error"], ref), "agent_trace": rt.trace(),
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
                         on_event: Optional[OnEvent] = None, name: str | None = None, progress: Optional[Callable] = None) -> dict[str, Any]:
    """Analyse an existing local directory (developer/CLI use only; never reachable from the UI URL box)."""
    on_event = on_event or _legacy_progress(progress)
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
    """Run the LangGraph agent pipeline (see ``orchestration/pipeline.py``) on an already-acquired working tree."""
    from orchestration.pipeline import run_pipeline
    st = ScanState(repo_dir=repo_dir, info=info, options=options, ctx=ctx, rules=load_rules(options.rules_path), git_history=git_history)
    st.prefix = f"{info.scan_id}-{_safe_name(info.name)}"
    st.result = {"status": "running", "repo": info.model_dump(), "from_cache": False, "limitations": [], "options_fp": options_fingerprint(options)}
    return run_pipeline(st, rt, workspace)
