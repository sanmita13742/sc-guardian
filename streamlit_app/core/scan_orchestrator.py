"""End-to-end scan pipeline. Each stage is isolated: a failure is recorded and independent stages continue."""
from __future__ import annotations

import platform
import time
import traceback
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Optional

import networkx as nx

from config.settings import Settings, get_settings
from core import git_manager as gm
from core.http import HttpClient
from core.models import Component, InspectionResult, LockDependency, RepoInfo
from core.repository_inspector import headline_languages, inspect_repository
from core.url_validator import validate_github_url, validate_ref
from explainability.explanation_engine import anthropic_call, explain
from graph.dependency_tracer import classify_all
from graph.graph_builder import build_graph
from graph.graph_exporter import graph_to_json
from graph.graph_validator import validate_graph
from reporting import json_exporter, report_generator
from reporting.sbom_exporter import derived_enriched_sbom, preserve_original
from risk_analysis.evidence_collector import collect_lockfile_evidence, collect_typosquat_evidence, collect_vulnerability_evidence
from risk_analysis.evidence_normalizer import normalize_bundle
from risk_analysis.finding_correlator import correlate_findings, summarize_by_root
from risk_analysis.risk_rules import RULES_VERSION, load_rules
from sbom.cyclonedx_validator import load_sbom, normalize_components, validate_cyclonedx
from sbom.lockfile_analyzer import analyze_repository
from sbom.metadata_enricher import enrich_components
from sbom.quality_analyzer import analyze_quality
from sbom.syft_runner import resolve_syft, run_syft
from storage.cache import Cache
from storage.database import Database
from suspicious_changes.lockfile_change_detector import detect_lockfile_changes
from suspicious_changes.typosquatting_detector import detect_typosquatting
from vulnerability.kev_client import KevClient
from vulnerability.nvd_client import NvdClient
from vulnerability.osv_client import OsvClient
from vulnerability.vulnerability_correlator import correlate

SCANNER_VERSION = "1.0.0"
STAGES = ["validate", "clone", "inspect", "lockfiles", "sbom", "quality", "graph", "vulnerabilities", "typosquatting",
          "lockfile_changes", "risk", "explain", "export", "done"]

Progress = Callable[[str, float, str], None]


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
    def __init__(self, settings: Settings, db: Database, progress: Optional[Progress]):
        self.s, self.db, self.progress = settings, db, progress
        self.cache = Cache(db)
        self.http = HttpClient(timeout=settings.http_timeout_s, retries=settings.http_retries)
        self.errors: list[dict] = []
        self.timings: dict[str, float] = {}

    def step(self, stage: str, msg: str = "") -> None:
        if self.progress:
            self.progress(stage, (STAGES.index(stage) + 1) / len(STAGES), msg or stage)

    def stage(self, name: str, fn: Callable, default: Any = None, msg: str = "") -> Any:
        self.step(name, msg)
        t0 = time.time()
        try:
            return fn()
        except Exception as e:  # a stage failure must never abort the whole scan
            self.errors.append({"stage": name, "error": f"{type(e).__name__}: {str(e)[:300]}", "trace": traceback.format_exc()[-600:]})
            return default
        finally:
            self.timings[name] = round(time.time() - t0, 2)


def resolve_remote_sha(url: str, ref: str | None) -> Optional[str]:
    try:
        out = gm.run_git(["ls-remote", "--", url, ref or "HEAD"], timeout=30).stdout.split()
        return out[0] if out else None
    except gm.GitError:
        return None


def run_scan(options: ScanOptions, settings: Settings | None = None, db: Database | None = None,
             progress: Optional[Progress] = None) -> dict[str, Any]:
    """Scan a public GitHub repository."""
    s = settings or get_settings()
    db = db or Database(s.db_path)
    ctx = _Ctx(s, db, progress)
    ctx.step("validate", "Validating repository URL")
    repo_ref = validate_github_url(options.url)  # raises InvalidRepositoryURL (caller shows the message)
    ref = validate_ref(options.ref)
    if options.reuse_cached:
        sha = resolve_remote_sha(repo_ref.clone_url, ref)
        if sha:
            cached = db.find_scan(repo_ref.web_url, sha)
            if cached:
                res = db.load_scan(cached)
                if res:
                    res["from_cache"] = True
                    return res
    scan_id, ws = gm.new_workspace(s)
    try:
        ctx.step("clone", f"Cloning {repo_ref.web_url} (shallow, no submodules, no hooks)")
        try:
            repo_dir = gm.clone_repository(repo_ref, ws, ref, s)
        except gm.GitError as e:
            return _failed(scan_id, repo_ref.web_url, repo_ref.name, ref, f"Clone failed: {e}")
        info = RepoInfo(scan_id=scan_id, url=repo_ref.web_url, name=repo_ref.name, owner=repo_ref.owner, ref=ref,
                        branch=gm.current_branch(repo_dir) or ref, commit_sha=gm.head_sha(repo_dir), scan_timestamp=_now(),
                        shallow=gm.is_shallow(repo_dir), source="github")
        return analyze_directory(repo_dir, info, options, ctx)
    finally:
        if not options.keep_workspace:
            gm.cleanup(ws)


def scan_local_directory(path: Path, options: ScanOptions | None = None, settings: Settings | None = None,
                         db: Database | None = None, progress: Optional[Progress] = None, name: str | None = None) -> dict[str, Any]:
    """Analyse an existing local directory (tests / fixtures only; never reachable from the UI URL box)."""
    options = options or ScanOptions()
    s = settings or get_settings()
    db = db or Database(s.db_path)
    ctx = _Ctx(s, db, progress)
    path = Path(path).resolve()
    top = gm.run_git(["rev-parse", "--show-toplevel"], cwd=path, check=False).stdout.strip()
    is_toplevel = bool(top) and Path(top).resolve() == path
    sha = gm.run_git(["rev-parse", "HEAD"], cwd=path, check=False).stdout.strip() if top else ""
    info = RepoInfo(scan_id=uuid.uuid4().hex[:12], url=f"local-fixture:{path.name}", name=name or path.name, ref=options.ref,
                    branch=gm.current_branch(path) if is_toplevel else None,
                    commit_sha=(sha if is_toplevel else (sha + " (enclosing repository HEAD; scanned path is a subdirectory)" if sha else "unversioned")),
                    scan_timestamp=_now(), shallow=gm.is_shallow(path) if is_toplevel else False, source="local-fixture")
    info.local_path = str(path)
    return analyze_directory(path, info, options, ctx, git_history=is_toplevel)


def _failed(scan_id, url, name, ref, msg) -> dict:
    return {"status": "failed", "error": msg, "repo": {"scan_id": scan_id, "url": url, "name": name, "ref": ref, "commit_sha": "", "scan_timestamp": _now()}}


# ======================================================================================================== pipeline
def analyze_directory(repo_dir: Path, info: RepoInfo, options: ScanOptions, ctx: _Ctx, git_history: bool = True) -> dict[str, Any]:
    s, db = ctx.s, ctx.db
    rules = load_rules(options.rules_path)
    result: dict[str, Any] = {"status": "running", "repo": info.model_dump(), "from_cache": False, "limitations": []}
    prefix = f"{info.scan_id}-{_safe_name(info.name)}"

    # ---- inspect
    ctx.step("inspect", "Inspecting repository (static)")
    insp: InspectionResult = ctx.stage("inspect", lambda: inspect_repository(repo_dir, s), InspectionResult())
    service_dirs = sorted({m["dir"] for m in insp.services} | {"."}) if insp.services else ["."]
    result["inspection"] = {**insp.model_dump(), "headline_languages": headline_languages(insp)}

    # ---- lockfiles
    lock_deps, lock_errors = ctx.stage("lockfiles", lambda: analyze_repository(repo_dir, insp), ([], []), "Parsing manifests and lockfiles")
    result["lockfile_dependencies"] = [d.model_dump() for d in lock_deps]
    result["lockfile_errors"] = lock_errors

    # ---- SBOM via Syft
    def do_sbom():
        out = s.artifacts_dir / "sbom" / f"{prefix}.cdx.json"
        syft = run_syft(repo_dir, out, s)
        return syft
    syft = ctx.stage("sbom", do_sbom, None, "Generating CycloneDX SBOM with Syft")
    sbom_doc: dict = {}
    components: list[Component] = []
    validation: dict = {"valid": False, "errors": ["SBOM not generated"], "warnings": [], "stats": {}}
    inventory_source = "none"
    sbom_path = None
    if syft is not None and syft.ok:
        sbom_doc = load_sbom(syft.sbom_path)
        validation = validate_cyclonedx(sbom_doc)
        components = normalize_components(sbom_doc, repo_dir, service_dirs)
        inventory_source, sbom_path = "syft", syft.sbom_path
        if not validation["valid"]:
            ctx.errors.append({"stage": "sbom", "error": "SBOM failed validation: " + "; ".join(validation["errors"][:3])})
    else:
        reason = (syft.error if syft is not None else "Syft stage failed")
        result["limitations"].append(f"SBOM generation failed ({reason}). Falling back to a lockfile-derived inventory; this is NOT a Syft SBOM and cannot be downloaded as one.")
        components = _components_from_lockfiles(lock_deps)
        inventory_source = "lockfile-fallback" if components else "none"
    result["syft"] = syft.to_dict() if syft is not None else None
    result["sbom"] = {"path": sbom_path, "validation": validation, "serial_number": sbom_doc.get("serialNumber"), "spec_version": sbom_doc.get("specVersion")}
    result["inventory_source"] = inventory_source
    result["sbom_path"] = sbom_path

    # ---- optional enrichment (derived data only)
    enrichment_stats = None
    if options.enrich_metadata and components:
        enrichment_stats = ctx.stage("sbom", lambda: enrich_components(components, ctx.http, ctx.cache), None, "Enriching missing metadata from registries")
    result["enrichment"] = enrichment_stats
    result["components"] = [c.model_dump() for c in components]
    if enrichment_stats and sbom_path:
        derived = derived_enriched_sbom(sbom_doc, result["components"])
        p = s.artifacts_dir / "sbom" / f"{prefix}.enrichment.json"
        p.write_text(json_exporter.dumps(derived), encoding="utf-8")
        result["enrichment_path"] = str(p)

    # ---- quality
    quality = ctx.stage("quality", lambda: analyze_quality(components, sbom_doc, lock_deps, insp, syft_ok=inventory_source == "syft", lock_errors=lock_errors), {}, "Assessing SBOM quality")
    result["quality"] = quality

    # ---- graph
    graph: nx.DiGraph = nx.DiGraph()
    rel: dict = {}

    def do_graph():
        g, binfo = build_graph(sbom_doc, components, lock_deps, service_dirs, info.name)
        v = validate_graph(g, binfo)
        return g, v, classify_all(g)
    gres = ctx.stage("graph", do_graph, None, "Building dependency graph")
    gvalid: dict = {}
    if gres:
        graph, gvalid, rel = gres
    result["graph"] = {**graph_to_json(graph, gvalid), "relationships": rel}

    # ---- vulnerabilities
    def do_vulns():
        osv = OsvClient(ctx.http, ctx.cache, s.osv_batch_size, s.osv_workers)
        nvd = NvdClient(ctx.http, ctx.cache, s.nvd_api_key) if options.use_nvd else None
        kev = KevClient(ctx.http, ctx.cache) if options.use_kev else None
        max_nvd = s.nvd_max_cves_with_key if s.nvd_api_key else s.nvd_max_cves_no_key
        return correlate(components, graph, lock_deps, osv, nvd, kev, max_nvd, info.scan_timestamp, s.max_paths_per_target, s.max_path_depth)
    vres = ctx.stage("vulnerabilities", do_vulns, None, "Querying OSV / NVD / CISA KEV")
    vulns: list[dict] = []
    if vres:
        vulns = [f.model_dump() for f in vres["findings"]]
        result["vuln_coverage"] = vres["coverage"]
        result["source_status"] = vres["source_status"]
    else:
        result["vuln_coverage"] = {}
        result["source_status"] = {"OSV": {"source": "OSV", "state": "failed"}}
        result["limitations"].append("Vulnerability correlation failed; absence of findings here does NOT mean no vulnerabilities.")
    result["vulnerabilities"] = vulns
    st = result["source_status"].get("OSV", {})
    if st.get("state") in ("unavailable", "partial", "failed"):
        result["limitations"].append(f"OSV was {st.get('state')}: vulnerability results are incomplete (packages not queried: see coverage).")

    # ---- typosquatting
    dep_info = {ref: {"type": _overall(r), "roots": [graph.nodes[k].get("label", k) for k in r]} for ref, r in rel.items()}
    typo = ctx.stage("typosquatting", lambda: detect_typosquatting(components, ctx.http if options.registry_checks else None, ctx.cache, dep_info, info.scan_timestamp),
                     {"findings": [], "suppressed": [], "stats": {}}, "Checking package names for typosquatting")
    result["typosquatting"] = [f.model_dump() for f in typo["findings"]]
    result["typosquatting_meta"] = {"suppressed": typo["suppressed"], "stats": typo["stats"]}

    # ---- lockfile changes
    if git_history:
        lres = ctx.stage("lockfile_changes", lambda: detect_lockfile_changes(repo_dir, "HEAD", options.baseline, options.lockfile_commits, info.scan_timestamp),
                         {"changes": [], "findings": [], "comparisons": [], "limitations": ["Lockfile change analysis failed."], "summary": {}}, msg="Comparing lockfiles against Git history")
    else:
        lres = {"changes": [], "findings": [], "comparisons": [], "summary": {},
                "limitations": ["The scanned path is not the top level of a Git repository, so no Git history comparison was possible (nothing inferred)."]}
    result["lockfile_analysis"] = {k: v for k, v in lres.items() if k != "findings"}
    result["lockfile_changes"] = lres["findings"]
    result["limitations"].extend(lres.get("limitations", []))

    # ---- risk + evidence + explanations
    def do_risk():
        return correlate_findings(vulns, result["typosquatting"], result["lockfile_changes"], rules)
    rk = ctx.stage("risk", do_risk, {"assessments": [], "correlations": []}, "Scoring risk (deterministic rules)")
    result["risk_assessments"], result["correlations"] = rk["assessments"], rk["correlations"]
    result["risk_by_root"] = summarize_by_root(vulns, rk["assessments"])
    result["risk_rules_version"] = RULES_VERSION
    sbom_id = sbom_doc.get("serialNumber")
    lock_index = {(d.service_dir, d.ecosystem, d.name, d.version): d.model_dump() for d in lock_deps}
    repo_d = result["repo"]

    def do_explain():
        llm = None
        if options.use_llm and s.llm_api_key:
            llm = lambda sys_, usr: anthropic_call(s.llm_api_key, s.llm_model, sys_, usr)  # noqa: E731
        risks = {a["finding_id"]: a for a in rk["assessments"]}
        out, evidence = {}, {}
        for kind, items, collect in (("vulnerability", vulns, lambda f: collect_vulnerability_evidence(f, repo_d, sbom_id, lock_index)),
                                     ("typosquatting", result["typosquatting"], lambda f: collect_typosquat_evidence(f, repo_d, sbom_id)),
                                     ("lockfile_change", result["lockfile_changes"], lambda f: collect_lockfile_evidence(f, repo_d, sbom_id))):
            for f in items:
                b = normalize_bundle(collect(f))
                evidence[f["finding_id"]] = {k: v for k, v in b.items() if k != "corpus"}
                out[f["finding_id"]] = explain(b, risks[f["finding_id"]], f, llm)
        return out, evidence
    ex = ctx.stage("explain", do_explain, ({}, {}), "Generating evidence-grounded explanations")
    result["explanations"], result["evidence"] = ex

    # ---- summary
    result["summary"] = _summary(result, components)
    result["tool_versions"] = {"scanner": SCANNER_VERSION, "syft": (syft.version if syft else None) or "unavailable", "python": platform.python_version(),
                               "networkx": nx.__version__}
    result["errors"] = [{k: v for k, v in e.items() if k != "trace"} for e in ctx.errors]
    result["timings"] = ctx.timings
    result["status"] = "completed" if not ctx.errors else "completed_with_errors"
    result["limitations"] = list(dict.fromkeys(result["limitations"] + (quality.get("limitations", []) if quality else [])))

    # ---- exports + persistence
    def do_export():
        paths = json_exporter.write_all(result, s.artifacts_dir / "scans", prefix)
        (s.artifacts_dir / "graphs" / f"{prefix}.json").write_text(json_exporter.dumps(graph_export_payload(result)), encoding="utf-8")
        md = report_generator.generate_markdown(result)
        (s.artifacts_dir / "reports" / f"{prefix}-report.md").write_text(md, encoding="utf-8")
        (s.artifacts_dir / "reports" / f"{prefix}-report.html").write_text(report_generator.generate_html(result), encoding="utf-8")
        paths["report_md"] = str(s.artifacts_dir / "reports" / f"{prefix}-report.md")
        paths["report_html"] = str(s.artifacts_dir / "reports" / f"{prefix}-report.html")
        return paths
    result["artifacts"] = ctx.stage("export", do_export, {}, "Writing reports and artifacts")
    ctx.stage("export", lambda: db.save_scan(result), None, "Saving scan to SQLite")
    ctx.step("done", "Scan complete")
    return result


def graph_export_payload(result: dict) -> dict:
    return json_exporter.graph_export(result)


def _overall(r: dict) -> str:
    vals = set(r.values())
    return "direct" if "direct" in vals else "direct_inferred" if "direct_inferred" in vals else "transitive" if "transitive" in vals else "unknown"


def _components_from_lockfiles(lock_deps: list[LockDependency]) -> list[Component]:
    seen: dict[str, Component] = {}
    from sbom.package_extractors.common import parse_purl
    for d in lock_deps:
        if not d.version or d.lockfile.endswith("go.sum"):
            continue
        ref = f"lock:{d.ecosystem}:{d.name}@{d.version}:{d.service_dir}"
        if ref in seen:
            continue
        pp = parse_purl(d.purl) if d.purl else None
        seen[ref] = Component(bom_ref=ref, name=pp["osv_name"] if pp else d.name, version=d.version, purl=d.purl, ecosystem=d.ecosystem,
                              purl_type=pp["type"] if pp else None, locations=[d.lockfile], service_dir=d.service_dir, found_by="lockfile-parser")
    return list(seen.values())


def _summary(result: dict, components: list[Component]) -> dict:
    v = result["vulnerabilities"]
    by_sev: dict[str, int] = {}
    for f in v:
        k = f["severity"] or "UNKNOWN"
        by_sev[k] = by_sev.get(k, 0) + 1
    by_risk: dict[str, int] = {}
    for a in result["risk_assessments"]:
        by_risk[a["label"]] = by_risk.get(a["label"], 0) + 1
    confirmed = [f for f in v if f["affected_status"] == "confirmed_affected"]
    return {
        "components": len([c for c in components if c.type != "file"]),
        "by_ecosystem": result.get("quality", {}).get("components_by_ecosystem", {}),
        "vulnerabilities_confirmed": len(confirmed), "vulnerabilities_unknown": len(v) - len(confirmed),
        "by_cvss_severity": by_sev,
        "vuln_direct": sum(f["dependency_type"].startswith("direct") for f in v), "vuln_transitive": sum(f["dependency_type"] == "transitive" for f in v),
        "kev": sum(f["kev"] for f in v), "with_fix": sum(bool(f["fixed_versions"]) for f in v),
        "typosquatting": len(result["typosquatting"]), "lockfile_findings": len([c for c in result["lockfile_changes"] if c["classification"] != "insufficient_baseline"]),
        "by_risk": by_risk, "services": len(result["inspection"].get("services", [])),
    }
