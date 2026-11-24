"""Specialist agents. Each agent owns a set of pipeline steps, uses tools (Git, Syft, OSV, NetworkX, ...), reports every
observation/decision through the Runtime and leaves its outputs on the shared ScanState.

Reasoning is rule-based and deterministic. An LLM is used only where free text is produced (Risk Agent explanations),
and only when an API key is configured; its output is validated against the collected evidence.
"""
from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

import networkx as nx

from agents.runtime import Runtime
from core import git_manager as gm
from core.models import Component, InspectionResult, LockDependency, RepoInfo
from core.repository_inspector import headline_languages, inspect_repository, own_package_identities
from explainability.explanation_engine import explain
from llm.client import from_settings as llm_from_settings, CALL_LOG
from evidence.store import EvidenceStore
from graph.dependency_tracer import classify_all
from graph.graph_builder import build_graph
from graph.graph_exporter import graph_to_json
from graph.graph_validator import validate_graph
from reporting import json_exporter, report_generator
from risk_analysis.evidence_collector import collect_lockfile_evidence, collect_typosquat_evidence, collect_vulnerability_evidence
from risk_analysis.evidence_normalizer import normalize_bundle
from risk_analysis.finding_correlator import correlate_findings, summarize_by_root
from sbom.cyclonedx_validator import load_sbom, normalize_components, validate_cyclonedx
from sbom.lockfile_analyzer import analyze_repository, supported_files
from sbom.package_extractors.common import parse_purl
from sbom.quality_analyzer import analyze_quality
from sbom.scanner_engine import SCANNER_LABELS, available_scanners, generate_sbom
from sbom.syft_runner import run_syft
from sbom.trivy_runner import run_trivy
from suspicious_changes.lockfile_change_detector import detect_lockfile_changes
from suspicious_changes.typosquatting_detector import detect_typosquatting
from vulnerability.kev_client import KevClient
from vulnerability.nvd_client import NvdClient
from vulnerability.osv_client import OsvClient
from vulnerability.verification import cross_check
from vulnerability.vulnerability_correlator import correlate

LLM_EXPLAIN_TOP_N = 15


@dataclass
class ScanState:
    repo_dir: Path
    info: RepoInfo
    options: Any
    ctx: Any  # settings, db, cache, http
    rules: dict
    git_history: bool = True
    result: dict = field(default_factory=dict)
    insp: InspectionResult = field(default_factory=InspectionResult)
    service_dirs: list[str] = field(default_factory=lambda: ["."])
    lock_deps: list[LockDependency] = field(default_factory=list)
    lock_errors: list[dict] = field(default_factory=list)
    syft: Any = None  # result of the external scanner that produced the SBOM (Syft or Trivy), if any
    sbom_tool: dict = field(default_factory=dict)
    fused_path: Optional[str] = None
    fusion: dict = field(default_factory=dict)  # metadata fusion report
    pkgrisk: dict = field(default_factory=lambda: {"findings": [], "provenance": {}})
    pipe: dict = field(default_factory=lambda: {"findings": [], "images": [], "actions": [], "files": [], "summary": {}})
    evidence: EvidenceStore = field(default_factory=EvidenceStore)
    source_index: Any = None  # reachability.scanners.SourceIndex, built lazily by the Investigator tools
    epss: dict = field(default_factory=dict)
    investigations: dict = field(default_factory=dict)
    remediation: dict = field(default_factory=dict)
    rem_sims: dict = field(default_factory=dict)
    sbom_files: list = field(default_factory=list)  # [{label, path}] files shown in the SBOM viewer
    sbom_doc: dict = field(default_factory=dict)
    sbom_path: Optional[str] = None
    inventory_source: str = "none"
    components: list[Component] = field(default_factory=list)
    quality: dict = field(default_factory=dict)
    graph: nx.DiGraph = field(default_factory=nx.DiGraph)
    rel: dict = field(default_factory=dict)
    osv: Optional[OsvClient] = None
    vres: Optional[dict] = None
    vulns: list[dict] = field(default_factory=list)
    typo: dict = field(default_factory=lambda: {"findings": [], "suppressed": [], "stats": {}})
    lres: dict = field(default_factory=lambda: {"changes": [], "findings": [], "comparisons": [], "summary": {}, "limitations": []})
    risk: dict = field(default_factory=lambda: {"assessments": [], "correlations": []})
    prefix: str = ""


# ====================================================================================================== Recon
class ReconAgent:
    name = "Recon Agent"

    def discover(self, st: ScanState, rt: Runtime) -> None:
        with rt.step("discover", f"Scanning {st.repo_dir.name} for manifests, lockfiles and configuration files (static, nothing is executed)") as b:
            st.insp = inspect_repository(st.repo_dir, st.ctx.s)
            insp = st.insp
            for m in sorted(insp.manifests, key=lambda m: (m.service_dir, m.name)):
                rt.progress("discover", f"Found {m.kind}: {m.path}  ({m.ecosystem})", path=m.path, kind=m.kind, ecosystem=m.ecosystem)
            for d in insp.dockerfiles + insp.container_files:
                rt.progress("discover", f"Found container config: {d} (recorded as context only)", path=d)
            for c in insp.ci_files:
                rt.progress("discover", f"Found CI/CD config: {c} (recorded as context only)", path=c)
            b["message"] = (f"{len(insp.manifests)} manifest/lock files, {len(insp.dockerfiles) + len(insp.container_files)} container files, "
                            f"{len(insp.ci_files)} CI files in {insp.total_files} files")

    def classify(self, st: ScanState, rt: Runtime) -> None:
        with rt.step("classify") as b:
            insp = st.insp
            st.service_dirs = sorted({s["dir"] for s in insp.services} | {"."}) if insp.services else ["."]
            langs = headline_languages(insp)
            rt.observe("classify", "Languages: " + (", ".join(f"{k} ({insp.languages[k]['files']} files)" for k in langs[:6]) or "none detected"))
            rt.observe("classify", "Ecosystems: " + (", ".join(insp.ecosystems) or "none") + " | Frameworks: " + (", ".join(sorted({h.name for h in insp.frameworks})) or "none"))
            rt.observe("classify", f"{len(insp.services)} service root(s): " + ", ".join(s["dir"] for s in insp.services[:8]))
            b["message"] = f"{len(langs)} languages, {len(insp.ecosystems)} ecosystems, {len(insp.services)} services"


# ====================================================================================================== SBOM
class SBOMAgent:
    name = "SBOM Agent"

    def lockfiles(self, st: ScanState, rt: Runtime) -> None:
        with rt.step("lockfiles") as b:
            st.lock_deps, st.lock_errors = analyze_repository(st.repo_dir, st.insp)
            by: dict[str, int] = {}
            for d in st.lock_deps:
                by[d.lockfile] = by.get(d.lockfile, 0) + 1
            for f, n in sorted(by.items()):
                rt.progress("lockfiles", f"Parsed {f}: {n} dependency records", file=f, count=n)
            for e in st.lock_errors:
                rt.warn("lockfiles", f"Could not parse {e['file']}: {e['error']}")
            b["message"] = f"{len(st.lock_deps)} dependency records from {len(by)} files"

    def generate(self, st: ScanState, rt: Runtime) -> None:
        """Rule-based scanner selection: try Syft, then Trivy, then the built-in lockfile rule engine (see sbom/scanner_engine)."""
        s = st.ctx.s
        choice = getattr(st.options, "sbom_scanner", "auto") or "auto"
        avail = available_scanners(s)
        with rt.step("sbom_generate", f"Selecting SBOM scanner (requested: {SCANNER_LABELS.get(choice, choice)})") as b:
            rt.observe("sbom_generate", "Scanners available: " + ", ".join(f"{k} ({'found' if v else 'not installed'})" for k, v in avail.items()))
            out = generate_sbom(st.repo_dir, st.lock_deps, s.artifacts_dir / "sbom", st.prefix, choice, s, st.info.name, st.info.commit_sha)
            for a in out.attempts:
                if a["ok"]:
                    rt.observe("sbom_generate", f"{a['scanner']} produced a CycloneDX SBOM" + (f" (v{a['version']}, {a['duration_s']}s)" if a["version"] else ""), command=a["command"])
                else:
                    rt.warn("sbom_generate", f"{a['scanner']} unavailable or failed: {a['error']}")
            if out.scanner is None:
                st.inventory_source = "none"
                st.sbom_tool = {"requested": choice, "used": None, "attempts": out.attempts}
                st.result["limitations"].append("No SBOM could be generated.")
                b["message"] = "no SBOM generated"
                return
            failed_first = [a["scanner"] for a in out.attempts if not a["ok"]]
            if failed_first:
                rt.decide("sbom_generate", f"Fall back to {out.scanner}", reason=f"{', '.join(failed_first)} did not produce an SBOM; the next scanner in the chain was used.", agent="Supervisor")
            if out.scanner == "builtin":
                rt.decide("sbom_generate", "Use the built-in rule engine", reason="Generates CycloneDX from the parsed lockfiles/manifests with documented rules R1-R6; "
                          "the lockfile-vs-SBOM comparison is therefore not independent.", agent="Supervisor")
                st.result["limitations"].append("The SBOM was produced by the built-in rule engine from lockfiles/manifests (no Syft/Trivy installed or both failed): "
                                                "packages that are not declared in a parsed lockfile (binaries, OS packages, vendored code) are not inventoried.")
            if out.engine_stats.get("skipped_unpinned"):
                n = out.engine_stats["skipped_unpinned"]
                rt.warn("sbom_generate", f"Rule R1: {n} declared dependency record(s) have no pinned version (manifest ranges without a lockfile) and are not inventoried.")
                st.result["limitations"].append(f"{n} dependency declaration(s) without a pinned version were not inventoried by the rule engine; add a lockfile or install Syft/Trivy for better coverage.")
            st.syft = out.run
            st.sbom_doc, st.sbom_path, st.inventory_source = out.doc, out.raw_path, out.scanner
            st.sbom_tool = {"requested": choice, "used": out.scanner, "attempts": out.attempts, "engine_stats": out.engine_stats,
                            "version": out.run.version if out.run else None, "run": out.run.to_dict() if out.run else None, "available": {k: bool(v) for k, v in avail.items()}}
            b["message"] = f"{out.scanner}: CycloneDX {out.doc.get('specVersion')} ({len(out.doc.get('components', []))} components)"

    def validate(self, st: ScanState, rt: Runtime) -> None:
        if not st.sbom_doc:
            rt.skip("sbom_validate", "no SBOM to validate")
            st.result["sbom"] = {"path": None, "validation": {"valid": False, "errors": ["SBOM not generated"], "warnings": [], "stats": {}}}
            return
        with rt.step("sbom_validate") as b:
            v = validate_cyclonedx(st.sbom_doc)
            st.components = normalize_components(st.sbom_doc, st.repo_dir, st.service_dirs, tool=st.inventory_source)
            own = own_package_identities(st.repo_dir, st.insp)
            for c in st.components:
                ids = own.get(c.service_dir or ".", set())
                if any(c.name == n and (v is None or c.version in (None, v)) for n, v in ids):
                    c.is_self = True
            selfs = [c for c in st.components if c.is_self]
            if selfs:
                rt.observe("sbom_validate", "Application's own package(s) recognised and excluded from dependency matching: " + ", ".join(f"{c.name}@{c.version}" for c in selfs))
            st.result["sbom"] = {"path": st.sbom_path, "validation": v, "serial_number": st.sbom_doc.get("serialNumber"), "spec_version": st.sbom_doc.get("specVersion")}
            for e in v["errors"]:
                rt.warn("sbom_validate", f"Validation error: {e}")
            if not v["valid"]:
                rt.fail("sbom_validate", "SBOM failed validation: " + "; ".join(v["errors"][:3]))
                return
            rt.observe("sbom_validate", f"Valid CycloneDX {v['stats']['spec_version']}: {v['stats']['components']} components, {v['stats']['dependencies']} dependency records, {len(v['warnings'])} warnings")
            b["message"] = "valid"

    @staticmethod
    def wants_second_pass(st: ScanState) -> bool:
        """Routing predicate for the graph's conditional edge (auto mode, external primary scanner, SBOM misses lockfile packages)."""
        return ((getattr(st.options, "sbom_scanner", "auto") or "auto") == "auto" and st.inventory_source in ("syft", "trivy")
                and st.quality.get("inventory_status") == "incomplete")

    def second_pass(self, st: ScanState, rt: Runtime) -> bool:
        """Adaptive step: if the primary SBOM misses lockfile packages and another installed scanner has not run, run it and merge."""
        s = st.ctx.s
        if not self.wants_second_pass(st):
            return False
        q = st.quality
        other = "trivy" if st.inventory_source == "syft" else "syft"
        avail = available_scanners(s)
        if not avail.get(other):
            rt.observe("quality", f"{q['lockfile_missing_from_sbom_count']} lockfile package(s) are missing from the {st.inventory_source} SBOM; {other} is not installed, so no second opinion is possible", agent="Supervisor")
            return False
        rt.decide("quality", f"Run {other} as a second inventory and merge", reason=f"{q['lockfile_missing_from_sbom_count']} lockfile package(s) are missing from the {st.inventory_source} SBOM.", agent="Supervisor")
        out_dir = s.artifacts_dir / "sbom"
        res = (run_syft if other == "syft" else run_trivy)(st.repo_dir, out_dir / f"{st.prefix}.{other}.cdx.json", s)
        st.sbom_tool.setdefault("attempts", []).append({"scanner": other, "ok": res.ok, "version": res.version, "duration_s": res.duration_s, "error": res.error,
                                                        "command": " ".join(res.command) if res.command else None, "role": "second-pass"})
        if not res.ok:
            rt.warn("quality", f"Second-pass {other} failed: {res.error}")
            return False
        from sbom.adapters import get_adapter
        from sbom.merge import merge_inventories
        sec_doc = get_adapter(other).canonicalize(load_sbom(res.sbom_path))
        sec = normalize_components(sec_doc, st.repo_dir, st.service_dirs, tool=other)
        st.sbom_doc, st.components, stats = merge_inventories(st.sbom_doc, st.components, sec_doc, sec)
        merged_path = out_dir / f"{st.prefix}.merged.cdx.json"
        merged_path.write_text(json.dumps(st.sbom_doc, indent=2), encoding="utf-8")
        st.sbom_files = [{"label": f"{st.inventory_source} (primary, raw)", "path": st.sbom_path}, {"label": f"{other} (second pass, raw)", "path": res.sbom_path},
                         {"label": "merged canonical (used for analysis)", "path": str(merged_path)}]
        st.inventory_source = f"{st.inventory_source}+{other}"
        st.sbom_tool.update(merged=stats, used=st.inventory_source)
        rt.observe("quality", f"Merged inventories: {stats['matched']} components confirmed by both, {stats['added_from_secondary']} added by {other}; analysis now uses {stats['total']} components")
        st.quality = analyze_quality(st.components, st.sbom_doc, st.lock_deps, st.insp, syft_ok=True, lock_errors=st.lock_errors)
        rt.observe("quality", f"Re-assessed inventory: {st.quality['inventory_status']}")
        return True

    def fuse_metadata(self, st: ScanState, rt: Runtime) -> None:
        """Fill every metadata field from the most trustworthy source, record provenance, verify digests, write the fused CycloneDX file."""
        s, o = st.ctx.s, st.options
        if not st.sbom_doc:
            rt.skip("metadata", "no SBOM to enrich")
            return
        with rt.step("metadata", "Fusing lockfile, scanner and registry metadata (field-level provenance)") as b:
            from sbom.fusion.engine import fuse
            from sbom.fusion.resolver import resolve
            from sbom.fusion.writer import write_fused
            if o.metadata_registry:
                res_ = resolve(st.lock_deps, st.ctx.http, st.ctx.cache, budget_s=min(90.0, s.metadata_budget_s))
                rs = res_["stats"]
                st.result["registry_resolution"] = rs
                if rs["candidates"]:
                    rt.decide("metadata", f"Resolve transitive dependencies of {rs['candidates']} pinned direct dependenc(ies) via deps.dev", reason="These services have no lockfile for that ecosystem, so the transitive closure "
                              "is otherwise unknown; resolution is done by the registry, nothing from the repository is executed.", agent="Supervisor")
                    rt.observe("metadata", f"Registry resolution: {rs['resolved']} resolved, {rs['not_found']} not found, {rs['unavailable']} unavailable -> {rs['derived_packages']} additional transitive package(s)")
                if res_["derived"]:
                    from sbom.builtin_generator import generate_cyclonedx
                    from sbom.merge import merge_inventories
                    ddoc, _ = generate_cyclonedx(res_["derived"], st.info.name, st.info.commit_sha)
                    dcomps = normalize_components(ddoc, st.repo_dir, st.service_dirs, tool="builtin")
                    for c_ in dcomps:
                        c_.sources, c_.resolution = ["registry-resolver"], "registry-resolved"
                    st.lock_deps.extend(res_["derived"])
                    st.sbom_doc, st.components, mstats = merge_inventories(st.sbom_doc, st.components, ddoc, dcomps)
                    st.result["limitations"].append(f"{rs['derived_packages']} transitive package(s) were resolved by the deps.dev registry for manifest-only services (no lockfile): each direct dependency was "
                                                    "resolved on its own, so the project's real version mediation may differ. They are labelled 'registry-resolved'.")
            rep = fuse(st.components, st.lock_deps, st.ctx.http if o.metadata_registry else None, st.ctx.cache, registry=bool(o.metadata_registry),
                       budget_s=s.metadata_budget_s, on_progress=lambda m: rt.progress("metadata", m))
            st.fusion = rep
            cov = rep["coverage"]
            rt.observe("metadata", "Coverage (scanner -> after fusion): " + ", ".join(f"{f} {c['before']}->{c['after']}" for f, c in cov.items()) + f" of {rep['components']} components")
            reg = rep.get("registry_phase", {})
            if reg.get("skipped"):
                rt.decide("metadata", "Skip registry look-ups", reason="Disabled in the scan options; only lockfile-recorded metadata was used.", agent="Supervisor")
            else:
                rt.observe("metadata", f"Registries: {reg.get('fetched', 0)} fetched, {reg.get('from_cache', 0)} from cache, {reg.get('not_found', 0)} not found, {reg.get('unavailable', 0)} unavailable"
                           + (f", {reg['skipped_budget']} skipped (time budget)" if reg.get("skipped_budget") else ""))
                if reg.get("hosts_tripped"):
                    rt.warn("metadata", "Registry host(s) unreachable, skipped after repeated failures: " + ", ".join(reg["hosts_tripped"]))
                    st.result["limitations"].append("Some registries were unreachable; metadata for those packages may be incomplete (see Metadata tab for per-field reasons).")
                if reg.get("unsupported_ecosystems"):
                    rt.observe("metadata", "No registry client for: " + ", ".join(reg["unsupported_ecosystems"]) + " (only lockfile/scanner metadata available)")
            integ = rep["integrity"]
            rt.observe("metadata", "Integrity: " + ", ".join(f"{k} {v}" for k, v in sorted(integ.items())))
            if rep["integrity_mismatches"]:
                rt.warn("metadata", f"{len(rep['integrity_mismatches'])} lockfile digest(s) differ from the registry's digest for the same version - possible tampered lockfile or republished package")
                rt.decide("metadata", "Surface integrity mismatches prominently", reason="A pinned digest that does not match the registry is a strong supply-chain signal.", agent="Supervisor")
            if rep["install_script_packages"]:
                rt.observe("metadata", f"{len(rep['install_script_packages'])} package(s) run install-time scripts")
            out_dir = s.artifacts_dir / "sbom"
            fused = write_fused(st.sbom_doc, st.components, rep, st.inventory_source)
            path = out_dir / f"{st.prefix}.fused.cdx.json"
            path.write_text(json.dumps(fused, indent=2), encoding="utf-8")
            v = validate_cyclonedx(fused)
            for e in v["errors"]:
                rt.warn("metadata", f"Fused document validation error: {e}")
            raw = st.sbom_files or [{"label": f"{st.inventory_source} (raw scanner output)", "path": st.sbom_path}]
            st.sbom_files = [{"label": "FUSED CycloneDX (scanner + lockfile + registries, with provenance)", "path": str(path)}] + raw
            st.fused_path, st.sbom_doc, st.sbom_path = str(path), fused, str(path)  # the fused file is the primary SBOM; raw files stay in sbom_files
            st.result["sbom"] = {**st.result.get("sbom", {}), "fused_validation": v, "fused_path": str(path)}
            st.quality = analyze_quality(st.components, st.sbom_doc, st.lock_deps, st.insp, syft_ok=True, lock_errors=st.lock_errors)
            b["message"] = f"avg completeness {rep['average_completeness']:.0%}; integrity: " + ", ".join(f"{k} {v}" for k, v in sorted(integ.items()))

    def quality(self, st: ScanState, rt: Runtime) -> None:
        with rt.step("quality") as b:
            st.quality = analyze_quality(st.components, st.sbom_doc, st.lock_deps, st.insp, syft_ok=bool(st.sbom_doc), lock_errors=st.lock_errors)
            q = st.quality
            if st.inventory_source == "builtin":
                q.setdefault("limitations", []).append("SBOM and lockfile inventory come from the same parsers, so the lockfile-vs-SBOM comparison cannot reveal missed packages.")
            rt.observe("quality", f"Inventory: {q['inventory_status']}; relationships: {q['dependency_relationships']}; metadata: {q['metadata_status']}; "
                       f"{q['lockfile_missing_from_sbom_count']} lockfile packages missing from SBOM; {q['unresolved_components']} unresolved components")
            if q["lockfile_missing_from_sbom_count"]:
                rt.decide("quality", "Flag the SBOM as incomplete", reason="Lockfile packages were not discovered by Syft.", agent="Supervisor")
            b["message"] = q["inventory_status"]


def _components_from_lockfiles(lock_deps: list[LockDependency]) -> list[Component]:
    seen: dict[str, Component] = {}
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


# ====================================================================================================== Graph
class GraphAgent:
    name = "Graph Agent"

    def build(self, st: ScanState, rt: Runtime) -> None:
        with rt.step("graph") as b:
            g, binfo = build_graph(st.sbom_doc, st.components, st.lock_deps, st.service_dirs, st.info.name)
            val = validate_graph(g, binfo)
            st.graph, st.rel = g, classify_all(g)
            st.result["graph"] = {**graph_to_json(g, val), "relationships": st.rel}
            for w in val["warnings"]:
                rt.observe("graph", w)
            direct = sum(1 for per in st.rel.values() if any(v.startswith("direct") for v in per.values()))
            b["message"] = f"{val['components']} packages, {val['edges']} edges, {len(val['roots'])} root(s); {direct} direct, {len(st.rel) - direct} transitive-only"


# ====================================================================================================== Vulnerability
class VulnerabilityAgent:
    name = "Vulnerability Agent"
    ORDER = ["osv", "enrich", "trace"]

    def run(self, st: ScanState, rt: Runtime) -> None:
        o, s, ctx = st.options, st.ctx.s, st.ctx
        eligible = [c for c in st.components if c.ecosystem and c.version and c.type != "file"]
        if not eligible:
            for step in self.ORDER:
                rt.skip(step, "no components with a known ecosystem and version")
            st.result.update(vuln_coverage={}, source_status={"OSV": {"source": "OSV", "state": "not_queried"}})
            return
        st.osv = OsvClient(ctx.http, ctx.cache, s.osv_batch_size, s.osv_workers)

        def on_step(stage: str, msg: str) -> None:
            idx = self.ORDER.index(stage)
            for earlier in self.ORDER[:idx]:
                rt.finish_open(earlier, "done")
            rt.begin(stage, msg)

        for attempt in (1, 2):
            osv = st.osv if attempt == 1 else OsvClient(ctx.http, ctx.cache, s.osv_batch_size, s.osv_workers)
            st.osv = osv
            nvd = NvdClient(ctx.http, ctx.cache, s.nvd_api_key) if o.use_nvd else None
            kev = KevClient(ctx.http, ctx.cache) if o.use_kev else None
            cap = s.nvd_max_cves_with_key if s.nvd_api_key else s.nvd_max_cves_no_key
            try:
                st.vres = correlate(st.components, st.graph, st.lock_deps, osv, nvd, kev, cap, st.info.scan_timestamp, s.max_paths_per_target,
                                    s.max_path_depth, on_step=on_step)
            except Exception as e:
                for step in self.ORDER:
                    if rt.status[step] == "running":
                        rt.fail(step, f"{type(e).__name__}: {str(e)[:200]}")
                st.vres = None
                break
            state = st.vres["source_status"]["OSV"]["state"]
            if state in ("unavailable", "partial") and attempt == 1:
                rt.decide("osv", "Retry OSV once after a short pause", reason=f"OSV state was '{state}'; packages that already succeeded are cached so only the missing ones are re-queried.", agent="Supervisor")
                time.sleep(3)
                continue
            break
        if st.vres is None:
            st.result["limitations"].append("Vulnerability correlation failed; absence of findings here does NOT mean no vulnerabilities.")
            st.result.update(vuln_coverage={}, source_status={"OSV": {"source": "OSV", "state": "failed"}})
            return
        st.vulns = [f.model_dump() for f in st.vres["findings"]]
        if st.pipe and st.pipe.get("container_findings"):
            st.vulns.extend(st.pipe["container_findings"])
        st.result.update(vuln_coverage=st.vres["coverage"], source_status=st.vres["source_status"])
        cov = st.vres["coverage"]
        rt.observe("osv", f"{cov['queried_unique_packages']} unique packages queried; {cov['advisories_returned']} advisories returned; "
                   f"{cov['confirmed']} confirmed, {cov['not_affected']} not affected after local range validation, {cov['unknown']} unconfirmed; "
                   f"{cov['unscanned_components']} components not queryable")
        nvd_s = st.vres["source_status"]["NVD"]
        if nvd_s.get("skipped_over_cap"):
            rt.decide("enrich", f"Limit NVD lookups to {nvd_s['requested'] + nvd_s['from_cache']} CVEs", reason="No NVD_API_KEY: the public rate limit allows only a few requests; "
                      f"CVEs without any CVSS score were prioritised; {nvd_s['skipped_over_cap']} skipped.", agent="Supervisor")
        if not (o.use_nvd or o.use_kev):
            rt.progress("enrich", "NVD and KEV disabled by options")
        for step in self.ORDER:
            rt.finish_open(step, "done")
        tr = [f for f in st.vulns if f["dependency_type"] == "transitive"]
        rt.observe("trace", f"{len(tr)} findings are transitive; {len({p for f in tr for p in f['source_packages']})} direct dependencies introduce them")
        st.result["osv_name_route"] = st.vres["osv_name_route"]


class VerificationAgent:
    name = "Verification Agent"

    def run(self, st: ScanState, rt: Runtime) -> None:
        if st.vres is None or st.osv is None or not st.vres.get("osv_name_route"):
            rt.skip("verify", "no OSV results to verify")
            return
        if st.vres["source_status"]["OSV"]["state"] in ("unavailable", "failed"):
            rt.skip("verify", "OSV unreachable")
            return
        with rt.step("verify", "Re-querying every PURL through OSV's PURL route and comparing with the name/version route") as b:
            res = cross_check(st.osv, st.vres["osv_name_route"], st.vres["findings"])
            st.vulns = [f.model_dump() for f in st.vres["findings"]]
        if st.pipe and st.pipe.get("container_findings"):
            st.vulns.extend(st.pipe["container_findings"])
            st.result["verification"] = res
            rt.observe("verify", f"{res['routes_agree']}/{res['components_checked']} components returned identical advisory sets by both routes; "
                       f"{res['findings_cross_verified']}/{res['findings_checked']} findings independently reproduced")
            if res["disagreement_count"]:
                rt.warn("verify", f"{res['disagreement_count']} component(s) differ between the two routes (listed in the Ground Truth view)")
            b["message"] = f"{res['findings_cross_verified']}/{res['findings_checked']} findings cross-verified"


# ====================================================================================================== Threat
class ThreatAgent:
    name = "Threat Agent"

    def typosquat(self, st: ScanState, rt: Runtime) -> None:
        o = st.options
        with rt.step("typosquat") as b:
            dep = {r: {"type": _overall(v), "roots": [st.graph.nodes[k].get("label", k) for k in v]} for r, v in st.rel.items()}
            st.typo = detect_typosquatting(st.components, st.ctx.http if o.registry_checks else None, st.ctx.cache, dep, st.info.scan_timestamp)
            stt = st.typo["stats"]
            rt.observe("typosquat", f"{stt.get('unique_packages_checked', 0)} package names compared; {stt.get('candidates', 0)} similarity candidates; "
                       f"{stt.get('registry_checks', 0)} verified against the registry; {stt.get('suppressed_established', 0)} suppressed as established packages")
            if stt.get("candidates") and not o.registry_checks:
                rt.decide("typosquat", "Cap uncorroborated name matches at 'low' evidence", reason="Registry checks are disabled.", agent="Supervisor")
            b["message"] = f"{len(st.typo['findings'])} suspicious package name(s)"

    def package_risk(self, st: ScanState, rt: Runtime) -> None:
        from suspicious_changes.package_risk import assess
        with rt.step("package_risk", "Checking fused package metadata for integrity, install-script, recency, deprecation and dependency-confusion signals") as b:
            st.pkgrisk = assess(st.components, st.info.scan_timestamp)
            fs = st.pkgrisk["findings"]
            for f in fs:
                f["evidence_id"] = st.evidence.add("registry", "package-risk", f["finding_id"], f"{f['rule_id']}: {f['title']}", {"rule": f["rule_id"], "package": f["subject"]})
            pv = st.pkgrisk["provenance"]
            rt.observe("package_risk", f"{len(fs)} signal(s); build provenance published for {pv['attested']} of {pv['with_registry_data']} packages with registry data (presence only, not cryptographically verified)")
            if any(f["rule_id"] == "PKG-INT" for f in fs):
                rt.decide("package_risk", "Escalate lockfile digest mismatches", reason="A pinned digest that does not match the registry is a strong supply-chain signal.", agent="Supervisor")
            b["message"] = f"{len(fs)} package risk signal(s)"

    def lockfile_history(self, st: ScanState, rt: Runtime) -> None:
        o = st.options
        if not st.git_history:
            rt.skip("lockfile_history", "not the top level of a Git repository")
            st.lres["limitations"] = ["The scanned path is not the top level of a Git repository, so no Git history comparison was possible (nothing inferred)."]
            return
        with rt.step("lockfile_history", f"Comparing the {o.lockfile_commits} most recent commit(s) with their parent{' / explicit baseline' if o.baseline else ''}") as b:
            st.lres = detect_lockfile_changes(st.repo_dir, "HEAD", o.baseline, o.lockfile_commits, st.info.scan_timestamp)
            sm = st.lres.get("summary") or {}
            for c in st.lres.get("comparisons", []):
                rt.progress("lockfile_history", f"{c['commit'][:8]} vs {(c['baseline'] or 'none')[:8]}: {c['status']}; lockfiles changed: {', '.join(c.get('lockfiles_changed', [])) or 'none'}")
            for lim in st.lres.get("limitations", []):
                rt.warn("lockfile_history", lim)
            if sm.get("potentially_suspicious"):
                rt.decide("lockfile_history", f"Escalate {sm['potentially_suspicious']} potentially suspicious change(s) to risk scoring",
                          reason="Integrity/source anomalies were found in Git history.", agent="Supervisor")
            b["message"] = f"{sm.get('total_changes', 0)} changes: {sm.get('potentially_suspicious', 0)} suspicious, {sm.get('unexplained_change', 0)} unexplained"


def _overall(r: dict) -> str:
    vals = set(r.values())
    return "direct" if "direct" in vals else "direct_inferred" if "direct_inferred" in vals else "transitive" if "transitive" in vals else "unknown"


# ====================================================================================================== Risk
class RiskAgent:
    name = "Risk Agent"

    def score(self, st: ScanState, rt: Runtime) -> None:
        with rt.step("risk") as b:
            st.risk = correlate_findings(
                st.vulns,
                [f.model_dump() for f in st.typo["findings"]],
                st.lres["findings"],
                st.rules,
                st.pipe["findings"] + st.pkgrisk["findings"],
                source_index=st.source_index,
                repo_dir=getattr(st, "repo_dir", None),
            )
            res = st.result
            res["risk_assessments"], res["correlations"] = st.risk["assessments"], st.risk["correlations"]
            res["risk_by_root"] = summarize_by_root(st.vulns, st.risk["assessments"])
            counts: dict[str, int] = {}
            for a in st.risk["assessments"]:
                counts[a["label"]] = counts.get(a["label"], 0) + 1
            rt.observe("risk", "Risk labels: " + ", ".join(f"{k} {v}" for k, v in sorted(counts.items(), key=lambda kv: ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"].index(kv[0]))))
            for c in st.risk["correlations"]:
                rt.decide("risk", c["note"], reason="Independent detectors agree on the same package.", agent="Supervisor")
            b["message"] = f"{len(st.risk['assessments'])} findings scored"

    def explain(self, st: ScanState, rt: Runtime) -> None:
        s, o = st.ctx.s, st.options
        with rt.step("explain") as b:
            llm = None
            client = llm_from_settings(s) if o.use_llm else None
            if client:
                llm = lambda sys_, usr: client.complete(sys_, usr, max_tokens=1500)  # noqa: E731
            elif o.use_llm:
                rt.warn("explain", "LLM explanations requested but LLM_API_KEY is not set - using deterministic templates")
            risks = {a["finding_id"]: a for a in st.risk["assessments"]}
            top = {a["finding_id"] for a in sorted(st.risk["assessments"], key=lambda a: -a["score"])[:LLM_EXPLAIN_TOP_N]}
            if llm:
                rt.decide("explain", f"Use the LLM only for the {LLM_EXPLAIN_TOP_N} highest-risk findings", reason="Bounds cost; every LLM section is validated against evidence and falls back to templates.", agent="Supervisor")
            typos = [f.model_dump() for f in st.typo["findings"]]
            sbom_id = st.sbom_doc.get("serialNumber")
            lock_index = {(d.service_dir, d.ecosystem, d.name, d.version): d.model_dump() for d in st.lock_deps}
            repo_d = st.result["repo"]
            out, evidence = {}, {}
            for items, collect in ((st.vulns, lambda f: collect_vulnerability_evidence(f, repo_d, sbom_id, lock_index)),
                                   (typos, lambda f: collect_typosquat_evidence(f, repo_d, sbom_id)),
                                   (st.lres["findings"], lambda f: collect_lockfile_evidence(f, repo_d, sbom_id))):
                for f in items:
                    bundle = normalize_bundle(collect(f))
                    evidence[f["finding_id"]] = {k: v for k, v in bundle.items() if k != "corpus"}
                    out[f["finding_id"]] = explain(bundle, risks[f["finding_id"]], f, llm if f["finding_id"] in top else None)
            for f in st.pipe["findings"] + st.pkgrisk["findings"]:
                a = risks.get(f["finding_id"])
                if not a:
                    continue
                out[f["finding_id"]] = {"headline": f"{a['label']} risk - {f['title']}", "source": "template", "validation": {"grounded": True, "removed_sections": [], "checked": "template"},
                                        "evidence_ids": [f["evidence_id"]] if f.get("evidence_id") else [],
                                        "sections": {"impact": f["why"], "how_entered": f"{f['file']}" + (f":{f['line']}" if f["line"] else "") + (f" - `{f['snippet']}`" if f["snippet"] else ""),
                                                     "direct_transitive": (f"package signal {f['rule_id']} for {f['subject']}" if f.get("kind") == "package_risk" else f"{f['ecosystem']} configuration ({f['rule_id']}), not a package dependency"), "remediation": f["remediation"]}}
                evidence[f["finding_id"]] = {"kind": f.get("kind", "pipeline"), "rule": f["rule_id"], "file": f["file"], "line": f["line"], "evidence_id": f.get("evidence_id")}
            st.result["explanations"], st.result["evidence"] = out, evidence
            replaced = sum(len(e["validation"].get("removed_sections", [])) for e in out.values())
            if replaced:
                rt.observe("explain", f"{replaced} LLM-written section(s) failed grounding checks and were replaced by templates")
            b["message"] = f"{len(out)} explanations ({sum(1 for e in out.values() if e['source'] != 'template')} LLM-assisted)"
        st.result["typosquatting"] = typos


# ====================================================================================================== Analyst
def llm_log() -> list:
    """Outgoing LLM calls recorded by the client (size + hash only), for the disclosure section."""
    return [dict(c) for c in CALL_LOG]


SEV = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, None: 0}


class AnalystAgent:
    name = "Analyst Agent"

    def summarize(self, st: ScanState, rt: Runtime) -> None:
        with rt.step("summary") as b:
            res = st.result
            res["source_package_view"] = source_package_view(st.vulns, {a["finding_id"]: a for a in st.risk["assessments"]})
            v = st.vulns
            sm = res["summary"] = _summary(st, res)
            crit = sum(1 for f in v if f["severity"] == "CRITICAL")
            trans = [f for f in v if f["dependency_type"] == "transitive"]
            lines = [f"{sm['components']} components analysed; {sm['vulnerabilities_confirmed']} confirmed vulnerability findings "
                     f"({crit} CRITICAL by CVSS), {sm['vuln_direct']} in direct and {sm['vuln_transitive']} in transitive dependencies."]
            if trans:
                lines.append(f"{len(trans)} transitive findings are introduced by {len({p for f in trans for p in f['source_packages']})} direct dependencies - "
                             "fixing a handful of those usually removes most of them.")
            if st.pipe["findings"]:
                ph = sm["pipeline_critical_high"]
                lines.append(f"{len(st.pipe['findings'])} container/CI-CD hygiene finding(s)" + (f", {ph} of them critical or high" if ph else "") + " (Dockerfile, compose and workflow analysis).")
            if st.typo["findings"]:
                lines.append(f"{len(st.typo['findings'])} package name(s) resemble popular packages (signal only, not proof).")
            ls = [c for c in st.lres["findings"] if c["classification"] != "insufficient_baseline"]
            if ls:
                lines.append(f"{len(ls)} lockfile change(s) in Git history need review.")
            lim = st.result["limitations"]
            lines.append("Not assessed: reachability of vulnerable code. " + (f"{len(lim)} coverage limitation(s) are listed." if lim else ""))
            prios = []
            for g in res["source_package_view"][:5]:
                fix = g["top_fix"]
                prios.append(f"Update **{g['source_package']}** in {g['root']}: it brings in {g['vulnerable_packages']} vulnerable package(s) (worst: {g['worst_severity'] or 'n/a'})"
                             + (f"; e.g. upgrade {fix}" if fix else ""))
            res["analyst"] = {"headline": lines[0], "paragraphs": lines[1:], "priorities": prios}
            for p in prios[:3]:
                rt.decide("summary", p.replace("**", ""), reason="Highest-impact source package by worst risk and number of vulnerable packages.", agent="Analyst Agent")
            b["message"] = f"{len(prios)} prioritised actions"

    @staticmethod
    def _policy_gate(st: ScanState, rt: Runtime) -> None:
        """Evaluate the default policy so the report and UI always show a gate result (analyst waivers from memory apply)."""
        from policy.engine import PolicyError, evaluate, load_policy
        from storage.memory import Memory
        try:
            waivers = Memory(st.ctx.db).decisions(st.info.url)
            pr = evaluate(load_policy("default"), st.result, waivers)
            st.result["policy_result"] = pr
            rt.observe("export", f"Policy gate '{pr['policy']}': {'PASS' if pr['passed'] else 'FAIL'} - {pr['blocking']} blocking, {pr['warnings']} warning(s), {pr['waived']} waived")
        except (PolicyError, Exception) as e:  # noqa: BLE001 - a policy problem must not lose the scan
            rt.warn("export", f"Policy evaluation skipped: {type(e).__name__}: {str(e)[:120]}")

    def export(self, st: ScanState, rt: Runtime) -> None:
        s = st.ctx.s
        res = st.result
        with rt.step("export") as b:
            self._policy_gate(st, rt)
            res["llm_calls"] = list(llm_log())
            paths = json_exporter.write_all(res, s.artifacts_dir / "scans", st.prefix)
            from reporting.sarif import to_sarif
            from reporting.vex import to_vex
            (s.artifacts_dir / "reports").mkdir(parents=True, exist_ok=True)
            (s.artifacts_dir / "reports" / f"{st.prefix}.sarif").write_text(json_exporter.dumps(to_sarif(res)), encoding="utf-8")
            (s.artifacts_dir / "reports" / f"{st.prefix}.vex.json").write_text(json_exporter.dumps(to_vex(res)), encoding="utf-8")
            paths["sarif"] = str(s.artifacts_dir / "reports" / f"{st.prefix}.sarif")
            paths["vex"] = str(s.artifacts_dir / "reports" / f"{st.prefix}.vex.json")
            (s.artifacts_dir / "graphs" / f"{st.prefix}.json").write_text(json_exporter.dumps(json_exporter.graph_export(res)), encoding="utf-8")
            md = report_generator.generate_markdown(res)
            (s.artifacts_dir / "reports" / f"{st.prefix}-report.md").write_text(md, encoding="utf-8")
            (s.artifacts_dir / "reports" / f"{st.prefix}-report.html").write_text(report_generator.generate_html(res), encoding="utf-8")
            paths["report_md"] = str(s.artifacts_dir / "reports" / f"{st.prefix}-report.md")
            paths["report_html"] = str(s.artifacts_dir / "reports" / f"{st.prefix}-report.html")
            res["artifacts"] = paths
            b["message"] = f"{len(paths)} report/artifact files written (the scan is saved to SQLite when the run finishes)"


def source_package_view(vulns: list[dict], risks: dict[str, dict]) -> list[dict]:
    """Group findings by the direct ('source') dependency that introduces them, per root."""
    groups: dict[tuple, dict] = {}
    for f in vulns:
        for e in f["exposures"]:
            for p in e["paths"][:5]:
                if len(p) < 2:
                    continue
                key = (e["root"], p[1])
                g = groups.setdefault(key, {"root": e["root"], "source_package": p[1], "findings": set(), "packages": set(), "direct_self": False,
                                            "worst_severity": None, "worst_risk": "INFORMATIONAL", "fixes": []})
                g["findings"].add(f["finding_id"])
                g["packages"].add(f"{f['package_name']}@{f['installed_version']}")
                if len(p) == 2:
                    g["direct_self"] = True
                if SEV[f["severity"]] > SEV[g["worst_severity"]]:
                    g["worst_severity"] = f["severity"]
                lab = risks.get(f["finding_id"], {}).get("label", "INFORMATIONAL")
                order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"]
                if order.index(lab) < order.index(g["worst_risk"]):
                    g["worst_risk"] = lab
                if f["recommended_fix"]:
                    g["fixes"].append(f"{f['package_name']} to {f['recommended_fix']}")
    out = []
    for g in groups.values():
        out.append({"root": g["root"], "source_package": g["source_package"], "vulnerable_packages": len(g["packages"]), "findings": len(g["findings"]),
                    "finding_ids": sorted(g["findings"]), "is_itself_vulnerable": g["direct_self"], "worst_severity": g["worst_severity"],
                    "worst_risk": g["worst_risk"], "top_fix": g["fixes"][0] if g["fixes"] else None, "packages": sorted(g["packages"])[:12]})
    order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"]
    out.sort(key=lambda g: (order.index(g["worst_risk"]), -g["vulnerable_packages"]))
    return out


def _summary(st: ScanState, result: dict) -> dict:
    v = st.vulns
    by_sev: dict[str, int] = {}
    for f in v:
        by_sev[f["severity"] or "UNKNOWN"] = by_sev.get(f["severity"] or "UNKNOWN", 0) + 1
    by_risk: dict[str, int] = {}
    for a in st.risk["assessments"]:
        by_risk[a["label"]] = by_risk.get(a["label"], 0) + 1
    confirmed = [f for f in v if f["affected_status"] == "confirmed_affected"]
    return {
        "components": len([c for c in st.components if c.type not in ("file", "container") and c.purl_type not in ("docker", "github") and not c.is_self]), "by_ecosystem": st.quality.get("components_by_ecosystem", {}),
        "vulnerabilities_confirmed": len(confirmed), "vulnerabilities_unknown": len(v) - len(confirmed), "by_cvss_severity": by_sev,
        "vuln_direct": sum(f["dependency_type"].startswith("direct") for f in v), "vuln_transitive": sum(f["dependency_type"] == "transitive" for f in v),
        "kev": sum(f["kev"] for f in v), "with_fix": sum(bool(f["fixed_versions"]) for f in v),
        "typosquatting": len(st.typo["findings"]),
        "pipeline_findings": len(st.pipe["findings"]), "pipeline_critical_high": sum(1 for f in st.pipe["findings"] if f["severity"] in ("CRITICAL", "HIGH")),
        "lockfile_findings": len([c for c in st.lres["findings"] if c["classification"] != "insufficient_baseline"]),
        "by_risk": by_risk, "services": len(st.insp.services), "cross_verified": (result.get("verification") or {}).get("findings_cross_verified"),
    }
