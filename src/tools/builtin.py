"""Built-in read-only tools used by the Investigator (deterministic planner and optional LLM planner alike).

Every tool records what it observed as Evidence and returns a compact result containing the evidence id, so conclusions can cite it.
Nothing here writes to the repository, runs repository code, or reaches the network (EPSS/OSV data was gathered by earlier agents).
"""
from __future__ import annotations

from pathlib import Path

from core.repository_inspector import safe_read_text
from llm.client import redact
from reachability.scanners import build_index, package_usage
from tools.registry import ToolContext, tool


def _finding(ctx: ToolContext, fid: str) -> dict:
    for f in ctx.state.vulns:
        if f["finding_id"] == fid:
            return f
    raise KeyError(f"unknown finding {fid}")


def _index(ctx: ToolContext):
    st = ctx.state
    if st.source_index is None:
        st.source_index = build_index(ctx.repo_dir)
    return st.source_index


@tool("advisory_facts", "Facts about the vulnerability finding: advisory ids, CVSS, KEV, affected-range validation, fixed versions, cross-verification.", {"finding_id": "finding id, e.g. VULN-007"})
def advisory_facts(ctx: ToolContext, finding_id: str) -> dict:
    f = _finding(ctx, finding_id)
    data = {"ids": f["vulnerability_ids"][:6], "cves": f["cve_ids"][:6], "severity": f["severity"], "cvss": f["cvss_score"], "affected_status": f["affected_status"], "ranges": f["affected_ranges"][:3],
            "fixed_versions": f["fixed_versions"][:4], "kev": f["kev"], "cross_verified": f["cross_verified"]}
    eid = ctx.evidence.add("osv", "osv-client", finding_id, f"{f['primary_id']}: {f['severity'] or 'severity n/a'}, affected={f['affected_status']}, cross_verified={f['cross_verified']}", data,
                           source=(f.get("advisory_urls") or [None])[0])
    return {"evidence_id": eid, **data}


@tool("dependency_path", "How the vulnerable package enters the application: direct/transitive, depth, the direct (source) dependency and the path from the service root.", {"finding_id": "finding id"})
def dependency_path(ctx: ToolContext, finding_id: str) -> dict:
    f = _finding(ctx, finding_id)
    e = (f["exposures"] or [{}])[0]
    path = (e.get("paths") or [[]])[0]
    data = {"relationship": f["dependency_type"], "depth": e.get("depth"), "source_packages": f["source_packages"][:4], "path": path[:10], "roots": f["roots"][:3], "dev_dependency": f["dev_dependency"]}
    eid = ctx.evidence.add("graph", "dependency-graph", finding_id, f"{f['dependency_type']} via {', '.join(f['source_packages'][:2]) or 'itself'}: {' -> '.join(path[:6])}", data)
    return {"evidence_id": eid, **data}


@tool("find_imports", "Static import evidence: is this package imported by the application's own source code (and where)?", {"package": "package name", "ecosystem": "OSV ecosystem, e.g. npm, PyPI, Maven, Go"})
def find_imports(ctx: ToolContext, package: str, ecosystem: str) -> dict:
    res = package_usage(_index(ctx), ecosystem, package)
    summary = (f"{package} imported by app code in {res['app_files']} file(s)" if res["status"] == "used_by_app" else f"{package} imported only in tests ({res['test_files']} file(s))" if res["status"] == "used_in_tests_only"
               else f"no import of {package} found in analysed {ecosystem} source" if res["status"] == "not_imported" else f"{package}: reachability unknown ({res.get('reason', '')})")
    eid = ctx.evidence.add("reachability", "import-scanner", f"{ecosystem}:{package}", summary, {k: res.get(k) for k in ("status", "app_files", "test_files", "locations", "files_analysed", "confidence", "import_density", "import_ratio", "influence_tier")},
                           source=(f"{res['locations'][0]['path']}:{res['locations'][0]['line']}" if res.get("locations") else None), verified=res["status"] != "unknown")
    return {"evidence_id": eid, **res}


@tool("package_meta", "Fused metadata of an installed package: licence, scope, publish date, install script, deprecation, digest verdict, attestations.", {"package": "package name", "version": "installed version"})
def package_meta(ctx: ToolContext, package: str, version: str) -> dict:
    for c in ctx.state.components:
        if c.name == package and c.version == version and not c.is_self:
            data = {"licenses": c.licenses[:3], "scope": c.scope, "published_at": c.published_at, "install_script": c.install_script, "deprecated": c.deprecated,
                    "integrity": c.integrity.get("status"), "attestations": c.integrity.get("attestations"), "resolution": c.resolution}
            eid = ctx.evidence.add("registry", "metadata-fusion", f"{package}@{version}", f"scope={c.scope}, published={c.published_at}, install_script={c.install_script}, integrity={c.integrity.get('status')}", data)
            return {"evidence_id": eid, **data}
    return {"error": f"{package}@{version} not in the inventory"}


@tool("epss", "EPSS exploitation probability (FIRST.org) for a CVE, if it was retrieved.", {"cve": "CVE id"})
def epss(ctx: ToolContext, cve: str) -> dict:
    r = ctx.state.epss.get(cve)
    if not r:
        return {"cve": cve, "available": False}
    eid = ctx.evidence.add("epss", "first.org-epss", cve, f"EPSS {r['epss']:.1%} (percentile {r['percentile']:.1%}) on {r.get('date')}", r, source="https://api.first.org/data/v1/epss")
    return {"evidence_id": eid, "available": True, **r}


@tool("read_snippet", "Read a few lines around an import found by find_imports (only files already cited as import evidence; secrets redacted).", {"path": "repo-relative path", "line": "line number", "radius": "lines of context, max 5"})
def read_snippet(ctx: ToolContext, path: str, line: int, radius: int = 3) -> dict:
    allowed = {loc["path"] for e in ctx.evidence._items.values() if e.kind == "reachability" for loc in (e.data.get("locations") or [])}
    if path not in allowed:
        return {"error": "path is not part of any import evidence; only files cited by find_imports can be read"}
    text = safe_read_text(Path(ctx.repo_dir), path, max_bytes=1_000_000)
    if text is None:
        return {"error": "file unreadable"}
    radius = max(0, min(int(radius), 5))
    lines = text.splitlines()
    a, b = max(0, int(line) - 1 - radius), min(len(lines), int(line) + radius)
    snippet = "\n".join(f"{n + 1}: {redact(lines[n])[:160]}" for n in range(a, b))
    eid = ctx.evidence.add("source", "snippet-reader", f"{path}:{line}", f"source lines {a + 1}-{b} of {path}", {"snippet": snippet})
    return {"evidence_id": eid, "snippet": snippet}
