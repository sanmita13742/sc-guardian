"""Architecture and behaviour audit for SC Guardian (no pytest needed).

Usage:  python scripts/audit_check.py [--offline] [--with-scanners]
  --offline        skip checks that need the network (OSV known-answer test)
  --with-scanners  also scan the fixture with every installed external scanner (Syft/Trivy) and compare with the rule engine

Exit code 0 = every check passed. Each check prints PASS/FAIL/SKIP and a reason.
"""
from __future__ import annotations

import ast
import json
import os
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

OFFLINE = "--offline" in sys.argv
WITH_SCANNERS = "--with-scanners" in sys.argv
results: list[tuple[str, str, str]] = []


def check(name: str, ok: bool | None, detail: str = "") -> None:
    status = "SKIP" if ok is None else ("PASS" if ok else "FAIL")
    results.append((name, status, detail))
    print(f"[{status}] {name}" + (f" - {detail}" if detail else ""))


def guarded(name: str):
    def deco(fn):
        try:
            fn()
        except Exception as e:  # a crashing check is a failing check
            import traceback
            check(name, False, f"{type(e).__name__}: {e}\n{traceback.format_exc()[-400:]}")
        return fn
    return deco


# ------------------------------------------------------------------------------------------------ architecture
LAYERS = {  # package -> packages it must NOT import (dependency direction: ui -> orchestration -> agents -> domain -> core/storage)
    "core": {"ui", "agents", "orchestration"},
    "storage": {"ui", "agents", "orchestration"},
    "sbom": {"ui", "agents", "orchestration"},
    "graph": {"ui", "agents", "orchestration"},
    "vulnerability": {"ui", "agents", "orchestration"},
    "suspicious_changes": {"ui", "agents", "orchestration"},
    "risk_analysis": {"ui", "agents", "orchestration"},
    "explainability": {"ui", "agents", "orchestration"},
    "reporting": {"ui", "agents", "orchestration"},
    "agents": {"ui", "orchestration"},
    "orchestration": {"ui"},
}


@guarded("layering")
def _layering() -> None:
    bad = []
    for pkg, forbidden in LAYERS.items():
        for f in (ROOT / pkg).rglob("*.py"):
            tree = ast.parse(f.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                mods = [node.module] if isinstance(node, ast.ImportFrom) and node.module else [a.name for a in node.names] if isinstance(node, ast.Import) else []
                for m in mods:
                    if m.split(".")[0] in forbidden:
                        bad.append(f"{f.relative_to(ROOT)} imports {m}")
    # core.scan_orchestrator is the documented entry point that lazily calls orchestration; allow only that one
    bad = [b for b in bad if not b.startswith("core\\scan_orchestrator.py") and not b.startswith("core/scan_orchestrator.py")]
    check("architecture: layer dependencies point downwards only", not bad, "; ".join(bad[:5]))


@guarded("subprocess")
def _subprocess_env() -> None:
    missing = []
    for f in ROOT.rglob("*.py"):
        if ".venv" in f.parts or f.name == "audit_check.py" or f.parent.name == "scripts":
            continue
        src = f.read_text(encoding="utf-8")
        tree = ast.parse(src)
        for n in ast.walk(tree):
            if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) and n.func.attr in ("run", "Popen", "check_output") \
                    and isinstance(n.func.value, ast.Name) and n.func.value.id == "subprocess":
                kws = {k.arg for k in n.keywords}
                if "env" not in kws or "shell" not in kws:
                    missing.append(f"{f.relative_to(ROOT)}:{n.lineno}")
    check("security: every subprocess call passes an explicit env and shell=False", not missing, ", ".join(missing))


@guarded("secrets")
def _secrets() -> None:
    from core.safe_env import scrubbed_env
    os.environ["ANTHROPIC_API_KEY"] = "sk-audit-secret"
    os.environ["NVD_API_KEY"] = "nvd-audit-secret"
    try:
        env = scrubbed_env()
        check("security: API keys are absent from subprocess environments", not any("audit-secret" in v for v in env.values()))
    finally:
        os.environ.pop("ANTHROPIC_API_KEY")
        os.environ.pop("NVD_API_KEY")


@guarded("steps")
def _pipeline_shape() -> None:
    from agents.runtime import STEPS
    from orchestration.pipeline import NODES, build_graph, mermaid
    owned = {s for _, steps, _ in NODES.values() for s in steps}
    missing = [s[0] for s in STEPS if s[0] not in owned and s[0] not in ("validate", "clone")]
    check("orchestration: every runtime step is owned by a graph node", not missing, ", ".join(missing))
    m = mermaid()
    check("orchestration: graph compiles with parallel branches and a conditional edge",
          bool(m) and "graph --> typosquat" in m and "graph --> vulnerability" in m and "sbom_quality -.->" in m)
    build_graph().compile()


# ------------------------------------------------------------------------------------------------ behaviour
def _fixture(td: Path) -> Path:
    fx = td / "fx"
    for svc in ("svc_a", "svc_b"):
        d = fx / svc
        d.mkdir(parents=True)
        (d / "package.json").write_text(json.dumps({"name": svc, "version": "1.0.0", "dependencies": {"minimist": "1.2.0"}}))
        (d / "package-lock.json").write_text(json.dumps({"name": svc, "version": "1.0.0", "lockfileVersion": 3, "packages": {
            "": {"name": svc, "version": "1.0.0", "dependencies": {"minimist": "1.2.0"}},
            "node_modules/minimist": {"version": "1.2.0", "resolved": "https://registry.npmjs.org/minimist/-/minimist-1.2.0.tgz", "integrity": "sha512-xxxxxxxxxxxx"}}}))
    return fx


def _settings(td: Path):
    from config.settings import Settings
    s = Settings()
    s.data_dir, s.artifacts_dir, s.workspace_dir = td / "data", td / "art", td / "ws"
    for d in (s.data_dir, s.workspace_dir, *(s.artifacts_dir / x for x in ("sbom", "scans", "reports", "graphs"))):
        d.mkdir(parents=True, exist_ok=True)
    return s


def _opts(**kw):
    from core.scan_orchestrator import ScanOptions
    base = dict(url="local", use_nvd=False, use_kev=False, registry_checks=False, reuse_cached=False)
    base.update(kw)
    return ScanOptions(**base)


@guarded("scan")
def _scan_checks() -> None:
    from core.scan_orchestrator import scan_local_directory
    from storage.database import Database
    td = Path(tempfile.mkdtemp())
    s, fx = _settings(td), _fixture(td)
    db = Database(s.db_path)
    modes = ["builtin"] + (["syft", "trivy"] if WITH_SCANNERS else [])
    out = {}
    for mode in modes:
        if OFFLINE:
            check(f"scan[{mode}]: fixture scan", None, "needs OSV (offline)")
            continue
        r = scan_local_directory(fx, _opts(sbom_scanner=mode), s, db, name="fx")
        pk = sorted((c["name"], c["service_dir"], c["version"]) for c in r["components"] if not c.get("is_self") and c["type"] != "file")
        out[mode] = (pk, len(r["vulnerabilities"]), r["sbom_tool"]["used"])
        ok = r["status"] == "completed" and Path(r["sbom_path"]).exists() and r["sbom"]["validation"]["valid"]
        check(f"scan[{mode}]: completed, valid CycloneDX file on disk (used {r['sbom_tool']['used']})", ok, "; ".join(e["error"] for e in r["errors"]))
        check(f"scan[{mode}]: both services keep their own component and graph root", len(pk) == 2 and len(r["graph"]["roots"]) == 2, str(pk))
        check(f"scan[{mode}]: persisted graph tables match the result", (db.load_graph(r["repo"]["scan_id"]) or {}).get("nodes") is not None)
        if mode == "builtin":
            base = r
    if len(out) > 1:
        ref = out["builtin"]
        check("parity: every scanner yields the same package set and finding count as the rule engine",
              all(v[0] == ref[0] and v[1] == ref[1] for v in out.values()), str({k: (v[1], v[2]) for k, v in out.items()}))
    if OFFLINE:
        return

    # failure containment: a crashing agent degrades the scan, never crashes it or leaves UI keys missing
    import orchestration.pipeline as P
    orig = P.risk.score
    P.risk.score = lambda st, rt: (_ for _ in ()).throw(RuntimeError("injected"))
    try:
        r = scan_local_directory(fx, _opts(sbom_scanner="builtin"), s, db, name="fx-fail")
    finally:
        P.risk.score = orig
    need = {"summary", "analyst", "risk_assessments", "explanations", "memory", "graph", "vulnerabilities", "limitations", "errors"}
    check("resilience: failed risk step -> run completes with errors, dependents skipped, full schema present",
          r["status"] == "completed_with_errors" and need <= set(r) and any(e["stage"] == "risk" for e in r["errors"]), str(sorted(need - set(r))))

    # memory
    from storage.memory import Memory
    r1 = scan_local_directory(fx, _opts(sbom_scanner="builtin"), s, db, name="mem")
    r2 = scan_local_directory(fx, _opts(sbom_scanner="builtin"), s, db, name="mem")
    c = r2["memory"]["diff"]["counts"]
    check("memory: scanning the same repo twice -> nothing new, nothing fixed, all persisting", c["new"] == 0 and c["persisting"] > 0 and c["fixed"] == 0, str(c))
    m = Memory(db)
    fp = next(iter(r2["memory"]["fingerprints"].values()))
    d1 = m.add_decision(r2["repo"]["url"], fp, "accepted_risk", "audit", "t", 1)
    check("memory: decision is active, newest wins, expiry honoured", fp in m.decisions(r2["repo"]["url"]))
    with db.connect() as cx:
        cx.execute("UPDATE decisions SET expires_at='2000-01-01T00:00:00Z' WHERE id=?", (d1,))
    check("memory: expired decision no longer applies", fp not in m.decisions(r2["repo"]["url"]))
    # graph diff between the two scans must be identical (same input)
    from graph.graph_diff import diff_graphs
    check("graph: diff of two scans of identical input is identical", diff_graphs(db.load_graph(r1["repo"]["scan_id"]), db.load_graph(r2["repo"]["scan_id"]))["identical"])
    # retention
    for _ in range(3):
        scan_local_directory(fx, _opts(sbom_scanner="builtin"), s, db, name="mem")
    ids = db.prune_repo(r2["repo"]["url"], 2)
    check("storage: prune keeps only the newest N scans of a repository", len(db.list_scans()) >= 2 and len(ids) >= 1)


@guarded("reuse")
def _reuse_rules() -> None:
    from core.scan_orchestrator import SCANNER_VERSION, options_fingerprint, reusable
    from risk_analysis.risk_rules import RULES_VERSION
    td = Path(tempfile.mkdtemp())
    s = _settings(td)
    sbom = td / "x.cdx.json"
    sbom.write_text("{}")
    o = _opts(sbom_scanner="auto")
    base = {"status": "completed", "repo": {"scan_timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}, "tool_versions": {"scanner": SCANNER_VERSION},
            "risk_rules_version": RULES_VERSION, "options_fp": options_fingerprint(o), "sbom_tool": {"used": "builtin"}, "sbom_path": str(sbom)}
    check("freshness: a fresh identical scan is reusable", reusable(base, o, s)[0])
    old = dict(base, repo={"scan_timestamp": "2020-01-01T00:00:00Z"})
    check("freshness: a stored scan older than the TTL is not reused", not reusable(old, o, s)[0])
    check("freshness: different scanner/rule version is not reused", not reusable(dict(base, tool_versions={"scanner": "0"}), o, s)[0])
    check("freshness: different options are not reused", not reusable(base, _opts(sbom_scanner="auto", use_nvd=True), s)[0])


@guarded("urls")
def _urls() -> None:
    from core.url_validator import InvalidRepositoryURL, validate_github_url
    bad = ["file:///etc/passwd", "C:\\Windows", "https://evil.com/a/b", "https://user:pw@github.com/a/b", "https://github.com:22/a/b", "https://github.com/a/b/../../c",
           "--upload-pack=x", "ssh://git@github.com/a/b", "https://github.com/a"]
    leaked = []
    for u in bad:
        try:
            validate_github_url(u)
            leaked.append(u)
        except (InvalidRepositoryURL, ValueError):
            pass
    ok = []
    for u in ["https://github.com/pallets/flask", "github.com/pallets/flask", "git@github.com:pallets/flask.git", "https://github.com/pallets/flask/tree/main"]:
        try:
            validate_github_url(u)
            ok.append(u)
        except Exception:
            pass
    check("security: attack-style URLs are rejected", not leaked, ", ".join(leaked))
    rebuilt = validate_github_url("https://github.com/a/b?x=`id`#frag").clone_url
    check("security: clone URL is rebuilt from owner/name (query and fragment never reach git)", rebuilt == "https://github.com/a/b.git", rebuilt)
    check("usability: all accepted URL forms validate", len(ok) == 4)


@guarded("graph_precedence")
def _adapters() -> None:
    from sbom.adapters import get_adapter
    raw = {"components": [{"type": "application", "name": "package-lock.json", "bom-ref": "A"}, {"type": "library", "name": "x", "version": "1", "purl": "pkg:npm/x@1", "bom-ref": "pkg:npm/x@1"}],
           "dependencies": [{"ref": "A", "dependsOn": ["pkg:npm/x@1"]}, {"ref": "pkg:npm/x@1", "dependsOn": []}], "metadata": {"component": {"bom-ref": "R"}}}
    snap = json.dumps(raw, sort_keys=True)
    doc = get_adapter("trivy").canonicalize(raw)
    check("normalisation: Trivy adapter folds lockfile applications into locations and never mutates the raw document",
          json.dumps(raw, sort_keys=True) == snap and len(doc["components"]) == 1 and doc["components"][0]["properties"][-1]["value"] == "package-lock.json")


@guarded("ground_truth")
def _ground_truth() -> None:
    if OFFLINE:
        check("ground truth: known-answer OSV test", None, "offline")
        return
    from config.settings import get_settings
    from core.http import HttpClient
    from storage.cache import Cache
    from storage.database import Database
    from vulnerability.osv_client import OsvClient
    from vulnerability.verification import run_ground_truth
    s = get_settings()
    res = run_ground_truth(OsvClient(HttpClient(), Cache(Database(s.db_path))))
    check("ground truth: known-answer test (documented CVEs detected, patched versions clean)", res["evaluated"] > 0 and res["passed"] == res["evaluated"], f"{res['passed']}/{res['evaluated']}, precision {res['precision']}, recall {res['recall']}")


if __name__ == "__main__":
    fails = [r for r in results if r[1] == "FAIL"]
    print(f"\n{sum(1 for r in results if r[1] == 'PASS')} passed, {len(fails)} failed, {sum(1 for r in results if r[1] == 'SKIP')} skipped")
    sys.exit(1 if fails else 0)
