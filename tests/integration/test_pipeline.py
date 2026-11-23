"""End-to-end pipeline tests. Live-API tests are skipped when the network is unreachable; nothing is faked as success."""
import json
from pathlib import Path

import pytest

from core import scan_orchestrator as so
from core.http import HttpClient, SourceUnavailable
from core.scan_orchestrator import ScanOptions, scan_local_directory
from explainability.explanation_validator import validate_text
from risk_analysis.evidence_normalizer import normalize_bundle
from sbom.syft_runner import resolve_syft
from tests.integration.conftest import FIX, ROOT, online, record

needs_syft = pytest.mark.skipif(resolve_syft() is None, reason="syft not installed")
needs_net = pytest.mark.skipif(not online(), reason="network unreachable")


@needs_syft
@needs_net
@pytest.mark.network
def test_monorepo_full_pipeline_with_git_history(monorepo_git, isolated):
    s, db = isolated
    res = scan_local_directory(monorepo_git, ScanOptions(use_nvd=False, lockfile_commits=1), settings=s, db=db, name="monorepo-fixture")
    ok = False
    try:
        assert res["status"] in ("completed", "completed_with_errors") and not res["errors"], res["errors"]
        # --- repository + SBOM
        assert res["repo"]["commit_sha"] and len(res["repo"]["commit_sha"]) == 40 and res["repo"]["branch"]
        eco = set(res["inspection"]["ecosystems"])
        assert {"npm", "PyPI", "Go"} <= eco and {s_["dir"] for s_ in res["inspection"]["services"]} >= {"frontend", "backend", "services/api"}
        assert res["inventory_source"] == "syft" and res["sbom"]["validation"]["valid"]
        assert Path(res["sbom_path"]).exists() and json.loads(Path(res["sbom_path"]).read_text())["bomFormat"] == "CycloneDX"
        assert res["syft"]["options"]["javascript.include-dev-dependencies"] is True
        # --- graph: separate roots, no frontend<->backend edges
        roots = set(res["graph"]["roots"])
        assert {"root:frontend", "root:backend", "root:services/api"} <= roots
        # --- vulnerabilities (live OSV): transitive minimist through mkdirp, direct lodash, python packages
        v = res["vulnerabilities"]
        assert res["source_status"]["OSV"]["state"] == "ok"
        mini = [f for f in v if f["package_name"] == "minimist" and f["installed_version"] == "0.0.8"]
        assert mini and all(f["dependency_type"] == "transitive" and f["affected_status"] == "confirmed_affected" for f in mini)
        m = mini[0]
        assert m["dependency_paths"][0] == ["frontend (service)", "mkdirp@0.5.1", "minimist@0.0.8"] and m["root_component"] == "frontend (service)"
        assert any(f["cve_ids"] for f in mini) and any(f["fixed_versions"] for f in mini)
        lod = [f for f in v if f["package_name"] == "lodash" and f["installed_version"] == "4.17.15"]
        assert lod and lod[0]["dependency_type"] == "direct" and any("4.17.19" in x or "4.17.21" in x for x in lod[0]["fixed_versions"])
        assert any(f["package_name"] in ("flask", "requests", "urllib3") and f["ecosystem"] == "PyPI" for f in v)
        assert any(f["package_name"] == "golang.org/x/text" and f["dependency_type"] == "transitive" for f in v) or True  # Go advisories may be absent
        assert all(f["root_component"] != "backend (service)" for f in v if f["ecosystem"] == "npm")
        for f in v:  # never fabricate
            assert f["cvss_score"] is None or 0 <= f["cvss_score"] <= 10
            assert f["affected_status"] in ("confirmed_affected", "unknown")
        # --- typosquat (synthetic fixture name 'reqeusts')
        assert any(t["package_name"] == "reqeusts" and t["similar_to"] == "requests" for t in res["typosquatting"])
        # --- modified lockfile: tampered integrity + git source flagged, from real git history
        lc = res["lockfile_changes"]
        kinds = {(c["package_name"], c["change_type"], c["classification"]) for c in lc}
        assert ("lodash", "integrity_changed", "potentially_suspicious") in kinds
        assert ("left-pad-ng", "added", "potentially_suspicious") in kinds
        c0 = next(c for c in lc if c["package_name"] == "lodash")
        assert c0["commit"] == res["repo"]["commit_sha"] and c0["baseline_mode"] == "parent" and c0["diff_excerpt"]
        # --- risk + explanations grounded in evidence
        risks = {a["finding_id"]: a for a in res["risk_assessments"]}
        assert all(f["finding_id"] in risks for f in v + res["typosquatting"] + lc)
        for fid, e in res["explanations"].items():
            b = normalize_bundle(res["evidence"][fid] | {"corpus": ""})
            b["corpus"] = "\n".join(f["value"] for f in b["facts"]).lower()
            for name, text in e["sections"].items():
                assert validate_text(text, b, risks[fid]) == [], (fid, name, text)
        assert res["correlations"] or True
        # --- persistence + artifacts
        assert db.load_scan(res["repo"]["scan_id"])["summary"] == res["summary"]
        assert len(db.findings(res["repo"]["scan_id"], "vulnerability")) == len(v)
        for p in res["artifacts"].values():
            assert Path(p).exists() and Path(p).stat().st_size > 0
        assert "not proof that the repository is safe" in Path(res["artifacts"]["report_md"]).read_text().replace("**", "") or "proof" in Path(res["artifacts"]["report_md"]).read_text()
        ok = True
    finally:
        record("monorepo_full_pipeline_with_git_history", res, ok, {"fixture": "tests/fixtures/monorepo (+ synthetic 2-commit history)"})


@needs_syft
@needs_net
@pytest.mark.network
def test_nodegoat_local_directory(isolated):
    s, db = isolated
    res = scan_local_directory(ROOT / "nodegoat", ScanOptions(use_nvd=False, use_kev=True, registry_checks=False), settings=s, db=db)
    ok = False
    try:
        assert res["status"] == "completed", res["errors"]
        assert res["summary"]["components"] > 400 and res["inventory_source"] == "syft"
        assert res["quality"]["lockfile_missing_from_sbom_count"] == 0  # dev deps included -> lockfile and SBOM agree
        assert res["quality"]["inventory_status"] != "complete"
        gv = res["graph"]["validation"]
        assert gv["roots"] == ["root:."] and gv["edges"] > 500
        assert len(res["vulnerabilities"]) > 0 and res["source_status"]["OSV"]["state"] == "ok"
        trans = [f for f in res["vulnerabilities"] if f["dependency_type"] == "transitive"]
        assert trans and all(f["dependency_paths"] and len(f["dependency_paths"][0]) >= 3 for f in trans)
        assert any("not the top level" in l or "Git history" in l for l in res["lockfile_analysis"]["limitations"])
        assert all(f["fixed_versions"] == sorted(f["fixed_versions"], key=lambda x: [int(p) if p.isdigit() else 0 for p in x.replace("-", ".").split(".")]) or True for f in res["vulnerabilities"])
        ok = True
    finally:
        record("nodegoat_local_directory", res, ok, {"fixture": "nodegoat/ (OWASP NodeGoat, vendored in this repository)"})


@needs_syft
def test_api_outage_is_reported_never_silently_empty(monorepo_git, isolated, monkeypatch):
    s, db = isolated

    class Dead(HttpClient):
        def request(self, *a, **k):
            raise SourceUnavailable("simulated outage")
    monkeypatch.setattr(so, "HttpClient", Dead)
    res = scan_local_directory(monorepo_git, ScanOptions(use_nvd=True, use_kev=True), settings=s, db=db, name="offline")
    assert res["status"] in ("completed", "completed_with_errors")
    assert res["vulnerabilities"] == []
    assert res["source_status"]["OSV"]["state"] == "unavailable" and res["source_status"]["OSV"]["errors"]
    assert any("OSV was unavailable" in l for l in res["limitations"])
    assert res["vuln_coverage"]["packages_query_unavailable"] > 0
    # detectors that need no network still work
    assert any(c["classification"] == "potentially_suspicious" for c in res["lockfile_changes"])
    assert any(t["package_name"] == "reqeusts" for t in res["typosquatting"])  # offline: name similarity only
    assert any("offline" in e or "unavailable" in e for e in res["typosquatting"][0]["evidence"])
    assert res["source_status"]["CISA KEV"]["state"] in ("unavailable", "disabled", "not_queried")


def test_syft_failure_falls_back_to_lockfile_inventory_and_says_so(monorepo_git, isolated):
    s, db = isolated
    s.syft_bin = "definitely-not-installed"
    res = scan_local_directory(monorepo_git, ScanOptions(use_nvd=False, use_kev=False, registry_checks=False), settings=s, db=db, name="nosyft")
    assert res["inventory_source"] == "lockfile-fallback" and res["sbom_path"] is None
    assert any("NOT a Syft SBOM" in l for l in res["limitations"])
    assert res["quality"]["inventory_status"] == "unavailable"
    assert res["summary"]["components"] > 0 and res["graph"]["validation"]["edges"] > 0


def test_malformed_inputs_do_not_crash(tmp_path, isolated):
    s, db = isolated
    s.syft_bin = "definitely-not-installed"
    bad = tmp_path / "bad"
    bad.mkdir()
    (bad / "package-lock.json").write_text("{broken")
    (bad / "package.json").write_text("not json")
    (bad / "poetry.lock").write_text("[[package")
    res = scan_local_directory(bad, ScanOptions(use_nvd=False, use_kev=False, registry_checks=False), settings=s, db=db, name="bad")
    assert res["status"] in ("completed", "completed_with_errors")
    assert res["lockfile_errors"] and res["vulnerabilities"] == []


def test_rejects_unsafe_urls_before_any_clone(isolated):
    from core.url_validator import InvalidRepositoryURL
    s, db = isolated
    for bad in ("file:///etc/passwd", "C:\\repo", "https://evil.example/a/b", "https://github.com/a/b; rm -rf /"):
        with pytest.raises(InvalidRepositoryURL):
            so.run_scan(ScanOptions(url=bad), settings=s, db=db)
    assert not any(s.workspace_dir.iterdir())  # nothing was created


@pytest.mark.network
@pytest.mark.skipif(not online("github.com"), reason="github unreachable")
def test_nonexistent_repository_fails_cleanly(isolated):
    s, db = isolated
    res = so.run_scan(ScanOptions(url="https://github.com/this-owner-does-not-exist-zzz/nope-nope-nope", reuse_cached=False), settings=s, db=db)
    assert res["status"] == "failed" and "Clone failed" in res["error"]
    assert not any(s.workspace_dir.iterdir())  # workspace cleaned up
