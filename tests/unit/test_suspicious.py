import json
import subprocess
from pathlib import Path

import pytest

from core.http import NotFound, SourceUnavailable
from core.models import Component
from suspicious_changes.lockfile_change_detector import detect_lockfile_changes
from suspicious_changes.typosquatting_detector import candidate_matches, detect_typosquatting, fetch_registry_signals


# ------------------------------------------------------------------ typosquatting
def comp(name, eco="PyPI", ver="1.0.0", ref=None):
    return Component(bom_ref=ref or f"{eco}:{name}", name=name, version=ver, ecosystem=eco)


def test_candidate_techniques():
    m = candidate_matches("PyPI", "requestss", ["requests", "flask"])[0]
    assert m["ref"] == "requests" and m["distance"] == 1 and "repeated character" in m["techniques"]
    m = candidate_matches("PyPI", "reqeusts", ["requests"])[0]
    assert "character transposition" in m["techniques"] and m["similarity"] == 87.5
    m = candidate_matches("npm", "lodahs", ["lodash"])[0]
    assert m["ref"] == "lodash"
    assert candidate_matches("npm", "l0dash", ["lodash"])[0]["techniques"]  # look-alike character
    assert candidate_matches("npm", "react-js", ["react"])[0]["techniques"][0].startswith("common affix")


def test_no_candidates_for_unrelated_exact_or_cross_ecosystem():
    assert candidate_matches("npm", "lodash", ["lodash"]) == []  # exact name is the reference itself
    assert candidate_matches("npm", "totally-different", ["lodash", "express"]) == []
    assert candidate_matches("PyPI", "Flask_Cors", ["flask-cors"]) == []  # PEP 503 normalization -> identical
    assert candidate_matches("npm", "ms", ["qs"]) == []  # short names are not compared at distance 1


def test_detector_offline_findings_and_context():
    comps = [comp("requestss"), comp("requests"), comp("flask"), comp("lodahs", "npm"), comp("left-pad", "npm"),
             Component(bom_ref="d", name="curl", version="7", purl="pkg:deb/debian/curl@7")]
    out = detect_typosquatting(comps, http=None, dependency_info={"PyPI:requestss": {"type": "transitive", "roots": ["svc"]}})
    names = {f.package_name: f for f in out["findings"]}
    assert set(names) == {"requestss", "lodahs"}
    f = names["requestss"]
    assert f.classification == "suspicious_name_similarity" and f.similar_to == "requests"
    assert f.dependency_type == "transitive" and any("transitive" in c for c in f.caveats)
    assert any("does not prove malicious" in c for c in f.caveats)
    assert any("offline" in e for e in f.evidence)
    assert "malicious" not in f.classification


class FakeRegistry:
    def __init__(self, data):
        self.data = data

    def get_json(self, url, **kw):
        for k, v in self.data.items():
            if url.startswith(k):
                if isinstance(v, Exception):
                    raise v
                return v
        raise NotFound(url)


def test_registry_signals_raise_and_suppress():
    import datetime
    young = (datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=10)).isoformat()
    old = (datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=2000)).isoformat()
    http = FakeRegistry({
        "https://registry.npmjs.org/lodahs": {"time": {"created": young}, "versions": {"1.0.0": {}}},
        "https://api.npmjs.org/downloads/point/last-month/lodahs": {"downloads": 12},
        "https://registry.npmjs.org/debugs": {"time": {"created": old}, "versions": {f"{i}.0.0": {} for i in range(40)}},
        "https://api.npmjs.org/downloads/point/last-month/debugs": {"downloads": 900000},
    })
    comps = [comp("lodahs", "npm"), comp("debugs", "npm"), comp("expresss", "npm")]
    out = detect_typosquatting(comps, http=http)  # type: ignore[arg-type]
    by = {f.package_name: f for f in out["findings"]}
    assert by["lodahs"].evidence_strength == "high" and by["lodahs"].registry["exists"] is True
    assert any("12 downloads" in e for e in by["lodahs"].evidence)
    assert "debugs" not in by and out["suppressed"][0]["package"] == "debugs"  # established package suppressed with a reason
    assert "expresss" in by and by["expresss"].registry["exists"] is False  # not found -> weak, flagged with caveat evidence


def test_registry_outage_degrades_gracefully():
    out = detect_typosquatting([comp("lodahs", "npm")], http=FakeRegistry({"https://registry.npmjs.org/": SourceUnavailable("x")}))  # type: ignore[arg-type]
    assert out["findings"] and out["stats"]["registry_unavailable"] == 1
    assert any("unavailable" in e for e in out["findings"][0].evidence)


def test_fetch_registry_unsupported_ecosystem():
    sig = fetch_registry_signals(FakeRegistry({}), None, "Go", "x")  # type: ignore[arg-type]
    assert sig["checked"] is False


# ------------------------------------------------------------------ lockfile changes (real git repos)
def git(repo, *args):
    subprocess.run(["git", "-c", "user.name=t", "-c", "user.email=t@example.com", "-c", "commit.gpgsign=false", *args],
                   cwd=repo, check=True, capture_output=True)


def lock(pkgs):
    """pkgs: {name: (version, integrity, resolved, dev)} -> package-lock v3 text."""
    packages = {"": {"name": "app", "dependencies": {n: v[0] for n, v in pkgs.items() if v[3] != "transitive"}}}
    for n, (ver, integ, res, kind) in pkgs.items():
        e = {"version": ver, "resolved": res or f"https://registry.npmjs.org/{n}/-/{n}-{ver}.tgz"}
        if integ:
            e["integrity"] = integ
        packages[f"node_modules/{n}"] = e
    return json.dumps({"lockfileVersion": 3, "packages": packages}, indent=2)


def manifest(deps):
    return json.dumps({"name": "app", "dependencies": deps}, indent=2)


class GitRepo:
    """PathLike wrapper around a temp git repo with a commit() helper."""

    def __init__(self, path):
        self.path = path

    def __fspath__(self):
        return str(self.path)

    def commit(self, files, msg="c", delete=()):
        for p, c in files.items():
            (self.path / p).parent.mkdir(parents=True, exist_ok=True)
            (self.path / p).write_text(c, encoding="utf-8")
        for p in delete:
            (self.path / p).unlink()
        git(self.path, "add", "-A")
        git(self.path, "commit", "-q", "--allow-empty", "-m", msg)


@pytest.fixture
def repo(tmp_path):
    r = tmp_path / "r"
    r.mkdir()
    git(r, "init", "-q")
    return GitRepo(r)


def classes(res):
    return {(c["package_name"], c["change_type"]): c["classification"] for c in res["changes"]}


def test_root_commit_is_insufficient_baseline(repo):
    repo.commit({"package.json": manifest({"a": "1"}), "package-lock.json": lock({"a": ("1.0.0", "sha512-x", None, "")})})
    res = detect_lockfile_changes(repo)
    assert res["changes"][0]["classification"] == "insufficient_baseline"
    assert res["limitations"] and res["summary"]["insufficient_baseline"] == 1 and res["findings"][0]["classification"] == "insufficient_baseline"


def test_normal_update_with_manifest_change_is_not_flagged(repo):
    repo.commit({"package.json": manifest({"lodash": "4.17.15"}), "package-lock.json": lock({"lodash": ("4.17.15", "sha512-a", None, "")})})
    repo.commit({"package.json": manifest({"lodash": "4.17.21"}), "package-lock.json": lock({"lodash": ("4.17.21", "sha512-b", None, "")})})
    res = detect_lockfile_changes(repo)
    assert classes(res) == {("lodash", "version_changed"): "normal_update"}
    assert res["findings"] == [] and res["changes"][0]["manifest_changed"] is True
    c = res["changes"][0]
    assert c["previous"]["version"] == "4.17.15" and c["new"]["version"] == "4.17.21" and c["commit_info"]["subject"] == "c"
    assert any("lodash" in l for l in c["diff_excerpt"])


def test_lockfile_only_direct_change_is_unexplained_not_malicious(repo):
    repo.commit({"package.json": manifest({"lodash": "^4"}), "package-lock.json": lock({"lodash": ("4.17.15", "sha512-a", None, "")})})
    repo.commit({"package-lock.json": lock({"lodash": ("4.17.21", "sha512-b", None, "")})})
    res = detect_lockfile_changes(repo)
    c = res["findings"][0]
    assert c["classification"] == "unexplained_change" and c["severity"] == "LOW"
    assert "direct_dependency_changed_without_manifest_change" in c["signals"]
    assert not any("malicious" in r.lower() for r in c["reasons"] if "not" not in r.lower())


def test_integrity_change_same_version_is_suspicious_high(repo):
    repo.commit({"package.json": manifest({"a": "1.0.0"}), "package-lock.json": lock({"a": ("1.0.0", "sha512-AAA", None, "")})})
    repo.commit({"package-lock.json": lock({"a": ("1.0.0", "sha512-BBB", None, "")})})
    res = detect_lockfile_changes(repo)
    c = res["findings"][0]
    assert c["classification"] == "potentially_suspicious" and c["change_type"] == "integrity_changed"
    assert c["evidence_strength"] == "high" and c["severity"] == "HIGH"
    assert "integrity_changed_same_version" in c["signals"] and c["previous"]["integrity"] == "sha512-AAA"


def test_new_git_source_dependency_flagged(repo):
    repo.commit({"package.json": manifest({"a": "1.0.0"}), "package-lock.json": lock({"a": ("1.0.0", "sha512-a", None, "")})})
    repo.commit({"package.json": manifest({"a": "1.0.0", "evil": "git+https://example.com/x.git"}),
                 "package-lock.json": lock({"a": ("1.0.0", "sha512-a", None, ""), "evil": ("1.0.0", None, "git+https://example.com/x.git#abc", "")})})
    res = detect_lockfile_changes(repo)
    c = next(x for x in res["findings"] if x["package_name"] == "evil")
    assert c["classification"] == "potentially_suspicious" and "non_registry_source_git" in c["signals"]
    assert c["manifest_changed"] is True  # manifest mention does not hide the non-registry source


def test_transitive_cascade_is_normal(repo):
    repo.commit({"package.json": manifest({"mkdirp": "0.5.0"}), "package-lock.json": lock({"mkdirp": ("0.5.0", "sha512-a", None, "")})})
    both = {"mkdirp": ("0.5.1", "sha512-b", None, ""), "minimist": ("0.0.8", "sha512-c", None, "transitive")}
    lk = json.loads(lock(both))
    lk["packages"]["node_modules/mkdirp"]["dependencies"] = {"minimist": "0.0.8"}
    repo.commit({"package.json": manifest({"mkdirp": "0.5.1"}), "package-lock.json": json.dumps(lk)})
    res = detect_lockfile_changes(repo)
    assert classes(res) == {("minimist", "added"): "normal_update", ("mkdirp", "version_changed"): "normal_update"}
    assert res["findings"] == []


def test_lockfile_deleted_and_explicit_baseline_and_missing_baseline(repo):
    repo.commit({"package.json": manifest({"a": "1"}), "package-lock.json": lock({"a": ("1.0.0", "sha512-a", None, "")})}, "v1")
    first = subprocess.run(["git", "rev-parse", "HEAD"], cwd=repo, capture_output=True, text=True).stdout.strip()
    repo.commit({"package.json": manifest({"a": "1"}), "package-lock.json": lock({"a": ("1.0.1", "sha512-b", None, "")})}, "v2")
    repo.commit({"x.txt": "unrelated"}, "noise", delete=())
    repo.commit({}, "del", delete=["package-lock.json"])
    res = detect_lockfile_changes(repo)
    assert res["changes"][0]["change_type"] == "lockfile_removed" and res["changes"][0]["classification"] == "unexplained_change"
    # explicit baseline: compare HEAD~0 vs the first commit (lockfile exists at baseline only)
    res2 = detect_lockfile_changes(repo, baseline=first)
    assert res2["comparisons"][0]["mode"] == "explicit" and res2["changes"][0]["baseline"] == first
    res3 = detect_lockfile_changes(repo, baseline="deadbeefdeadbeef")
    assert res3["changes"][0]["classification"] == "insufficient_baseline" and "not found" in res3["limitations"][0]


def test_multiple_commits_and_no_lockfile_changes(repo):
    repo.commit({"package.json": manifest({"a": "1"}), "package-lock.json": lock({"a": ("1.0.0", "sha512-a", None, "")})})
    repo.commit({"README.md": "x"})
    repo.commit({"README.md": "y"})
    res = detect_lockfile_changes(repo, commits=2)
    assert res["changes"] == [] and res["summary"]["commits_analysed"] == 2
    res = detect_lockfile_changes(repo, commits=3)
    assert res["summary"]["insufficient_baseline"] == 1  # oldest commit is a root


def test_unresolvable_revision(repo):
    repo.commit({"a.txt": "x"})
    res = detect_lockfile_changes(repo, head="nope")
    assert res["changes"] == [] and "could not be resolved" in res["limitations"][0]


def test_new_lockfile_only_reports_non_registry_entries(repo):
    repo.commit({"a.txt": "x"})
    repo.commit({"package-lock.json": lock({f"p{i}": ("1.0.0", "sha512-a", None, "transitive") for i in range(30)})})
    res = detect_lockfile_changes(repo)
    assert [c["change_type"] for c in res["changes"]] == ["lockfile_added"]
