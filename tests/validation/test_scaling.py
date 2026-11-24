"""Test evidence, cache volumes and baseline memoisation (no Docker: sandbox calls are stubbed)."""
import os
import tempfile
from types import SimpleNamespace

import pytest
from conftest import comp, make_after

from sandbox import runner as sbx
from storage.database import Database
from validation import agent as ag
from validation.comparison import compare
from validation.contracts import ApprovedRemediation, PhaseRun, SandboxOutcome
from validation.decider import Decider
from validation.test_evidence import summarize
from validation.verdict import decide

NODEGOAT_LOG = '>> Local Npm module "grunt-nodemon" not found. Is it installed?\n\nRunning "mochaTest:unit" (mochaTest) task\nNo files to check...OK\n\nDone.'


@pytest.mark.parametrize("log,executed", [
    (NODEGOAT_LOG, 0), ("  12 passing (40ms)\n  1 failing", 13), ("..F\n2 passed, 1 failed in 0.31s", 3),
    ("Tests:       1 failed, 9 passed, 10 total", 10), ("ok  \texample.com/a\t0.01s", 1), ("test result: ok. 7 passed; 0 failed; 0 ignored", 7),
    ("Tests run: 14, Failures: 1, Errors: 0, Skipped: 0", 14), ("collected 0 items", 0), ("all good", None)])
def test_summarize_counts_executed_tests(log, executed):
    assert summarize(log)["executed"] == executed


def test_exit_zero_without_executed_tests_is_not_verified(item, before):
    """The real NodeGoat case: `npm test` exits 0 but runs no test, so a fix can be at most fixed_untested."""
    vacuous = SandboxOutcome(status="passed", runs=[PhaseRun(phase="install", exit_code=0), PhaseRun(phase="test", exit_code=0)],
                             test_evidence=summarize(NODEGOAT_LOG), reason="tests exited 0 but no test was executed")
    cmp = compare(before, make_after([], [comp("express", "4.21.2"), comp("qs", "6.13.0")]), ApprovedRemediation.from_item(item))
    v, reasons, checks = decide(cmp, vacuous, True)
    assert v == "fixed_untested" and checks["tests_ok"] is None and "no test was executed" in reasons[-1]


def test_cache_scope_shared_only_for_content_verified_ecosystems(monkeypatch):
    monkeypatch.delenv("SCG_SANDBOX_CACHE", raising=False)
    npm, pip = sbx.cache_volume("npm", "https://github.com/a/b"), sbx.cache_volume("PyPI", "https://github.com/a/b")
    assert npm["scope"] == "shared" and npm["volume"] == "scg-cache-npm" and npm["env"]["npm_config_cache"] == "/cache/npm"
    assert pip["scope"] == "repo" and pip["volume"].startswith("scg-cache-pypi-") and pip["volume"] != sbx.cache_volume("PyPI", "https://github.com/a/c")["volume"]
    monkeypatch.setenv("SCG_SANDBOX_CACHE", "run")
    assert sbx.cache_volume("npm", "u", "rem-001")["volume"] == "scg-run-npm-rem-001"


def test_run_phase_mounts_cache_and_env(monkeypatch, tmp_path):
    seen = {}

    def fake_run(cmd, **kw):
        seen["cmd"] = cmd
        return SimpleNamespace(returncode=0, stdout="ok", stderr="")

    monkeypatch.setattr(sbx.subprocess, "run", fake_run)
    recipe = {"image": "node:22", "workdir": ".", "test": "npm test", "cache": {"volume": "scg-cache-npm", "env": {"npm_config_cache": "/cache/npm"}}}
    sbx.run_phase("docker", tmp_path, recipe, "test")
    c = seen["cmd"]
    assert "scg-cache-npm:/cache" in c and "npm_config_cache=/cache/npm" in c and c[c.index("--network") + 1] == "none"


def test_baseline_is_computed_once_per_commit(monkeypatch, tmp_path):
    runs = []

    def run_phase(exe, repo_dir, recipe, phase, timeout=None):
        runs.append(phase)
        return {"phase": phase, "exit_code": 1 if phase == "test" else 0, "seconds": 1, "log_tail": "1 failing"}

    monkeypatch.setattr(ag.sbx, "run_phase", run_phase)
    monkeypatch.setattr(ag.sbx, "prepare_workspace", lambda s, repo, patch: (tmp_path / "ws", tmp_path))
    monkeypatch.setattr(ag.gm, "cleanup", lambda ws: True)
    monkeypatch.setattr(ag.provenance, "docker_image_digest", lambda exe, image: "node@sha256:ab")
    db = Database(os.path.join(tempfile.mkdtemp(), "t.db"))
    a = ag.FixValidationAgent(settings=SimpleNamespace(artifacts_dir=tmp_path), db=db, decider=Decider(api_key=""))
    repo = {"url": "https://github.com/o/r", "commit_sha": "abc"}
    recipe = {"image": "node:22", "workdir": ".", "install": "npm ci", "test": "npm test"}
    first, second = a._baseline(repo, recipe, "docker", True), a._baseline(repo, recipe, "docker", True)
    assert runs == ["install", "test"] and not first["cached"] and second["cached"]
    a._baseline({**repo, "commit_sha": "def"}, recipe, "docker", True)  # another commit -> a new baseline
    assert runs == ["install", "test", "install", "test"]
