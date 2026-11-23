import json
import subprocess
import threading
from pathlib import Path

import pytest

from app.pipeline import AnalysisPipeline, PipelineError, validate_repository_url


def result(code=0, stdout="", stderr=""):
    return subprocess.CompletedProcess([], code, stdout, stderr)


@pytest.mark.parametrize("url", [
    "https://github.com/OWASP/NodeGoat",
    "https://github.com/OWASP/NodeGoat.git",
    "https://github.com/OWASP/NodeGoat/",
])
def test_valid_nodegoat_urls(url):
    assert validate_repository_url(url) == "https://github.com/OWASP/NodeGoat"


@pytest.mark.parametrize("url", [
    "http://github.com/OWASP/NodeGoat", "https://gitlab.com/OWASP/NodeGoat",
    "git@github.com:OWASP/NodeGoat.git", "file:///tmp/repo", "https://user@github.com/a/b",
    "https://github.com/a/b/issues", "https://github.com/a/b?x=1", "https://github.com/a/../b",
])
def test_rejects_unsafe_urls(url):
    with pytest.raises(PipelineError) as error:
        validate_repository_url(url)
    assert error.value.code == "INVALID_REPOSITORY_URL"


class FakeRunner:
    def __init__(self, mode, fixture, osv_fixture):
        self.mode = mode
        self.fixture = fixture
        self.osv_fixture = osv_fixture

    def __call__(self, args, **kwargs):
        if args[:2] == ["git", "clone"]:
            if self.mode == "clone_error": return result(1, stderr="network refused")
            repo = Path(args[-1]); repo.mkdir(parents=True)
            (repo / "package.json").write_text('{"name":"fixture","version":"1"}', encoding="utf-8")
            if self.mode != "missing_lock": (repo / "package-lock.json").write_text('{"lockfileVersion":3}', encoding="utf-8")
            return result()
        if args[:3] == ["git", "rev-parse", "HEAD"]:
            return result(stdout="a" * 40 + "\n")
        if args[:2] == ["git", "log"]:
            return result(stdout="")
        if Path(args[0]).name.lower() in {"npx", "npx.cmd"}:
            if self.mode == "generator_error": return result(2, stderr="generator broke")
            output = Path(args[args.index("--output-file") + 1])
            output.write_text(self.fixture.read_text(encoding="utf-8"), encoding="utf-8")
            return result()
        if "validate" in args:
            return result(3, stderr="invalid schema") if self.mode == "validator_error" else result(stdout="valid")
        if Path(args[0]).name.lower().startswith("osv-scanner"):
            if "--version" in args:
                return result(stdout="osv-scanner version: fixture\n")
            output = Path(args[args.index("--output-file") + 1])
            output.write_text(self.osv_fixture.read_text(encoding="utf-8"), encoding="utf-8")
            return result(1, stderr="findings present")
        raise AssertionError(args)


def run_pipeline(tmp_path, mode):
    fixture = Path(__file__).parent / "fixtures" / "tiny-sbom.json"
    osv_fixture = Path(__file__).parent / "fixtures" / "tiny-osv.json"
    if mode in {"validator_error", "success"}:
        (tmp_path / "cyclonedx-win-x64.exe").write_bytes(b"fixture")
        (tmp_path / "osv-scanner_windows_amd64.exe").write_bytes(b"fixture")
    pipeline = AnalysisPipeline(tmp_path, FakeRunner(mode, fixture, osv_fixture))
    manifest = {"job_id": "b" * 32, "repository_url": "https://github.com/OWASP/NodeGoat", "created_at": "now", "started_at": "now"}
    updates = []
    pipeline.execute(manifest, lambda stage, values: updates.append((stage, values)), threading.Event())
    return tmp_path / "analysis_runs" / manifest["job_id"], updates


@pytest.mark.parametrize("mode,code", [
    ("clone_error", "CLONE_FAILED"), ("missing_lock", "UNSUPPORTED_OR_MISSING_LOCKFILE"),
    ("generator_error", "SBOM_GENERATION_FAILED"), ("validator_error", "SBOM_VALIDATION_FAILED"),
])
def test_clear_pipeline_failures(tmp_path, mode, code):
    with pytest.raises(PipelineError) as error:
        run_pipeline(tmp_path, mode)
    assert error.value.code == code


def test_fixture_pipeline_completes(tmp_path):
    run_dir, updates = run_pipeline(tmp_path, "success")
    graph = json.loads((run_dir / "graph.json").read_text(encoding="utf-8"))
    manifest = json.loads((run_dir / "manifest.json").read_text(encoding="utf-8"))
    assert graph["format"] == "nodegoat-guardian-graph-v1"
    assert manifest["status"] in {"completed", "completed_with_warnings"}
    assert updates[-1][0] == "ready"
    assert (run_dir / "vulnerabilities.json").is_file()
    assert (run_dir / "report.md").is_file()
    report_text = (run_dir / "report.md").read_text(encoding="utf-8")
    assert "## 10. Evidence table" in report_text
    assert "scanner advisory" in report_text

