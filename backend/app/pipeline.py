from __future__ import annotations

import json
import hashlib
import os
import re
import shutil
import subprocess
import threading
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable
from urllib.parse import urlparse

from .change_analysis import analyze_history, inspect_marked_source, inspect_supply_chain, manifest_lock_mismatches
from .graph_builder import build_graph
from .reporting import build_report
from .vulnerability import add_source_evidence, normalize_osv


STAGES = {
    "queued": ("Queued", 0),
    "clone": ("Validating URL and cloning pinned history", 8),
    "inventory": ("Generating lockfile-only CycloneDX inventory", 20),
    "validate": ("Validating CycloneDX SBOM", 30),
    "graph": ("Building and reconciling dependency graph", 42),
    "vulnerabilities": ("Scanning lockfile with OSV-Scanner", 56),
    "changes": ("Inspecting dependency history", 67),
    "supply_chain_context": ("Inspecting CI/CD and container definitions", 74),
    "correlate": ("Correlating advisories, graph paths, and source evidence", 84),
    "report": ("Generating evidence reports", 94),
    "ready": ("Ready", 100),
    "failed": ("Failed", 100),
    "cancelled": ("Cancelled", 100),
}
ARTIFACTS = {
    "sbom.json",
    "sbom-validation.json",
    "sbom-reconciliation.json",
    "graph.json",
    "graph-summary.json",
    "summary.json",
    "validation.json",
    "osv-raw.json",
    "vulnerabilities.json",
    "changes.json",
    "ci-inspection.json",
    "reachability-evidence.json",
    "report.json",
    "report.md",
    "report.html",
    "manifest.json",
    "pipeline.log",
}
OWNER_REPO_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9._-]{0,99})$")


class PipelineError(RuntimeError):
    def __init__(self, code: str, message: str, detail: str | None = None):
        super().__init__(message)
        self.code = code
        self.message = message
        self.detail = detail


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def validate_repository_url(value: str) -> str:
    try:
        parsed = urlparse(value.strip())
    except ValueError as exc:
        raise PipelineError("INVALID_REPOSITORY_URL", "Malformed repository URL") from exc
    if (
        parsed.scheme != "https"
        or parsed.hostname != "github.com"
        or parsed.username
        or parsed.password
        or parsed.port is not None
        or parsed.query
        or parsed.fragment
        or parsed.params
    ):
        raise PipelineError(
            "INVALID_REPOSITORY_URL",
            "Use an HTTPS github.com/OWNER/REPO repository URL without credentials, query, or fragment",
        )
    parts = [part for part in parsed.path.split("/") if part]
    if len(parts) != 2:
        raise PipelineError("INVALID_REPOSITORY_URL", "Repository URL must contain exactly OWNER/REPO")
    owner, repo = parts
    if repo.endswith(".git"):
        repo = repo[:-4]
    if not owner or not repo or not OWNER_REPO_RE.fullmatch(owner) or not OWNER_REPO_RE.fullmatch(repo):
        raise PipelineError("INVALID_REPOSITORY_URL", "Invalid GitHub owner or repository name")
    return f"https://github.com/{owner}/{repo}"


class AnalysisPipeline:
    def __init__(self, workspace: Path, command_runner: Callable[..., subprocess.CompletedProcess[str]] | None = None):
        self.workspace = workspace.resolve()
        self.runs_dir = (self.workspace / "analysis_runs").resolve()
        self.runs_dir.mkdir(parents=True, exist_ok=True)
        self.command_runner = command_runner or subprocess.run
        self.clone_timeout = int(os.getenv("GUARDIAN_CLONE_TIMEOUT", "180"))
        self.tool_timeout = int(os.getenv("GUARDIAN_TOOL_TIMEOUT", "300"))
        self.max_log_chars = int(os.getenv("GUARDIAN_MAX_LOG_CHARS", "200000"))
        self.history_depth = max(2, min(2000, int(os.getenv("GUARDIAN_HISTORY_DEPTH", "500"))))
        self.history_commits = max(1, min(500, int(os.getenv("GUARDIAN_HISTORY_COMMITS", "150"))))

    def _write_json(self, path: Path, value: Any) -> None:
        path.write_text(json.dumps(value, indent=2, ensure_ascii=False), encoding="utf-8")

    def _log(self, run_dir: Path, text: str) -> None:
        path = run_dir / "pipeline.log"
        current_size = path.stat().st_size if path.exists() else 0
        remaining = max(0, self.max_log_chars - current_size)
        if remaining:
            encoded = (text + "\n").encode("utf-8", errors="replace")[:remaining]
            encoded = encoded.decode("utf-8", errors="ignore").encode("utf-8")
            with path.open("ab") as handle:
                handle.write(encoded)

    def _run_command(self, args: list[str], cwd: Path, timeout: int, run_dir: Path) -> subprocess.CompletedProcess[str]:
        try:
            result = self.command_runner(
                args,
                cwd=str(cwd),
                shell=False,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=timeout,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise PipelineError("TOOL_EXECUTION_ERROR", f"Could not run {args[0]}", str(exc)) from exc
        self._log(run_dir, f"$ {' '.join(args)}\n{result.stdout}\n{result.stderr}")
        return result

    def _validator_path(self) -> Path | None:
        configured = os.getenv("CYCLONEDX_CLI_PATH")
        choices = [Path(configured)] if configured else []
        choices.append(self.workspace / "cyclonedx-win-x64.exe")
        return next((path.resolve() for path in choices if path and path.is_file()), None)

    def _osv_path(self) -> Path | None:
        configured = os.getenv("OSV_SCANNER_PATH")
        choices = [Path(configured)] if configured else []
        choices.append(self.workspace / "osv-scanner_windows_amd64.exe")
        executable = shutil.which("osv-scanner")
        if executable:
            choices.append(Path(executable))
        return next((path.resolve() for path in choices if path and path.is_file()), None)

    def _osv_query(self, package_name: str, version: str) -> set[str]:
        body = json.dumps({"package": {"name": package_name, "ecosystem": "npm"}, "version": version}).encode("utf-8")
        request = urllib.request.Request(
            "https://api.osv.dev/v1/query",
            data=body,
            headers={"Content-Type": "application/json", "User-Agent": "nodegoat-guardian/1.0"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=30) as response:
                payload = json.loads(response.read(5_000_000).decode("utf-8"))
        except (OSError, urllib.error.URLError, json.JSONDecodeError) as exc:
            raise RuntimeError(f"OSV API query failed: {exc}") from exc
        return {item["id"] for item in payload.get("vulns") or [] if isinstance(item.get("id"), str)}

    @staticmethod
    def _sha256(path: Path) -> str:
        digest = hashlib.sha256()
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
        return digest.hexdigest()

    def execute(
        self,
        manifest: dict[str, Any],
        update: Callable[[str, dict[str, Any]], None],
        cancelled: threading.Event,
    ) -> dict[str, Any]:
        job_id = manifest["job_id"]
        run_dir = (self.runs_dir / job_id).resolve()
        if run_dir.parent != self.runs_dir:
            raise PipelineError("INVALID_JOB_ID", "Invalid job directory")
        run_dir.mkdir(parents=False, exist_ok=False)
        (run_dir / "pipeline.log").write_text("", encoding="utf-8")

        def stage(stage_id: str, **extra: Any) -> None:
            if cancelled.is_set():
                raise PipelineError("CANCELLED", "Analysis was cancelled")
            label, progress = STAGES[stage_id]
            update(stage_id, {"stage_label": label, "progress": progress, **extra})

        stage("clone")
        repository_url = validate_repository_url(manifest["repository_url"])
        repo_dir = run_dir / "repo"

        clone = self._run_command(
            ["git", "clone", "--depth", str(self.history_depth), "--no-tags", "--", repository_url, str(repo_dir)],
            self.workspace,
            self.clone_timeout,
            run_dir,
        )
        if clone.returncode:
            raise PipelineError("CLONE_FAILED", "Git clone failed", clone.stderr[-4000:])
        revision = self._run_command(["git", "rev-parse", "HEAD"], repo_dir, 30, run_dir)
        if revision.returncode or not re.fullmatch(r"[0-9a-fA-F]{40}", revision.stdout.strip()):
            raise PipelineError("COMMIT_RESOLUTION_FAILED", "Could not resolve cloned commit", revision.stderr[-4000:])
        commit_sha = revision.stdout.strip().lower()
        update("clone", {"commit_sha": commit_sha})

        stage("inventory", commit_sha=commit_sha)
        package_json = repo_dir / "package.json"
        lockfile = repo_dir / "package-lock.json"
        if not package_json.is_file() or not lockfile.is_file():
            raise PipelineError(
                "UNSUPPORTED_OR_MISSING_LOCKFILE",
                "A root package.json and package-lock.json are required; no lockfile will be generated",
            )
        try:
            package_data = json.loads(package_json.read_text(encoding="utf-8"))
            lock_data = json.loads(lockfile.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise PipelineError("INVALID_NPM_PROJECT", "npm manifest or lockfile is not valid UTF-8 JSON", str(exc)) from exc

        sbom_path = run_dir / "sbom.json"
        generator = os.getenv("CYCLONEDX_NPM_COMMAND")
        if generator:
            generator_args = [generator]
        else:
            version = os.getenv("CYCLONEDX_NPM_VERSION", "1.19.3")
            npx_executable = shutil.which("npx.cmd" if os.name == "nt" else "npx")
            if not npx_executable:
                raise PipelineError(
                    "ANALYZER_NOT_FOUND",
                    "npx was not found. Install Node.js/npm or configure CYCLONEDX_NPM_COMMAND",
                )
            generator_args = [npx_executable, "--yes", f"@cyclonedx/cyclonedx-npm@{version}"]
        generator_args += [
            "--package-lock-only",
            "--output-format",
            "JSON",
            "--output-file",
            str(sbom_path),
        ]
        generated = self._run_command(generator_args, repo_dir, self.tool_timeout, run_dir)
        if generated.returncode:
            raise PipelineError("SBOM_GENERATION_FAILED", "CycloneDX npm SBOM generation failed", generated.stderr[-4000:])
        try:
            bom = json.loads(sbom_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise PipelineError("INVALID_SBOM_OUTPUT", "Generator did not produce valid JSON", str(exc)) from exc
        if bom.get("bomFormat") != "CycloneDX":
            raise PipelineError("INVALID_SBOM_OUTPUT", "Generated file is not a CycloneDX SBOM")

        stage("validate")
        validator = self._validator_path()
        validation_status = "unavailable"
        validator_diagnostics = "CycloneDX CLI was not found"
        if validator:
            spec_version = str(bom.get("specVersion") or "").replace(".", "_")
            validated = self._run_command(
                [str(validator), "validate", "--input-file", str(sbom_path), "--input-format", "json", "--input-version", f"v{spec_version}", "--fail-on-errors"],
                run_dir,
                self.tool_timeout,
                run_dir,
            )
            validator_diagnostics = (validated.stdout + "\n" + validated.stderr).strip()[-12000:]
            if validated.returncode:
                raise PipelineError("SBOM_VALIDATION_FAILED", "Official CycloneDX validation failed", validator_diagnostics)
            validation_status = "passed"

        stage("graph")
        graph, reconciliation = build_graph(bom)
        owner, name = repository_url.removeprefix("https://github.com/").split("/", 1)
        graph_timestamp = utc_now()
        graph["info"].update(
            {
                "repository": {"url": repository_url, "owner": owner, "name": name},
                "commit_sha": commit_sha,
                "generated_at": graph_timestamp,
                "generator": bom.get("metadata", {}).get("tools") or bom.get("metadata", {}).get("tools", {}),
                "validation_status": validation_status,
            }
        )
        summary = {
            **graph["stats"],
            "repository_url": repository_url,
            "repository_owner": owner,
            "repository_name": name,
            "commit_sha": commit_sha,
            "scan_timestamp": graph_timestamp,
            "bom_format": bom.get("bomFormat"),
            "spec_version": bom.get("specVersion"),
            "root_ref": graph["root"],
            "validation_status": validation_status,
            "warnings": graph["info"]["warnings"],
            "package_name": package_data.get("name"),
            "package_version": package_data.get("version"),
            "lockfile_version": lock_data.get("lockfileVersion"),
        }
        validation = {
            "official_validator": {"status": validation_status, "diagnostics": validator_diagnostics},
            "semantic_reconciliation": reconciliation,
        }
        self._write_json(run_dir / "graph.json", graph)
        self._write_json(run_dir / "summary.json", summary)
        self._write_json(run_dir / "graph-summary.json", summary)
        self._write_json(run_dir / "validation.json", validation)
        self._write_json(run_dir / "sbom-validation.json", validation["official_validator"])
        self._write_json(run_dir / "sbom-reconciliation.json", reconciliation)

        stage("vulnerabilities")
        osv_path = self._osv_path()
        if not osv_path:
            raise PipelineError("OSV_SCANNER_NOT_FOUND", "OSV-Scanner was not found; set OSV_SCANNER_PATH")
        osv_raw_path = run_dir / "osv-raw.json"
        osv_result = self._run_command(
            [str(osv_path), "scan", "source", "--lockfile", str(lockfile), "--format", "json", "--output-file", str(osv_raw_path), "--all-packages"],
            repo_dir,
            self.tool_timeout,
            run_dir,
        )
        if not osv_raw_path.is_file() or osv_raw_path.stat().st_size == 0:
            raise PipelineError("OSV_SCAN_FAILED", "OSV-Scanner did not produce JSON results", osv_result.stderr[-4000:])
        try:
            osv_raw = json.loads(osv_raw_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise PipelineError("OSV_SCAN_FAILED", "OSV-Scanner output is not valid JSON", str(exc)) from exc
        try:
            vulnerabilities = normalize_osv(osv_raw, graph, commit_sha)
        except ValueError as exc:
            raise PipelineError("OSV_RESULT_UNSUPPORTED", str(exc)) from exc
        # OSV-Scanner uses a findings-present exit code. Valid parseable JSON remains a successful scan.
        if osv_result.returncode not in {0, 1}:
            raise PipelineError("OSV_SCAN_FAILED", "OSV-Scanner execution failed", osv_result.stderr[-4000:])

        stage("changes")
        def run_git(args: list[str]) -> subprocess.CompletedProcess[str]:
            return self._run_command(args, repo_dir, min(self.tool_timeout, 120), run_dir)

        readme_text = ""
        readme = repo_dir / "README.md"
        if readme.is_file():
            readme_text = readme.read_text(encoding="utf-8", errors="replace").lower()
        package_description = str(package_data.get("description") or "").lower()
        educational_context = any(marker in readme_text or marker in package_description for marker in ("intentionally vulnerable", "vulnerable node.js app", "to learn owasp", "security education"))
        changes = analyze_history(run_git, self.history_commits, self._osv_query, educational_context)
        changes.update({"commit_sha": commit_sha, "history_depth": self.history_depth, "manifest_lock_mismatches": manifest_lock_mismatches(package_data, lock_data)})

        stage("supply_chain_context")
        ci_inspection = inspect_supply_chain(repo_dir)
        ci_inspection["commit_sha"] = commit_sha

        stage("correlate")
        source_evidence = inspect_marked_source(repo_dir, commit_sha)
        add_source_evidence(vulnerabilities, source_evidence, "marked")
        reachability = {
            "schema": "nodegoat-guardian-reachability-evidence-v1",
            "commit_sha": commit_sha,
            "classification": "candidate" if source_evidence else "unassessed",
            "package_name": "marked",
            "evidence": source_evidence,
            "limitations": ["Static source strings only", "No runtime execution or exploit confirmation", "Does not establish reachability for every advisory"],
        }
        self._write_json(run_dir / "vulnerabilities.json", vulnerabilities)
        self._write_json(run_dir / "changes.json", changes)
        self._write_json(run_dir / "ci-inspection.json", ci_inspection)
        self._write_json(run_dir / "reachability-evidence.json", reachability)

        stage("report")
        osv_version_result = self._run_command([str(osv_path), "--version"], run_dir, 30, run_dir)
        osv_version = next((line.strip() for line in osv_version_result.stdout.splitlines() if "osv-scanner version" in line.lower()), "unknown")
        completed_at = utc_now()
        tool_versions = {
            "cyclonedx_npm": os.getenv("CYCLONEDX_NPM_VERSION", "1.19.3"),
            "cyclonedx_spec": bom.get("specVersion"),
            "cyclonedx_validator": "available" if validator else "unavailable",
            "osv_scanner": osv_version,
            "git": "system git",
        }
        report_manifest = {**manifest, "repository_url": repository_url, "commit_sha": commit_sha, "completed_at": completed_at, "tool_versions": tool_versions}
        hash_names = ["sbom.json", "sbom-validation.json", "sbom-reconciliation.json", "graph.json", "graph-summary.json", "osv-raw.json", "vulnerabilities.json", "changes.json", "ci-inspection.json", "reachability-evidence.json"]
        artifact_hashes = {name: self._sha256(run_dir / name) for name in hash_names}
        report, report_md, report_html = build_report(report_manifest, graph, vulnerabilities, changes, ci_inspection, source_evidence, artifact_hashes)
        self._write_json(run_dir / "report.json", report)
        (run_dir / "report.md").write_text(report_md, encoding="utf-8")
        (run_dir / "report.html").write_text(report_html, encoding="utf-8")

        warnings = list(report["warnings"])
        final_status = "completed_with_warnings" if warnings else "completed"
        summary.update({
            "osv_scanned_package_entries": vulnerabilities["scanner_package_entry_count"],
            "unique_advisory_count": vulnerabilities["unique_advisory_count"],
            "unique_cve_count": vulnerabilities["unique_cve_count"],
            "affected_package_version_count": vulnerabilities["affected_package_version_count"],
            "vulnerability_finding_count": vulnerabilities["finding_count"],
            "suspicious_change_count": changes.get("suspicious_change_count", 0),
            "ci_risk_signal_count": ci_inspection.get("risk_signal_count", 0),
            "pipeline_warnings": warnings,
        })
        self._write_json(run_dir / "summary.json", summary)
        completed = {
            **manifest,
            "status": final_status,
            "stage": "ready",
            "stage_label": STAGES["ready"][0],
            "progress": 100,
            "started_at": manifest.get("started_at"),
            "completed_at": completed_at,
            "commit_sha": commit_sha,
            "summary": summary,
            "tool_versions": tool_versions,
            "artifact_hashes": {**artifact_hashes, "report.json": self._sha256(run_dir / "report.json"), "report.md": self._sha256(run_dir / "report.md"), "report.html": self._sha256(run_dir / "report.html")},
        }
        self._write_json(run_dir / "manifest.json", completed)
        stage("ready", commit_sha=commit_sha, summary=summary, completed_at=completed_at)
        return completed

