"""Optional sandbox validation of an *approved* remediation: apply the patch to a throw-away re-clone and run the repository's own build/tests in Docker.

This is the only place where repository-controlled commands (``npm test``, ``pytest``, ``mvn test`` ...) can run, so it is:

* opt-in and explicit (UI checkbox + approved remediation); never part of a normal scan
* isolated: a fresh clone in a temp workspace, bind-mounted as the only host path; no host environment variables or secrets are passed;
  ``--cap-drop ALL``, ``no-new-privileges``, memory/CPU/PID limits and timeouts
* two phases: *install* (network allowed, to fetch dependencies) and *test* (``--network none``)
* compared with a baseline run when the patched run fails, so pre-existing failures are not blamed on the patch

Docker must be installed and its daemon running; otherwise the result is ``skipped`` with the reason.
"""
from __future__ import annotations

import json
import shutil
import subprocess
import time
from pathlib import Path
from typing import Any, Callable, Optional

from config.settings import Settings
from core import git_manager as gm
from core.safe_env import scrubbed_env
from core.url_validator import validate_github_url
from llm.client import redact

LIMITS = ["--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--pids-limit", "512", "--memory", "2g", "--cpus", "2", "--tmpfs", "/tmp:rw,exec,size=1g", "-e", "HOME=/tmp"]
INSTALL_TIMEOUT, TEST_TIMEOUT = 900, 900


def docker_status() -> dict:
    exe = shutil.which("docker")
    if not exe:
        return {"available": False, "reason": "Docker is not installed (no `docker` executable on PATH)."}
    try:
        p = subprocess.run([exe, "version", "--format", "{{.Server.Version}}"], capture_output=True, text=True, timeout=15, shell=False, env=scrubbed_env())
    except (OSError, subprocess.TimeoutExpired):
        return {"available": False, "reason": "Docker did not respond."}
    if p.returncode != 0 or not p.stdout.strip():
        return {"available": False, "reason": "The Docker daemon is not running (start Docker Desktop and retry)."}
    return {"available": True, "version": p.stdout.strip(), "exe": exe}


def detect_recipe(repo_dir: Path, ecosystem: str, service_dir: str = ".") -> Optional[dict]:
    """Install/test commands for the service, or None when there is no recognised build/test recipe (never guessed)."""
    d = repo_dir / (service_dir if service_dir not in (".", "") else "")
    wd = (service_dir if service_dir not in (".", "") else ".")
    if ecosystem == "npm" and (d / "package.json").exists():
        try:
            scripts = (json.loads((d / "package.json").read_text(encoding="utf-8")).get("scripts") or {})
        except ValueError:
            return None
        t = scripts.get("test")
        if not t or "no test specified" in t:
            return None
        return {"image": "node:22-bookworm-slim", "workdir": wd, "install": "npm ci || npm install", "test": "npm test --silent"}
    if ecosystem == "PyPI":
        has_tests = any((d / x).exists() for x in ("tests", "test", "pytest.ini", "tox.ini")) or (d / "pyproject.toml").exists()
        if not has_tests:
            return None
        inst = "pip install -r requirements.txt" if (d / "requirements.txt").exists() else "pip install ."
        return {"image": "python:3.12-slim", "workdir": wd, "install": f"{inst} && pip install pytest", "test": "python -m pytest -q -x"}
    if ecosystem == "Maven" and (d / "pom.xml").exists():
        return {"image": "maven:3.9-eclipse-temurin-21", "workdir": wd, "install": "mvn -B -q dependency:go-offline", "test": "mvn -B -q -o test"}
    if ecosystem == "Go" and (d / "go.mod").exists():
        return {"image": "golang:1.23", "workdir": wd, "install": "go mod download", "test": "go test ./..."}
    if ecosystem == "crates.io" and (d / "Cargo.toml").exists():
        return {"image": "rust:1", "workdir": wd, "install": "cargo fetch", "test": "cargo test --offline"}
    return None


def _run(exe: str, repo_dir: Path, recipe: dict, phase: str, timeout: int) -> dict:
    cmd = [exe, "run", "--rm", *LIMITS]
    if phase == "test":
        cmd += ["--network", "none"]
    cmd += ["-v", f"{repo_dir.resolve()}:/work", "-w", "/work/" + recipe["workdir"].strip("./"), recipe["image"], "sh", "-c", recipe[phase]]
    t0 = time.time()
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=timeout, shell=False, env=scrubbed_env())
        tail = redact("\n".join((p.stdout + "\n" + p.stderr).strip().splitlines()[-60:]))
        return {"phase": phase, "exit_code": p.returncode, "seconds": round(time.time() - t0, 1), "log_tail": tail}
    except subprocess.TimeoutExpired:
        return {"phase": phase, "exit_code": None, "seconds": round(time.time() - t0, 1), "log_tail": f"timed out after {timeout}s"}


def _prepare(settings: Settings, repo: dict, patch_diff: Optional[str]) -> tuple[Path, Path]:
    rr = validate_github_url(repo["url"])
    scan_id, ws = gm.new_workspace(settings)
    clone = gm.clone_repository(rr, ws, repo.get("branch") or repo.get("ref"), settings)
    sha = repo.get("commit_sha")
    if sha:
        try:
            gm.run_git(["fetch", "--depth", "1", "origin", sha], cwd=clone, timeout=120)
            gm.run_git(["checkout", "--detach", "FETCH_HEAD"], cwd=clone, timeout=60)
        except gm.GitError:
            pass  # stay on the cloned head; reported by the caller through the commit comparison
    if patch_diff:
        (ws / "fix.patch").write_text(patch_diff, encoding="utf-8", newline="")
        gm.run_git(["apply", "--whitespace=nowarn", str(ws / "fix.patch")], cwd=clone, timeout=30)
    return ws, clone


def validate_in_sandbox(settings: Settings, repo: dict, rem: dict, progress: Optional[Callable[[str], None]] = None) -> dict[str, Any]:
    say = progress or (lambda m: None)
    ds = docker_status()
    if not ds["available"]:
        return {"status": "skipped", "reason": ds["reason"]}
    patch = (rem.get("patch") or {}).get("diff")
    if not patch:
        return {"status": "skipped", "reason": "This proposal has no patch to validate."}
    eco = rem.get("ecosystem") or (rem.get("target") or {}).get("ecosystem")
    ws_patched = ws_base = None
    try:
        say("Cloning the repository at the scanned commit and applying the patch ...")
        ws_patched, clone = _prepare(settings, repo, patch)
        recipe = detect_recipe(clone, eco, rem.get("service") or ".")
        if not recipe:
            return {"status": "skipped", "reason": f"No recognised build/test recipe for {eco} in this repository (the Guardian never guesses commands)."}
        say(f"Installing dependencies in {recipe['image']} (network allowed for this phase) ...")
        inst = _run(ds["exe"], clone, recipe, "install", INSTALL_TIMEOUT)
        if inst["exit_code"] != 0:
            return {"status": "error", "reason": "dependency installation failed in the sandbox", "recipe": recipe, "runs": [inst], "docker": ds["version"]}
        say("Running the tests with the network disabled ...")
        test = _run(ds["exe"], clone, recipe, "test", TEST_TIMEOUT)
        out: dict[str, Any] = {"status": "passed" if test["exit_code"] == 0 else "failed", "recipe": recipe, "runs": [inst, test], "docker": ds["version"], "isolation": "cap-drop ALL, no-new-privileges, 2 CPU / 2 GB / 512 pids, tests without network, no host env or secrets"}
        if test["exit_code"] != 0:
            say("Tests failed: running the unpatched baseline to see whether the failure pre-existed ...")
            ws_base, base_clone = _prepare(settings, repo, None)
            binst = _run(ds["exe"], base_clone, recipe, "install", INSTALL_TIMEOUT)
            btest = _run(ds["exe"], base_clone, recipe, "test", TEST_TIMEOUT) if binst["exit_code"] == 0 else None
            out["baseline"] = {"status": "passed" if btest and btest["exit_code"] == 0 else "failed", "runs": [binst] + ([btest] if btest else [])}
            out["attribution"] = "the same failure occurs without the patch (pre-existing)" if out["baseline"]["status"] == "failed" else "the baseline passes: the patch likely broke a test"
        return out
    except Exception as e:  # noqa: BLE001
        return {"status": "error", "reason": f"{type(e).__name__}: {str(e)[:200]}"}
    finally:
        for w in (ws_patched, ws_base):
            if w:
                gm.cleanup(w)


# ------------------------------------------------------------------ public building blocks (used by validation.fix_validator)


def prepare_workspace(settings: Settings, repo: dict, patch_diff: Optional[str]) -> tuple[Path, Path]:
    """Fresh clone at the scanned commit with the patch applied. Returns (workspace, clone); the caller must ``git_manager.cleanup(workspace)``."""
    return _prepare(settings, repo, patch_diff)


def run_phase(exe: str, repo_dir: Path, recipe: dict, phase: str, timeout: Optional[int] = None) -> dict:
    """Run one recipe phase (``install`` with network, ``test`` without) under the sandbox limits."""
    return _run(exe, repo_dir, recipe, phase, timeout or (INSTALL_TIMEOUT if phase == "install" else TEST_TIMEOUT))
