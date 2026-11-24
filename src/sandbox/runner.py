"""Optional sandbox validation of an *approved* remediation: apply the patch to a throw-away re-clone and run the repository's own build/tests in Docker.

This is the only place where repository-controlled commands (``npm test``, ``pytest``, ``mvn test`` ...) can run, so it is:

* opt-in and explicit (UI checkbox + approved remediation); never part of a normal scan
* isolated: a fresh clone in a temp workspace, bind-mounted as the only host path; no host environment variables or secrets are passed;
  ``--cap-drop ALL``, ``no-new-privileges``, memory/CPU/PID limits and timeouts
* two phases: *install* (network allowed, to fetch dependencies) and *test* (``--network none`` for a single container,
  or a validated Compose stack on an internal-only runtime network)
* compared with a baseline run when the patched run fails, so pre-existing failures are not blamed on the patch

Docker must be installed and its daemon running; otherwise the result is ``skipped`` with the reason.
"""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import time
from pathlib import Path
from typing import Any, Callable, Optional

import yaml

from config.settings import Settings
from core import git_manager as gm
from core.safe_env import scrubbed_env
from core.url_validator import validate_github_url
from llm.client import redact

LIMITS = ["--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--pids-limit", "512", "--memory", "2g", "--cpus", "2", "--tmpfs", "/tmp:rw,exec,size=1g", "-e", "HOME=/tmp"]
INSTALL_TIMEOUT, TEST_TIMEOUT = 900, 900
COMPOSE_FILES = ("compose.yaml", "compose.yml", "docker-compose.yaml", "docker-compose.yml")

# Package-manager caches live in Docker named volumes mounted at /cache, so the install of the next validation re-uses downloads.
# The same volume also carries state from the install container to the test container (Go modules, Cargo registry, Maven repo).
CACHE_ENV = {
    "npm": {"npm_config_cache": "/cache/npm"},
    "PyPI": {"PIP_CACHE_DIR": "/cache/pip"},
    "Go": {"GOMODCACHE": "/cache/gomod", "GOCACHE": "/cache/gobuild", "GOFLAGS": "-mod=readonly"},
    "crates.io": {"CARGO_HOME": "/cache/cargo"},
    "Maven": {"MAVEN_OPTS": "-Dmaven.repo.local=/cache/m2"},
}
# Caches whose entries are verified against the lockfile's content hashes on every use (npm integrity, go.sum, Cargo.lock checksums)
# may be shared across repositories; pip and Maven caches are not content-verified the same way, so they are scoped per repository.
SHARED_SAFE = {"npm", "Go", "crates.io"}
VENV = "/work/.scg-venv"  # PyPI: dependencies installed in the bind-mounted tree survive into the (separate) test container


def cache_volume(ecosystem: str, repo_url: str, run_id: str = "") -> dict:
    """Volume and environment for the package cache. ``SCG_SANDBOX_CACHE``: auto (default) | repo | run (fresh per validation, removed after)."""
    scope = os.environ.get("SCG_SANDBOX_CACHE", "auto").lower()
    if scope not in ("auto", "repo", "run"):
        scope = "auto"
    if scope == "auto":
        scope = "shared" if ecosystem in SHARED_SAFE else "repo"
    slug = "".join(ch for ch in ecosystem.lower() if ch.isalnum())
    name = {"shared": f"scg-cache-{slug}", "repo": f"scg-cache-{slug}-{hashlib.sha256(repo_url.encode()).hexdigest()[:12]}",
            "run": f"scg-run-{slug}-{run_id or os.urandom(4).hex()}"}[scope]
    return {"volume": name, "scope": scope, "env": CACHE_ENV.get(ecosystem, {})}


def remove_volume(name: str) -> None:
    exe = shutil.which("docker")
    if exe and name.startswith("scg-run-"):
        subprocess.run([exe, "volume", "rm", "-f", name], capture_output=True, timeout=60, shell=False, env=scrubbed_env())


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
        compose = _detect_compose_recipe(repo_dir, d, "npm test --silent")
        if compose:
            return compose
        return {"image": "node:22-bookworm-slim", "workdir": wd, "install": "npm ci || npm install", "test": "npm test --silent"}
    if ecosystem == "PyPI":
        has_tests = any((d / x).exists() for x in ("tests", "test", "pytest.ini", "tox.ini")) or (d / "pyproject.toml").exists()
        if not has_tests:
            return None
        inst = "pip install -r requirements.txt" if (d / "requirements.txt").exists() else "pip install ."
        return {"image": "python:3.12-slim", "workdir": wd, "install": f"python -m venv {VENV} && . {VENV}/bin/activate && {inst} && pip install pytest",
                "test": f". {VENV}/bin/activate && python -m pytest -q -x"}
    if ecosystem == "Maven" and (d / "pom.xml").exists():
        return {"image": "maven:3.9-eclipse-temurin-21", "workdir": wd, "install": "mvn -B -q dependency:go-offline", "test": "mvn -B -q -o test"}
    if ecosystem == "Go" and (d / "go.mod").exists():
        return {"image": "golang:1.23", "workdir": wd, "install": "go mod download", "test": "go test ./..."}
    if ecosystem == "crates.io" and (d / "Cargo.toml").exists():
        return {"image": "rust:1", "workdir": wd, "install": "cargo fetch", "test": "cargo test --offline"}
    return None


def _inside(root: Path, value: str) -> bool:
    """Whether a Compose-controlled path resolves inside the disposable clone."""
    try:
        Path(root, value).resolve().relative_to(root.resolve())
        return True
    except (OSError, ValueError):
        return False


def _compose_safety_error(root: Path, spec: dict) -> Optional[str]:
    """Reject Compose capabilities that could reach the host or existing Docker resources.

    Compose is repository-controlled input. The validator permits local build contexts,
    named/anonymous volumes and an isolated default network, but never host namespaces,
    devices, elevated privileges, host bind mounts, external resources or build secrets.
    """
    if not isinstance(spec.get("services"), dict) or not spec["services"]:
        return "Compose file has no services"
    for kind in ("volumes", "networks", "secrets", "configs"):
        entries = spec.get(kind) or {}
        if not isinstance(entries, dict):
            return f"Compose {kind} must be a mapping"
        if any(isinstance(v, dict) and v.get("external") for v in entries.values()):
            return f"external Compose {kind} are not allowed"
    if spec.get("secrets") or spec.get("configs"):
        return "Compose secrets/configs are not allowed in validation"
    named_volumes = set((spec.get("volumes") or {}).keys())
    forbidden = ("privileged", "devices", "cap_add", "cgroup", "cgroup_parent")
    for name, svc in spec["services"].items():
        if not isinstance(svc, dict):
            return f"Compose service '{name}' is invalid"
        if any(svc.get(k) for k in forbidden):
            return f"Compose service '{name}' requests a forbidden privilege/device setting"
        if svc.get("network_mode") == "host" or svc.get("pid") == "host" or svc.get("ipc") == "host" or svc.get("userns_mode") == "host":
            return f"Compose service '{name}' requests a host namespace"
        if any("unconfined" in str(x).lower() for x in (svc.get("security_opt") or [])):
            return f"Compose service '{name}' disables a security profile"
        for volume in svc.get("volumes") or []:
            if isinstance(volume, dict):
                if volume.get("type") == "bind":
                    return f"Compose service '{name}' uses a host bind mount"
                source = volume.get("source")
                if source and source not in named_volumes:
                    return f"Compose service '{name}' uses an undeclared volume"
            elif isinstance(volume, str) and ":" in volume:
                source = volume.split(":", 1)[0]
                if source and source not in named_volumes:
                    return f"Compose service '{name}' uses a host bind mount"
        build = svc.get("build")
        if build:
            b = {"context": build} if isinstance(build, str) else build
            if not isinstance(b, dict) or not _inside(root, str(b.get("context") or ".")):
                return f"Compose service '{name}' has a build context outside the clone"
            if b.get("ssh") or b.get("secrets") or b.get("privileged") or b.get("network") == "host" or b.get("additional_contexts"):
                return f"Compose service '{name}' requests unsafe build access"
            dockerfile = str(b.get("dockerfile") or "Dockerfile")
            if Path(dockerfile).is_absolute() or not _inside(root / str(b.get("context") or "."), dockerfile):
                return f"Compose service '{name}' has a Dockerfile outside its build context"
        for port in svc.get("ports") or []:
            # Published fixed ports can expose an intentionally vulnerable app on all
            # interfaces. A variable port is forced to 127.0.0.1:0 at runtime.
            if isinstance(port, str) and "${APP_PORT" in port:
                continue
            if isinstance(port, dict) and str(port.get("host_ip") or "") in ("127.0.0.1", "::1") and str(port.get("published") or "") in ("", "0"):
                continue
            return f"Compose service '{name}' publishes a fixed or non-loopback host port"
    return None


def _detect_compose_recipe(repo_dir: Path, service_dir: Path, test_command: str) -> Optional[dict]:
    compose_file = next((repo_dir / n for n in COMPOSE_FILES if (repo_dir / n).is_file()), None)
    if not compose_file:
        return None
    try:
        spec = yaml.safe_load(compose_file.read_text(encoding="utf-8")) or {}
    except (OSError, yaml.YAMLError) as e:
        return {"kind": "compose", "blocked_reason": f"Compose file could not be parsed: {type(e).__name__}"}
    blocked = _compose_safety_error(repo_dir, spec)
    if blocked:
        return {"kind": "compose", "blocked_reason": blocked, "compose_file": compose_file.name}
    candidates: list[tuple[str, dict]] = []
    for name, svc in spec["services"].items():
        build = svc.get("build")
        if not build:
            continue
        context = build if isinstance(build, str) else build.get("context", ".")
        try:
            if (repo_dir / str(context)).resolve() == service_dir.resolve():
                candidates.append((name, svc))
        except OSError:
            continue
    if len(candidates) != 1:
        return {"kind": "compose", "blocked_reason": "Compose test service could not be identified unambiguously", "compose_file": compose_file.name}
    service, svc = candidates[0]
    container_port = 3000
    for port in svc.get("ports") or []:
        if isinstance(port, str):
            raw = port.rsplit(":", 1)[-1].split("/", 1)[0]
            if raw.isdigit():
                container_port = int(raw)
                break
        elif isinstance(port, dict) and str(port.get("target") or "").isdigit():
            container_port = int(port["target"])
            break
    return {"kind": "compose", "image": "node:22-bookworm-slim", "workdir": str(service_dir.relative_to(repo_dir)) or ".",
            "install": "npm ci || npm install", "test": test_command, "compose_file": compose_file.name,
            "compose_service": service, "app_url": f"http://localhost:{container_port}"}


def _run(exe: str, repo_dir: Path, recipe: dict, phase: str, timeout: int) -> dict:
    if recipe.get("kind") == "compose" and phase == "test":
        return _run_compose_test(exe, repo_dir, recipe, timeout)
    cmd = [exe, "run", "--rm", *LIMITS]
    if phase == "test":
        cmd += ["--network", "none"]
    cache = recipe.get("cache")
    if cache:
        cmd += ["-v", f"{cache['volume']}:/cache"]
        for k, v in cache.get("env", {}).items():
            cmd += ["-e", f"{k}={v}"]
    cmd += ["-v", f"{repo_dir.resolve()}:/work", "-w", "/work/" + recipe["workdir"].strip("./"), recipe["image"], "sh", "-c", recipe[phase]]
    t0 = time.time()
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=timeout, shell=False, env=scrubbed_env())
        tail = redact("\n".join((p.stdout + "\n" + p.stderr).strip().splitlines()[-60:]))
        return {"phase": phase, "exit_code": p.returncode, "seconds": round(time.time() - t0, 1), "log_tail": tail}
    except subprocess.TimeoutExpired:
        return {"phase": phase, "exit_code": None, "seconds": round(time.time() - t0, 1), "log_tail": f"timed out after {timeout}s"}


def _tail(*chunks: str, lines: int = 80) -> str:
    return redact("\n".join("\n".join(chunks).strip().splitlines()[-lines:]))


def _run_compose_test(exe: str, repo_dir: Path, recipe: dict, timeout: int) -> dict:
    """Start a validated Compose stack, test inside its app service, then always remove it."""
    project = "scg-" + hashlib.sha256(str(repo_dir.resolve()).encode()).hexdigest()[:12]
    compose_file = str((repo_dir / recipe["compose_file"]).resolve())
    override = repo_dir / ".scg-compose.override.yaml"
    services = (yaml.safe_load(Path(compose_file).read_text(encoding="utf-8")) or {}).get("services") or {}
    hardening = {}
    for name, service in services.items():
        limits = {"pids_limit": 512, "mem_limit": "2g", "cpus": 2}
        if not any(str(x).startswith("no-new-privileges") for x in (service.get("security_opt") or [])):
            limits["security_opt"] = ["no-new-privileges:true"]
        hardening[name] = limits
    override.write_text(yaml.safe_dump({"services": hardening, "networks": {"default": {"internal": True}}}, sort_keys=True), encoding="utf-8")
    base = [exe, "compose", "-f", compose_file, "-f", str(override.resolve()), "-p", project]
    env = scrubbed_env({"APP_PORT": "127.0.0.1:0"})

    # Ensure host node_modules, .git, and .scg-venv are excluded from BuildKit context transfer
    dockerignore = repo_dir / ".dockerignore"
    had_dockerignore = dockerignore.exists()
    orig_dockerignore = dockerignore.read_text(encoding="utf-8") if had_dockerignore else None
    needed_ignores = ["node_modules", "**/node_modules", ".git", ".scg-venv"]
    if not had_dockerignore:
        dockerignore.write_text("\n".join(needed_ignores) + "\n", encoding="utf-8")
    else:
        missing = [ig for ig in needed_ignores if ig not in orig_dockerignore]
        if missing:
            dockerignore.write_text(orig_dockerignore.rstrip() + "\n" + "\n".join(missing) + "\n", encoding="utf-8")

    t0, startup, test, logs = time.time(), None, None, None
    try:
        startup = subprocess.run([*base, "up", "--build", "-d", "--wait", "--wait-timeout", "180"], cwd=repo_dir, capture_output=True, text=True,
                                 encoding="utf-8", errors="replace", timeout=min(timeout, 600), shell=False, env=env)
        if startup.returncode == 0:
            test = subprocess.run([*base, "exec", "-T", "-e", f"APP_URL={recipe['app_url']}", recipe["compose_service"], "sh", "-c", recipe["test"]],
                                  cwd=repo_dir, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=timeout, shell=False, env=env)
        logs = subprocess.run([*base, "logs", "--no-color", "--tail", "80"], cwd=repo_dir, capture_output=True, text=True, encoding="utf-8",
                              errors="replace", timeout=60, shell=False, env=env)
        chosen = test if test is not None else startup
        extra = "" if test is not None and test.returncode == 0 else "\nCompose service logs:\n" + ((logs.stdout or "") + (logs.stderr or ""))
        return {"phase": "test", "exit_code": chosen.returncode, "seconds": round(time.time() - t0, 1),
                "log_tail": _tail(chosen.stdout or "", chosen.stderr or "", extra), "compose_project": project}
    except subprocess.TimeoutExpired:
        return {"phase": "test", "exit_code": None, "seconds": round(time.time() - t0, 1), "log_tail": f"Compose validation timed out after {timeout}s",
                "compose_project": project}
    finally:
        try:
            subprocess.run([*base, "down", "-v", "--remove-orphans"], cwd=repo_dir, capture_output=True, text=True, timeout=120, shell=False, env=env)
        except (OSError, subprocess.TimeoutExpired):
            pass
        try:
            override.unlink(missing_ok=True)
        except OSError:
            pass
        try:
            if had_dockerignore and orig_dockerignore is not None:
                dockerignore.write_text(orig_dockerignore, encoding="utf-8")
            elif not had_dockerignore:
                dockerignore.unlink(missing_ok=True)
        except OSError:
            pass


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
        if recipe.get("blocked_reason"):
            return {"status": "skipped", "reason": f"Compose validation blocked: {recipe['blocked_reason']}", "recipe": recipe}
        recipe["cache"] = cache_volume(eco, repo["url"])
        say(f"Installing dependencies in {recipe['image']} (network allowed for this phase) ...")
        inst = _run(ds["exe"], clone, recipe, "install", INSTALL_TIMEOUT)
        if inst["exit_code"] != 0:
            return {"status": "error", "reason": "dependency installation failed in the sandbox", "recipe": recipe, "runs": [inst], "docker": ds["version"]}
        say("Starting the isolated Compose stack and running its integration tests ..." if recipe.get("kind") == "compose" else
            "Running the tests with the network disabled ...")
        test = _run(ds["exe"], clone, recipe, "test", TEST_TIMEOUT)
        isolation = ("validated Compose file, unique project, internal runtime network, loopback-only ephemeral published port, "
                     "no-new-privileges, 2 CPU / 2 GB / 512 pids per service, no host env or secrets" if recipe.get("kind") == "compose" else
                     "cap-drop ALL, no-new-privileges, 2 CPU / 2 GB / 512 pids, tests without network, no host env or secrets")
        out: dict[str, Any] = {"status": "passed" if test["exit_code"] == 0 else "failed", "recipe": recipe, "runs": [inst, test],
                               "docker": ds["version"], "isolation": isolation}
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
