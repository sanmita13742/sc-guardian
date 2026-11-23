"""Safe Git helpers: all calls use argument lists (never a shell) and a hardened environment."""
from __future__ import annotations

import os
import shutil
import stat
import subprocess
import uuid
from pathlib import Path
from typing import Optional

from config.settings import Settings, get_settings
from core.safe_env import scrubbed_env
from core.url_validator import GitHubRepo, validate_ref

SAFE_CONFIG = [
    "-c", "core.symlinks=false",
    "-c", "protocol.file.allow=never",
    "-c", "core.fsmonitor=false",
    "-c", "core.hooksPath=NUL" if os.name == "nt" else "core.hooksPath=/dev/null",
    "-c", "credential.helper=",
    "-c", "submodule.recurse=false",
]


class GitError(RuntimeError):
    pass


def _env() -> dict[str, str]:
    env = scrubbed_env()
    env["GIT_TERMINAL_PROMPT"] = "0"
    env["GIT_ASKPASS"] = "echo"
    env["GCM_INTERACTIVE"] = "never"
    env.pop("GIT_SSH_COMMAND", None)
    return env


def run_git(args: list[str], cwd: Path | None = None, timeout: int = 60, check: bool = True) -> subprocess.CompletedProcess:
    cmd = ["git", *SAFE_CONFIG, *args]
    try:
        proc = subprocess.run(
            cmd, cwd=str(cwd) if cwd else None, capture_output=True, text=True, encoding="utf-8", errors="replace",
            timeout=timeout, env=_env(), shell=False,
        )
    except subprocess.TimeoutExpired as e:
        raise GitError(f"git {args[0]} timed out after {timeout}s") from e
    except FileNotFoundError as e:
        raise GitError("git executable not found") from e
    if check and proc.returncode != 0:
        raise GitError(f"git {args[0]} failed: {proc.stderr.strip()[:500]}")
    return proc


def _rmtree_force(path: Path) -> None:
    def onerror(func, p, _exc):  # read-only files inside .git on Windows
        try:
            os.chmod(p, stat.S_IWRITE)
            func(p)
        except Exception:
            pass

    shutil.rmtree(path, onerror=onerror)


def dir_size(path: Path, limit: int | None = None) -> int:
    total = 0
    for root, dirs, files in os.walk(path, followlinks=False):
        for f in files:
            try:
                total += os.lstat(os.path.join(root, f)).st_size
            except OSError:
                continue
            if limit and total > limit:
                return total
    return total


def new_workspace(settings: Settings | None = None) -> tuple[str, Path]:
    s = settings or get_settings()
    scan_id = uuid.uuid4().hex[:12]
    ws = s.workspace_dir / scan_id
    ws.mkdir(parents=True, exist_ok=False)
    return scan_id, ws


def reap_stale_workspaces(settings: Settings | None = None) -> int:
    """Delete clone workspaces left behind by crashed/killed scans (older than ``workspace_max_age_s``)."""
    import time
    s = settings or get_settings()
    removed = 0
    try:
        for d in s.workspace_dir.iterdir():
            try:
                if d.is_dir() and time.time() - d.stat().st_mtime > s.workspace_max_age_s:
                    _rmtree_force(d)
                    removed += 1
            except OSError:
                continue
    except OSError:
        pass
    return removed


def remove_artifacts(settings: Settings, scan_id: str) -> None:
    """Delete every generated artifact of a pruned scan (files are named ``<scan_id>-*``)."""
    for sub in ("sbom", "scans", "reports", "graphs"):
        for f in (settings.artifacts_dir / sub).glob(f"{scan_id}-*"):
            try:
                f.unlink()
            except OSError:
                pass


def clone_repository(repo: GitHubRepo, workspace: Path, ref: str | None = None, settings: Settings | None = None) -> Path:
    """Shallow, hook-less, submodule-less clone into ``workspace/repo``. Never runs repository code."""
    s = settings or get_settings()
    ref = validate_ref(ref)
    dest = workspace / "repo"
    args = ["clone", "--depth", str(s.clone_depth), "--no-tags", "--single-branch", "--no-recurse-submodules"]
    if ref:
        args += ["--branch", ref]
    args += ["--", repo.clone_url, str(dest)]
    run_git(args, timeout=s.clone_timeout_s)
    size = dir_size(dest, s.max_repo_bytes)
    if size > s.max_repo_bytes:
        cleanup(workspace)
        raise GitError(f"Repository exceeds the {s.max_repo_bytes // (1024 * 1024)} MB size limit")
    return dest


def head_sha(repo_dir: Path) -> str:
    return run_git(["rev-parse", "HEAD"], cwd=repo_dir).stdout.strip()


def current_branch(repo_dir: Path) -> Optional[str]:
    out = run_git(["rev-parse", "--abbrev-ref", "HEAD"], cwd=repo_dir, check=False).stdout.strip()
    return None if out in ("", "HEAD") else out


def is_shallow(repo_dir: Path) -> bool:
    return run_git(["rev-parse", "--is-shallow-repository"], cwd=repo_dir, check=False).stdout.strip() == "true"


def parent_sha(repo_dir: Path, sha: str = "HEAD") -> Optional[str]:
    p = run_git(["rev-parse", "--verify", "--quiet", f"{sha}^"], cwd=repo_dir, check=False)
    return p.stdout.strip() or None if p.returncode == 0 else None


def commit_exists(repo_dir: Path, sha: str) -> bool:
    return run_git(["cat-file", "-e", f"{sha}^{{commit}}"], cwd=repo_dir, check=False).returncode == 0


def commit_info(repo_dir: Path, sha: str) -> dict[str, str]:
    out = run_git(["show", "-s", "--format=%H%x1f%an%x1f%aI%x1f%s", sha], cwd=repo_dir, check=False).stdout.strip()
    parts = out.split("\x1f")
    if len(parts) < 4:
        return {"sha": sha, "author": "", "date": "", "subject": ""}
    return {"sha": parts[0], "author": parts[1], "date": parts[2], "subject": parts[3]}


def recent_commits(repo_dir: Path, n: int, ref: str = "HEAD") -> list[str]:
    out = run_git(["rev-list", f"--max-count={int(n)}", ref], cwd=repo_dir, check=False).stdout.split()
    return out


def changed_files(repo_dir: Path, base: str, head: str) -> list[tuple[str, str]]:
    """Return [(status, path)] between two commits (renames reported as D+A for simplicity)."""
    out = run_git(["diff", "--name-status", "--no-renames", base, head], cwd=repo_dir, check=False).stdout
    res = []
    for line in out.splitlines():
        if "\t" in line:
            st, path = line.split("\t", 1)
            res.append((st[0], path.strip()))
    return res


def show_file(repo_dir: Path, sha: str, path: str, max_bytes: int = 20 * 1024 * 1024) -> Optional[str]:
    """Return file text at a commit, or None if absent/too large. Never touches the working tree."""
    p = subprocess.run(
        ["git", *SAFE_CONFIG, "show", f"{sha}:{path}"], cwd=str(repo_dir), capture_output=True, env=_env(),
        timeout=60, shell=False,
    )
    if p.returncode != 0 or len(p.stdout) > max_bytes:
        return None
    return p.stdout.decode("utf-8", errors="replace")


def diff_text(repo_dir: Path, base: str, head: str, path: str, max_chars: int = 200000, context: int = 1) -> str:
    out = run_git(["diff", f"-U{int(context)}", "--no-color", base, head, "--", path], cwd=repo_dir, check=False).stdout
    return out[:max_chars]


def cleanup(workspace: Path) -> None:
    try:
        if workspace.exists():
            _rmtree_force(workspace)
    except Exception:
        pass
