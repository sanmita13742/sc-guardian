"""Governed Git branch creation, patch commit, and PR preparation.

Allows the user to commit remediation changes to an isolated branch with a standard
conventional commit message, formatted PR markdown according to repository templates,
and optional GitHub CLI dispatch.
"""
from __future__ import annotations

import os
import json
import re
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any, Optional
from urllib.parse import urlparse

from core.git_manager import GitError, run_git
from core.safe_env import scrubbed_env
from remediation.export import patch_text
from remediation.pr_template_engine import generate_pr_title, render_pull_request


def _sanitize_branch_name(pkg: str, version: str) -> str:
    clean_pkg = re.sub(r"[^a-zA-Z0-9._-]", "-", pkg).strip("-")
    clean_ver = re.sub(r"[^a-zA-Z0-9._-]", "-", version).strip("-")
    return f"remediation/fix-{clean_pkg}-{clean_ver}"


def can_dispatch_gh_cli() -> bool:
    """Check if GitHub CLI (gh) is available on the system."""
    return shutil.which("gh") is not None


def github_repo_slug(url: str) -> Optional[str]:
    """Return ``owner/repo`` for a GitHub URL, independent of HTTPS/SSH spelling."""
    value = str(url or "").strip()
    if value.startswith("git@github.com:"):
        path = value.split(":", 1)[1]
    else:
        parsed = urlparse(value)
        if parsed.hostname not in {"github.com", "www.github.com"}:
            return None
        path = parsed.path
    parts = [part for part in path.strip("/").removesuffix(".git").split("/") if part]
    return "/".join(parts[:2]) if len(parts) >= 2 else None


def _origin_matches_target(root: Path, repo_url: str) -> bool:
    """Do not let a reused same-name workspace redirect delivery to another owner."""
    target = github_repo_slug(repo_url)
    if not target:
        return True
    origin = run_git(["remote", "get-url", "origin"], cwd=root, check=False).stdout.strip()
    return not origin or github_repo_slug(origin) == target


def _run_external(args: list[str], *, cwd: Optional[Path] = None, timeout: int = 180, check: bool = True) -> subprocess.CompletedProcess:
    """Run a fixed GitHub/Git argument list without a shell or application secrets."""
    try:
        proc = subprocess.run(args, cwd=str(cwd) if cwd else None, capture_output=True, text=True, encoding="utf-8",
                              errors="replace", timeout=timeout, shell=False, env=scrubbed_env())
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise GitError(f"Could not run {Path(args[0]).name}: {exc}") from exc
    if check and proc.returncode != 0:
        raise GitError(f"{Path(args[0]).name} failed: {(proc.stderr or proc.stdout).strip()[:1200]}")
    return proc


def _gh_json(gh: str, args: list[str], *, cwd: Optional[Path] = None) -> Any:
    proc = _run_external([gh, *args], cwd=cwd)
    try:
        return json.loads(proc.stdout or "null")
    except ValueError as exc:
        raise GitError("GitHub CLI returned an invalid JSON response") from exc


def _fork_for_target(gh: str, target: str, login: str, target_meta: dict, *, cwd: Path) -> str:
    """Return a fork in the target's network, creating an owner-qualified one if names collide."""
    repo_name = target.split("/", 1)[1]
    target_root = ((target_meta.get("parent") or {}).get("full_name") if target_meta.get("fork") else target) or target
    forks = _gh_json(gh, ["api", f"repos/{target_root}/forks?per_page=100"], cwd=cwd) or []
    for fork in forks:
        if str((fork.get("owner") or {}).get("login") or "").lower() == login.lower():
            return fork["full_name"]
    candidates = [repo_name, re.sub(r"[^a-zA-Z0-9._-]", "-", f"{repo_name}-{target.split('/', 1)[0]}")]
    for index, name in enumerate(candidates):
        slug = f"{login}/{name}"
        proc = _run_external([gh, "api", f"repos/{slug}"], cwd=cwd, check=False)
        if proc.returncode == 0:
            meta = json.loads(proc.stdout)
            parent = (meta.get("parent") or {}).get("full_name")
            if meta.get("fork") and parent in {target, target_root}:
                return slug
            continue
        if index == 0 and name == repo_name:
            # Prefer GitHub's normal fork name when it is available.
            chosen = name
        else:
            chosen = name
        _run_external([gh, "repo", "fork", target, "--fork-name", chosen, "--clone=false"], cwd=cwd)
        return f"{login}/{chosen}"
    suffix = abs(hash(target)) % 100000
    chosen = f"{candidates[-1]}-{suffix}"
    _run_external([gh, "repo", "fork", target, "--fork-name", chosen, "--clone=false"], cwd=cwd)
    return f"{login}/{chosen}"


def _push_for_pr(root: Path, remote_repo: str, branch: str, gh: str) -> str:
    """Push without overwriting remote work; retry ref collisions with a unique name."""
    remote = "guardian-pr"
    url = f"https://github.com/{remote_repo}.git"
    exists = run_git(["remote", "get-url", remote], cwd=root, check=False).returncode == 0
    run_git(["remote", "set-url" if exists else "add", remote, url], cwd=root)
    git = shutil.which("git")
    if not git:
        raise GitError("git executable not found")
    gh_helper = gh.replace("\\", "/")
    args = [git, "-c", "core.hooksPath=NUL" if os.name == "nt" else "core.hooksPath=/dev/null",
            "-c", "credential.helper=", "-c", f'credential.https://github.com.helper=!"{gh_helper}" auth git-credential',
            "push", "--set-upstream", remote]
    refs = _run_external([git, "ls-remote", "--heads", url], cwd=root, check=False)
    existing = {line.split("refs/heads/", 1)[1] for line in refs.stdout.splitlines() if "refs/heads/" in line}
    last_error: Optional[GitError] = None
    suffix = 1
    for attempt in range(6):
        remote_branch = branch if attempt == 0 else f"{branch}-{suffix}"
        while remote_branch in existing:
            suffix += 1
            remote_branch = f"{branch}-{suffix}"
        try:
            _run_external([*args, f"{branch}:{remote_branch}"], cwd=root)
            return remote_branch
        except GitError as exc:
            last_error = exc
            detail = str(exc).lower()
            if not any(marker in detail for marker in ("rejected", "non-fast-forward", "cannot lock ref", "(failed)")):
                raise
            existing.add(remote_branch)
            suffix += 1
    raise GitError(f"Could not allocate a remote remediation branch after safe retries: {last_error}")


def dispatch_github_pull_request(delivery: dict[str, Any]) -> dict[str, Any]:
    """Push a prepared branch and open a PR only against its recorded scan repository."""
    target = delivery.get("target_repo")
    branch = delivery.get("branch")
    root = Path(delivery.get("repo_dir") or "")
    body_file = Path(delivery.get("pr_file_absolute") or "")
    gh = shutil.which("gh")
    if not target or not github_repo_slug(f"https://github.com/{target}"):
        return {"status": "error", "error": "The scanned repository is not a valid GitHub owner/repository target."}
    if not gh:
        return {"status": "error", "error": "GitHub CLI is not installed."}
    if not branch or not root.is_dir() or not (root / ".git").exists() or not body_file.is_file():
        return {"status": "error", "error": "The prepared branch or PR description is missing; prepare the PR branch again."}
    try:
        user = _gh_json(gh, ["api", "user"], cwd=root)
        target_meta = _gh_json(gh, ["api", f"repos/{target}"], cwd=root)
        login = user.get("login")
        if not login:
            raise GitError("GitHub CLI is not authenticated")
        api_head = f"{login}:{branch}"
        existing = _gh_json(gh, ["api", f"repos/{target}/pulls?state=open&head={api_head}"], cwd=root) or []
        if not existing:
            open_pulls = _gh_json(gh, ["api", f"repos/{target}/pulls?state=open&per_page=100"], cwd=root) or []
            title = delivery.get("pr_title") or "Security remediation"
            canonical_branch = re.sub(r"-\d+$", "", branch)
            existing = [pull for pull in open_pulls
                        if str((((pull.get("head") or {}).get("user") or {}).get("login")) or "").lower() == login.lower()
                        and (pull.get("title") == title
                             or re.sub(r"-\d+$", "", str((pull.get("head") or {}).get("ref") or "")) == canonical_branch)]
        if existing:
            found = existing[0]
            source_repo = ((((found.get("head") or {}).get("repo") or {}).get("full_name")) or "existing fork")
            return {"status": "success", "url": found.get("html_url") or found.get("url"), "number": found.get("number"),
                    "target_repo": target, "source_repo": source_repo, "branch": branch, "existing": True}
        can_push = bool((target_meta.get("permissions") or {}).get("push"))
        remote_repo = target if can_push else _fork_for_target(gh, target, login, target_meta, cwd=root)
        remote_branch = _push_for_pr(root, remote_repo, branch, gh)
        head = remote_branch if can_push else f"{login}:{remote_branch}"
        base = target_meta.get("default_branch") or "main"
        proc = _run_external([gh, "pr", "create", "--repo", target, "--base", base, "--head", head,
                              "--title", delivery.get("pr_title") or "Security remediation",
                              "--body-file", str(body_file)], cwd=root)
        url = next((line.strip() for line in reversed(proc.stdout.splitlines()) if line.strip().startswith("https://")), "")
        if not url:
            raise GitError("GitHub CLI did not return a pull request URL")
        return {"status": "success", "url": url, "target_repo": target, "source_repo": remote_repo,
                "branch": remote_branch, "local_branch": branch, "existing": False}
    except (GitError, ValueError) as exc:
        return {"status": "error", "error": str(exc), "target_repo": target, "branch": branch}


def _checkout_scanned_base(root: Path, repo: dict) -> Optional[str]:
    """Return the managed workspace to the exact revision that produced the proposal.

    PR workspaces are reused between UI clicks, so their current branch is not a safe
    patch base. Refuse tracked local edits, fetch the recorded commit when necessary,
    and detach at that immutable commit before checking/applying the patch.
    """
    dirty = run_git(["status", "--porcelain", "--untracked-files=no"], cwd=root, check=False).stdout.strip()
    if dirty:
        return "The remediation workspace has tracked local changes; refusing to overwrite them. Commit or remove those changes and retry."
    sha = str(repo.get("commit_sha") or "").strip()
    if not sha:
        return None
    exists = run_git(["cat-file", "-e", f"{sha}^{{commit}}"], cwd=root, check=False).returncode == 0
    if not exists:
        try:
            run_git(["fetch", "--depth", "1", "origin", sha], cwd=root, timeout=180)
        except GitError as e:
            return f"Could not fetch the scanned commit {sha[:12]}: {e}"
    try:
        run_git(["checkout", "--detach", sha], cwd=root)
    except GitError as e:
        return f"Could not check out the scanned commit {sha[:12]}: {e}"
    return None


def _available_branch(root: Path, desired: str) -> str:
    """Choose a new local branch without reusing a prior partially delivered branch."""
    for n in range(1, 1000):
        name = desired if n == 1 else f"{desired}-{n}"
        exists = run_git(["show-ref", "--verify", "--quiet", f"refs/heads/{name}"], cwd=root, check=False).returncode == 0
        if not exists:
            return name
    raise GitError(f"Could not allocate a unique branch derived from {desired}")


def commit_and_create_pr_branch(
    repo_dir: Path | str,
    rem: dict,
    repo: dict,
    approval: Optional[dict] = None,
) -> dict[str, Any]:
    """Create an isolated git branch, apply the remediation patch, and commit with a conventional message."""
    patch = patch_text(rem)
    if not patch:
        action = rem.get("action", "remediation")
        return {
            "status": "error",
            "error": f"Proposal '{rem.get('id')}' ({action}) does not have an automated code patch. See proposal rationale for manual mitigation.",
        }

    # Resolve target git working repository
    root = Path(repo_dir) if repo_dir and str(repo_dir) != "." else None
    if not root or not (root / ".git").exists():
        for cand in (repo.get("local_path"), repo.get("repo_dir"), repo.get("path")):
            if cand and Path(cand).exists() and (Path(cand) / ".git").exists():
                root = Path(cand)
                break

    repo_url = repo.get("url") or ""
    target_repo = github_repo_slug(repo_url)
    if root and (root / ".git").exists() and not _origin_matches_target(root, repo_url):
        root = None
    if not root or not (root / ".git").exists():
        if repo_url.startswith(("http://", "https://", "git@")):
            from config.settings import get_settings
            s = get_settings()
            repo_name = repo.get("name") or "repo"
            clean_name = re.sub(r"[^a-zA-Z0-9_-]", "-", (target_repo or repo_name).replace("/", "_"))
            rem_ws = Path(s.workspace_dir or ".workspaces") / f"remediation_{clean_name}"
            rem_ws.parent.mkdir(parents=True, exist_ok=True)
            if not (rem_ws / ".git").exists():
                try:
                    run_git(["clone", "--depth", "50", repo_url, str(rem_ws)])
                except GitError as e:
                    return {"status": "error", "error": f"Could not acquire repository workspace from {repo_url}: {e}"}
            elif not _origin_matches_target(rem_ws, repo_url):
                return {"status": "error", "error": f"Existing remediation workspace does not belong to target repository {target_repo}."}
            root = rem_ws
        else:
            return {"status": "error", "error": f"Working repository path not found (checked '{repo_dir}') and no remote Git URL available."}

    target = rem.get("target") or {}
    src_pkg = rem.get("source_package") or rem.get("package") or "dep"
    to_ver = target.get("to") or "fix"
    from_ver = target.get("from") or "cur"
    branch_name = _sanitize_branch_name(src_pkg, to_ver)

    # Render formatted PR body
    impact = rem.get("reachability_impact")
    pr_title, pr_body, used_template = render_pull_request(rem, repo, approval, repo_dir=root, impact=impact)

    # Build conventional commit message
    cves = ", ".join(rem.get("finding_ids", [])[:6]) or "security advisory"
    commit_msg = (
        f"{generate_pr_title(rem)}\n\n"
        f"Resolves security findings: {cves}\n"
        f"Target version: {from_ver} -> {to_ver}\n"
        f"Code reachability: {impact.get('impact_summary', 'Verified') if impact else 'Verified'}\n\n"
        f"Proposed by SC Guardian Remediation Agent."
    )

    # Apply patch and commit on an isolated branch
    td = Path(tempfile.mkdtemp())
    patch_file = td / "change.patch"
    try:
        patch_file.write_text(patch, encoding="utf-8")

        base_error = _checkout_scanned_base(root, repo)
        if base_error:
            return {"status": "error", "error": base_error}

        # 1. Test patch with --check first
        try:
            run_git(["apply", "--check", str(patch_file)], cwd=root)
        except GitError:
            # Try with whitespace-nowarn
            try:
                run_git(["apply", "--check", "--whitespace=nowarn", str(patch_file)], cwd=root)
            except GitError as e:
                return {"status": "error", "error": f"Patch application check failed: {e}"}

        # 2. Check out a new branch rooted at the immutable scanned commit.
        try:
            branch_name = _available_branch(root, branch_name)
            run_git(["checkout", "-b", branch_name], cwd=root)
        except GitError as e:
            return {"status": "error", "error": f"Could not create branch {branch_name}: {e}"}

        # 3. Apply the patch
        try:
            run_git(["apply", "--whitespace=nowarn", str(patch_file)], cwd=root)
        except GitError as e:
            return {"status": "error", "error": f"git apply failed: {e}"}

        # 4. Stage and commit
        manifest_path = (rem.get("patch") or {}).get("path")
        if manifest_path:
            run_git(["add", manifest_path], cwd=root)
        else:
            run_git(["add", "-u"], cwd=root)

        run_git(["commit", "-m", commit_msg], cwd=root)

        # 5. Save generated PR markdown file in .guardian/ for convenience
        guardian_dir = root / ".guardian"
        guardian_dir.mkdir(exist_ok=True)
        pr_file_path = guardian_dir / f"PR_{rem['id']}.md"
        pr_file_path.write_text(pr_body, encoding="utf-8")

        gh_pr_args = ["gh", "pr", "create"]
        if target_repo:
            gh_pr_args += ["--repo", target_repo]
        gh_pr_args += ["--head", branch_name, "--title", pr_title, "--body-file", str(pr_file_path.resolve())]

        return {
            "status": "success",
            "branch": branch_name,
            "commit_msg": commit_msg,
            "pr_title": pr_title,
            "pr_body": pr_body,
            "pr_file": str(pr_file_path.relative_to(root)),
            "pr_file_absolute": str(pr_file_path.resolve()),
            "used_repo_template": used_template,
            "gh_cli_available": can_dispatch_gh_cli(),
            "target_repo": target_repo,
            "target_repo_url": repo_url,
            "repo_dir": str(root.resolve()),
            "gh_pr_args": gh_pr_args,
        }
    except Exception as e:  # noqa: BLE001
        return {"status": "error", "error": f"Failed committing patch: {e}"}
    finally:
        shutil.rmtree(td, ignore_errors=True)


def get_remediation_severity_tier(rem: dict, vulns: Optional[list[dict]] = None) -> tuple[str, str]:
    """Determine whether a proposal is automated (Low/Medium) or requires human intervention (High/Critical).

    Returns (automation_tier, severity_label):
    - ('automated', 'Low/Medium'): pull request is automated and delivered without requiring human intervention
    - ('manual_review', 'High/Critical'): requires human intervention (accept or ignore) in Streamlit platform
    """
    prio = rem.get("priority", "P3")
    if prio in ("P0", "P1"):
        return "manual_review", "High/Critical"

    # Also check severities of individual findings fixed by this remediation
    if vulns:
        finding_ids = set(rem.get("finding_ids", []))
        for v in vulns:
            if v.get("finding_id") in finding_ids:
                sev = str(v.get("severity", "")).upper()
                if sev in ("CRITICAL", "HIGH"):
                    return "manual_review", "High/Critical"

    return "automated", "Low/Medium"


def auto_deliver_low_medium_remediations(
    repo_dir: Path | str,
    items: list[dict],
    repo: dict,
    memory: Optional[Any] = None,
) -> list[dict]:
    """Auto-approve and create PR branches for Low and Medium severity proposals without requiring human intervention."""
    import time
    delivered: list[dict] = []
    repo_path = Path(repo_dir)

    for rem in items:
        tier, label = get_remediation_severity_tier(rem)
        rem["automation_tier"] = tier
        rem["severity_tier"] = label

        if tier == "automated":
            # Auto-approve in persistent memory
            ap_record = {
                "state": "approved",
                "actor": "SC Guardian Policy Engine",
                "reason": f"Automated policy: {label} severity proposal auto-approved without human intervention",
                "decided_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            }
            if memory and rem.get("fingerprint"):
                try:
                    memory.set_approval(
                        repo_url=repo.get("url", ""),
                        fingerprint=rem["fingerprint"],
                        state="approved",
                        reason=ap_record["reason"],
                        title_=rem.get("title", ""),
                        actor="SC Guardian Policy Engine",
                    )
                except Exception:
                    pass

            # Commit to git branch if git repository exists
            if (repo_path / ".git").exists() and rem.get("patch"):
                res = commit_and_create_pr_branch(repo_path, rem, repo, ap_record)
                rem["delivery_result"] = res
                if res.get("status") == "success":
                    delivered.append(rem)
                    if memory:
                        try:
                            memory.audit(
                                repo.get("url", ""),
                                "SC Guardian Policy Engine",
                                "remediation_auto_delivered",
                                rem.get("title", ""),
                                f"Auto-delivered to branch {res.get('branch')} ({label} severity)",
                            )
                        except Exception:
                            pass
        else:
            # High and Critical proposals strictly require human intervention
            rem["requires_human_intervention"] = True

    return delivered
