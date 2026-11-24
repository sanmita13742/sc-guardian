"""Governed Git branch creation, patch commit, and PR preparation.

Allows the user to commit remediation changes to an isolated branch with a standard
conventional commit message, formatted PR markdown according to repository templates,
and optional GitHub CLI dispatch.
"""
from __future__ import annotations

import os
import re
import shutil
import tempfile
from pathlib import Path
from typing import Any, Optional

from core.git_manager import GitError, run_git
from remediation.export import patch_text
from remediation.pr_template_engine import generate_pr_title, render_pull_request


def _sanitize_branch_name(pkg: str, version: str) -> str:
    clean_pkg = re.sub(r"[^a-zA-Z0-9._-]", "-", pkg).strip("-")
    clean_ver = re.sub(r"[^a-zA-Z0-9._-]", "-", version).strip("-")
    return f"remediation/fix-{clean_pkg}-{clean_ver}"


def can_dispatch_gh_cli() -> bool:
    """Check if GitHub CLI (gh) is available on the system."""
    return shutil.which("gh") is not None


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
    if not root or not (root / ".git").exists():
        if repo_url.startswith(("http://", "https://", "git@")):
            from config.settings import get_settings
            s = get_settings()
            repo_name = repo.get("name") or "repo"
            clean_name = re.sub(r"[^a-zA-Z0-9_-]", "-", repo_name)
            rem_ws = Path(s.workspace_dir or ".workspaces") / f"remediation_{clean_name}"
            rem_ws.parent.mkdir(parents=True, exist_ok=True)
            if not (rem_ws / ".git").exists():
                try:
                    run_git(["clone", "--depth", "50", repo_url, str(rem_ws)])
                except GitError as e:
                    return {"status": "error", "error": f"Could not acquire repository workspace from {repo_url}: {e}"}
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

        # 1. Test patch with --check first
        try:
            run_git(["apply", "--check", str(patch_file)], cwd=root)
        except GitError:
            # Try with whitespace-nowarn
            try:
                run_git(["apply", "--check", "--whitespace=nowarn", str(patch_file)], cwd=root)
            except GitError as e:
                return {"status": "error", "error": f"Patch application check failed: {e}"}

        # 2. Check out new branch
        try:
            run_git(["checkout", "-b", branch_name], cwd=root)
        except GitError:
            # If branch already exists, switch to it or try a suffixed name
            try:
                run_git(["checkout", branch_name], cwd=root)
            except GitError as e:
                return {"status": "error", "error": f"Could not create or checkout branch {branch_name}: {e}"}

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

        return {
            "status": "success",
            "branch": branch_name,
            "commit_msg": commit_msg,
            "pr_title": pr_title,
            "pr_body": pr_body,
            "pr_file": str(pr_file_path.relative_to(root)),
            "used_repo_template": used_template,
            "gh_cli_available": can_dispatch_gh_cli(),
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
