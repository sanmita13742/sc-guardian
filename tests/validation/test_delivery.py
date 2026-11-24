"""PR delivery must apply a scan-time patch to the scan-time commit, not a stale workspace branch."""
from pathlib import Path

from core.git_manager import run_git
from remediation.delivery import _origin_matches_target, commit_and_create_pr_branch, github_repo_slug


def _write_package(path: Path, version: str) -> None:
    path.write_text('{\n  "dependencies": {\n    "morgan": "^' + version + '"\n  }\n}\n', encoding="utf-8")


def test_delivery_checks_out_scanned_commit_and_uses_unique_retry_branch(tmp_path):
    repo_dir = tmp_path / "repo"
    repo_dir.mkdir()
    run_git(["init"], cwd=repo_dir)
    run_git(["config", "user.email", "guardian@example.invalid"], cwd=repo_dir)
    run_git(["config", "user.name", "SC Guardian Test"], cwd=repo_dir)
    package = repo_dir / "package.json"
    _write_package(package, "1.10.0")
    run_git(["add", "package.json"], cwd=repo_dir)
    run_git(["commit", "-m", "scanned base"], cwd=repo_dir)
    scanned = run_git(["rev-parse", "HEAD"], cwd=repo_dir).stdout.strip()

    # Simulate a reused delivery workspace currently checked out at a newer revision
    # whose package.json no longer matches the generated patch context.
    _write_package(package, "1.12.1")
    run_git(["add", "package.json"], cwd=repo_dir)
    run_git(["commit", "-m", "newer workspace head"], cwd=repo_dir)
    patch = """--- a/package.json
+++ b/package.json
@@ -1,5 +1,5 @@
 {
   \"dependencies\": {
-    \"morgan\": \"^1.10.0\"
+    \"morgan\": \"^1.12.1\"
   }
 }
"""
    item = {"id": "REM-001", "fingerprint": "fp", "action": "upgrade", "title": "Upgrade morgan", "source_package": "morgan",
            "finding_ids": ["F-1"], "target": {"from": "1.12.0", "to": "1.12.1"},
            "patch": {"path": "package.json", "diff": patch}}
    repo = {"url": "https://github.com/o/r", "name": "r", "commit_sha": scanned}

    first = commit_and_create_pr_branch(repo_dir, item, repo)
    assert first["status"] == "success"
    assert first["branch"] == "remediation/fix-morgan-1.12.1"
    assert '"morgan": "^1.12.1"' in package.read_text(encoding="utf-8")

    # A retry returns to the scanned commit and creates a suffixed branch instead
    # of checking out and re-patching the already delivered branch.
    second = commit_and_create_pr_branch(repo_dir, item, repo)
    assert second["status"] == "success"
    assert second["branch"] == "remediation/fix-morgan-1.12.1-2"
    assert second["target_repo"] == "o/r"
    assert second["gh_pr_args"][3:5] == ["--repo", "o/r"]


def test_github_target_is_derived_from_exact_scanned_url():
    assert github_repo_slug("https://github.com/saiyesh1th/vulnerable-node") == "saiyesh1th/vulnerable-node"
    assert github_repo_slug("git@github.com:saiyesh1th/vulnerable-node.git") == "saiyesh1th/vulnerable-node"
    assert github_repo_slug("https://example.com/saiyesh1th/vulnerable-node") is None


def test_same_named_repository_from_another_owner_is_rejected(tmp_path):
    repo_dir = tmp_path / "repo"
    repo_dir.mkdir()
    run_git(["init"], cwd=repo_dir)
    run_git(["remote", "add", "origin", "https://github.com/cr0hn/vulnerable-node.git"], cwd=repo_dir)
    assert not _origin_matches_target(repo_dir, "https://github.com/saiyesh1th/vulnerable-node")
    assert _origin_matches_target(repo_dir, "https://github.com/cr0hn/vulnerable-node")
