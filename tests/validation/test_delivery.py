"""PR delivery must apply a scan-time patch to the scan-time commit, not a stale workspace branch."""
from pathlib import Path
import subprocess
from contextlib import nullcontext

from core.git_manager import run_git
import remediation.delivery as delivery_module
from remediation.delivery import _origin_matches_target, commit_and_create_pr_branch, dispatch_github_pull_request, github_repo_slug


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


def test_ui_dispatch_forks_pushes_and_creates_pr_in_scanned_repo(tmp_path, monkeypatch):
    root = tmp_path / "repo"
    (root / ".git").mkdir(parents=True)
    body = root / "PR.md"
    body.write_text("evidence", encoding="utf-8")
    calls = {}

    monkeypatch.setattr(delivery_module.shutil, "which", lambda name: f"C:/{name}.exe")

    def fake_json(_gh, args, **_kwargs):
        if args == ["api", "user"]:
            return {"login": "SivaPrasanthSivaraj"}
        if args == ["api", "repos/saiyesh1th/vulnerable-node"]:
            return {"default_branch": "master", "permissions": {"push": False}, "fork": False}
        if args[0] == "api" and ("/pulls?state=open" in args[1] or "/forks?per_page=" in args[1]):
            return []
        raise AssertionError(args)

    monkeypatch.setattr(delivery_module, "_gh_json", fake_json)
    monkeypatch.setattr(delivery_module, "_fork_for_target", lambda *_args, **_kwargs: "SivaPrasanthSivaraj/vulnerable-node-saiyesh")
    def fake_push(_root, remote, branch, _gh):
        calls.update(remote=remote, branch=branch)
        return branch
    monkeypatch.setattr(delivery_module, "_push_for_pr", fake_push)
    monkeypatch.setattr(delivery_module, "_run_external", lambda args, **_kwargs: subprocess.CompletedProcess(args, 0, "https://github.com/saiyesh1th/vulnerable-node/pull/1\n", ""))

    result = dispatch_github_pull_request({"target_repo": "saiyesh1th/vulnerable-node", "branch": "remediation/fix-morgan",
                                           "repo_dir": str(root), "pr_file_absolute": str(body), "pr_title": "Upgrade Morgan"})
    assert result["status"] == "success" and result["url"].endswith("/pull/1")
    assert result["target_repo"] == "saiyesh1th/vulnerable-node"
    assert calls == {"remote": "SivaPrasanthSivaraj/vulnerable-node-saiyesh", "branch": "remediation/fix-morgan"}


def test_push_uses_unique_remote_branch_without_force(tmp_path, monkeypatch):
    root = tmp_path / "repo"
    root.mkdir()
    seen = []
    monkeypatch.setattr(delivery_module.shutil, "which", lambda name: f"C:/{name}.exe")
    monkeypatch.setattr(delivery_module, "run_git", lambda *args, **kwargs: subprocess.CompletedProcess(args, 0, "", ""))

    def fake_external(args, **_kwargs):
        seen.append(args)
        if "ls-remote" in args:
            return subprocess.CompletedProcess(args, 0, "abc\trefs/heads/remediation/fix-morgan-5\n", "")
        return subprocess.CompletedProcess(args, 0, "", "")

    monkeypatch.setattr(delivery_module, "_run_external", fake_external)
    remote_branch = delivery_module._push_for_pr(root, "me/repo", "remediation/fix-morgan-5", "C:/gh.exe")
    assert remote_branch == "remediation/fix-morgan-5-2"
    push = next(args for args in seen if "push" in args)
    assert push[-1] == "remediation/fix-morgan-5:remediation/fix-morgan-5-2"
    assert "--force" not in push and "--force-with-lease" not in push


def test_remediation_ui_same_click_dispatch_shows_pr_url(monkeypatch):
    import ui.pages.remediation_page as page

    class FakeStreamlit:
        session_state = {}
        successes = []
        errors = []
        links = []

        @staticmethod
        def spinner(_message):
            return nullcontext()

        @classmethod
        def success(cls, message):
            cls.successes.append(message)

        @classmethod
        def error(cls, message):
            cls.errors.append(message)

        @classmethod
        def link_button(cls, label, url, **_kwargs):
            cls.links.append((label, url))

    monkeypatch.setattr(page, "st", FakeStreamlit)
    monkeypatch.setattr(page, "dispatch_github_pull_request", lambda _res: {
        "status": "success", "url": "https://github.com/o/r/pull/7", "target_repo": "o/r"
    })
    sent = page._send_prepared_pr({"status": "success", "gh_cli_available": True}, {"url": "https://github.com/o/r"},
                                  {"id": "REM-001", "title": "Upgrade"}, None, "analyst")
    assert sent["status"] == "success"
    assert FakeStreamlit.session_state["pr_sent_REM-001"]["url"].endswith("/pull/7")
    assert any("/pull/7" in message for message in FakeStreamlit.successes)
    assert FakeStreamlit.links == [("Open pull request", "https://github.com/o/r/pull/7")]
    assert not FakeStreamlit.errors
