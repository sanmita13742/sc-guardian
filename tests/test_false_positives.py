"""
Legitimate Development Scenarios and False Positive Prevention Test Suite (Person 2 - Phase 2.1)

Validates that Guardian does NOT falsely classify legitimate software engineering
practices as malicious supply-chain attacks or high-severity attack scenarios:

1. Approved Private Enterprise Registries:
   - Configures custom HTTPS internal registry with strict TLS verification.
   - Verified that it is not classified as an attack or insecure transport.

2. Legitimate Git Dependencies Pinned to Immutable Commits:
   - Manifest references git+https repository pinned to a 40-character commit SHA.
   - Verified that cryptographic commit pinning is recognized as mitigating factor (LOW severity).

3. Normal Dependency Updates:
   - Minor/patch semantic version update (express: ^4.18.1 -> ^4.18.2).
   - Verified that routine version maintenance is classified as LOW severity, not an attack.

4. Benign Compilation Scripts:
   - Manifest declares standard build/compilation scripts (node-gyp rebuild, tsc, webpack).
   - Verified that standard build tooling is skipped and not flagged as dangerous execution hooks.

5. First-Party GitHub Actions Workflows:
   - Workflow uses official actions/* actions without injection or remote download.
   - Verified that official first-party actions do not trigger pipeline hijack attack scenarios.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

# Ensure repo root and src are on sys.path
_ROOT = Path(__file__).resolve().parent.parent
_SRC = _ROOT / "src"
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

import pytest

from change_analyzer import ChangeAnalyzer
from suspicious_changes.manifest_diff_detector import inspect_git_diff_range
from suspicious_changes.registry_detector import (
    inspect_registry_configurations,
    inspect_manifest_dependency_sources,
)
from suspicious_changes.lifecycle_script_detector import inspect_lifecycle_scripts_text
from suspicious_changes.change_correlation import correlate_suspicious_changes

SAFE_ENV = {
    k: v for k, v in os.environ.items()
    if not any(s in k.upper() for s in ("KEY", "TOKEN", "SECRET", "PASSWORD", "AUTH"))
}


def _git(args: list[str], cwd: Path, capture_output: bool = False, text: bool = False) -> subprocess.CompletedProcess:
    return subprocess.run(
        args,
        cwd=cwd,
        capture_output=capture_output,
        text=text,
        env=SAFE_ENV,
        shell=False,
    )


# ==============================================================================
# Scenario 1: Approved Private Enterprise Registry
# ==============================================================================

def test_approved_private_enterprise_registry_not_flagged_as_attack(tmp_path: Path):
    """
    Scenario 1: Enterprise uses internal Artifactory/Nexus npm registry over HTTPS with strict TLS.
    Guardian must not classify this as an unencrypted transport or supply-chain attack.
    """
    npmrc = tmp_path / ".npmrc"
    npmrc.write_text(
        "registry=https://npm.corp.internal.example.com/artifactory/api/npm/\n"
        "strict-ssl=true\n"
        "save-exact=true\n"
    )

    findings = inspect_registry_configurations(tmp_path)

    # Must NOT produce high or critical findings (no insecure HTTP, no disabled SSL)
    high_or_crit = [f for f in findings if f.get("severity") in ("CRITICAL", "HIGH")]
    assert len(high_or_crit) == 0, f"Unexpected high/critical findings: {high_or_crit}"

    # Verify any finding emitted is purely informational mirror tracking (LOW severity)
    for f in findings:
        assert f.get("severity") == "LOW"
        assert "REG-INSECURE-HTTP" not in f.get("id", "")
        assert "REG-STRICT-SSL-DISABLED" not in f.get("id", "")

    # Correlation must not create an attack scenario
    result = correlate_suspicious_changes(findings)
    assert result["total_composites"] == 0


# ==============================================================================
# Scenario 2: Legitimate Git Dependency Pinned to Immutable Commit SHA
# ==============================================================================

def test_legitimate_git_dependency_pinned_to_commit(tmp_path: Path):
    """
    Scenario 2: Developer consumes internal library via git+https pinned to an immutable 40-character SHA.
    Guardian recognizes cryptographic pinning as an effective mitigation and assigns LOW severity.
    """
    manifest = {
        "name": "enterprise-app",
        "dependencies": {
            "internal-auth-client": "git+https://github.com/my-corp/auth-client.git#4a5b6c7d8e9f0123456789abcdef0123456789ab"
        }
    }

    findings = inspect_manifest_dependency_sources(manifest, "package.json")
    assert len(findings) == 1

    f = findings[0]
    assert f["severity"] == "LOW"
    assert "Pinned to Commit SHA" in f["title"]
    assert "immutable 40-character commit SHA" in f["technical_explanation"]

    # Correlation with no install scripts must not create an attack scenario
    result = correlate_suspicious_changes(findings)
    assert result["total_composites"] == 0


# ==============================================================================
# Scenario 3: Normal Routine Dependency Updates
# ==============================================================================

def test_routine_semver_update_is_low_severity(tmp_path: Path):
    """
    Scenario 3: Routine semantic version patch/minor bump within same release series.
    Guardian marks routine updates as LOW severity, distinguishing them from major jumps or floating updates.
    """
    repo = tmp_path / "repo-routine-bump"
    repo.mkdir()
    _git(["git", "init"], cwd=repo, capture_output=True)
    _git(["git", "config", "user.name", "Developer"], cwd=repo)
    _git(["git", "config", "user.email", "dev@example.com"], cwd=repo)

    # Base commit
    base_pkg = {"name": "app", "dependencies": {"express": "^4.18.1"}}
    (repo / "package.json").write_text(json.dumps(base_pkg, indent=2))
    _git(["git", "add", "package.json"], cwd=repo)
    _git(["git", "commit", "-m", "Base commit with express 4.18.1"], cwd=repo)
    base_sha = _git(["git", "rev-parse", "HEAD"], cwd=repo, capture_output=True, text=True).stdout.strip()

    # Head commit: routine minor patch bump
    head_pkg = {"name": "app", "dependencies": {"express": "^4.18.2"}}
    (repo / "package.json").write_text(json.dumps(head_pkg, indent=2))
    _git(["git", "add", "package.json"], cwd=repo)
    _git(["git", "commit", "-m", "Bump express to 4.18.2"], cwd=repo)
    head_sha = _git(["git", "rev-parse", "HEAD"], cwd=repo, capture_output=True, text=True).stdout.strip()

    findings = inspect_git_diff_range(repo, base_sha, head_sha)
    assert len(findings) >= 1

    modified = next((f for f in findings if "DIFF-DEP-MODIFIED-EXPRESS" in f["id"]), None)
    assert modified is not None
    assert modified["severity"] == "LOW"
    assert "routine semver update" in modified["technical_explanation"].lower()


# ==============================================================================
# Scenario 4: Benign Installation Scripts
# ==============================================================================

def test_benign_compilation_scripts_are_not_flagged():
    """
    Scenario 4: Manifest uses standard build/native compilation scripts (node-gyp rebuild, tsc, webpack).
    Guardian skips known benign compilation tools and produces zero suspicious lifecycle findings.
    """
    manifest_content = json.dumps({
        "name": "native-addon",
        "scripts": {
            "install": "node-gyp rebuild",
            "build": "tsc",
            "bundle": "webpack --mode production"
        }
    })

    findings = inspect_lifecycle_scripts_text(manifest_content, "package.json")
    assert len(findings) == 0, f"Expected 0 findings for benign compilation scripts, got {findings}"


# ==============================================================================
# Scenario 5: First-Party GitHub Actions Workflow
# ==============================================================================

def test_first_party_github_actions_not_classified_as_attack(tmp_path: Path):
    """
    Scenario 5: Workflow incorporates official GitHub Actions (actions/checkout@v4, actions/setup-node@v4).
    Guardian does NOT classify official first-party actions as a pipeline hijack attack scenario.
    """
    repo = tmp_path / "repo-first-party-ci"
    repo.mkdir()
    _git(["git", "init"], cwd=repo, capture_output=True)
    _git(["git", "config", "user.name", "CI Builder"], cwd=repo)
    _git(["git", "config", "user.email", "ci@example.com"], cwd=repo)

    wf_dir = repo / ".github" / "workflows"
    wf_dir.mkdir(parents=True)
    workflow_content = """name: Standard CI
on: [push]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout
        uses: actions/checkout@v4
      - name: Setup Node.js
        uses: actions/setup-node@v4
        with:
          node-version: '20'
      - name: Run Tests
        run: npm test
"""
    (wf_dir / "ci.yml").write_text(workflow_content)
    (repo / "package.json").write_text(json.dumps({"name": "standard-app", "scripts": {"test": "jest"}}))

    _git(["git", "add", "."], cwd=repo)
    _git(["git", "commit", "-m", "Standard CI workflow setup"], cwd=repo)
    sha = _git(["git", "rev-parse", "HEAD"], cwd=repo, capture_output=True, text=True).stdout.strip()

    analyzer = ChangeAnalyzer(repo_dir=repo, base_commit=f"{sha}~0", head_commit=sha)
    result = analyzer.run_investigation()

    # Must not contain any CRITICAL or HIGH pipeline attack scenarios
    pipeline_attacks = [
        s for s in result.get("correlated_scenarios", [])
        if s.get("scenario_type") == "pipeline_hijack" and s.get("severity") in ("CRITICAL", "HIGH")
    ]
    assert len(pipeline_attacks) == 0, f"First-party actions falsely flagged as pipeline attack: {pipeline_attacks}"

    # In fact, since there is no third-party action, injection, or remote shell,
    # no pipeline hijack scenario should be generated at all
    all_pipeline_scenarios = [
        s for s in result.get("correlated_scenarios", [])
        if s.get("scenario_type") == "pipeline_hijack"
    ]
    assert len(all_pipeline_scenarios) == 0
