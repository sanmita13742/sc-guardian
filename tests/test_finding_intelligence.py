"""
Comprehensive Regression Test Suite for Finding Intelligence (Person 2 - Section H)
Tests all regression cases identified in the NodeGoat audit:
1. Typosquatting conventions vs genuine deceptive homoglyphs (bcrypt-nodejs, object-assign, safe-buffer, through2).
2. Prevention of educational-context bias (educational app status cannot dismiss EOL images or floating versions).
3. Separation of independent risk dimensions (initial static severity, AI verdict, specific suspicion resolved, remaining risks).
4. Evidence interpretation for Git dependencies (commit SHA vs mutable branch).
5. GitHub Actions provenance (first-party actions vs third-party, undeclared permissions).
6. Grounding Gate enforcement (rejects empty supporting evidence, educational bias, unproven compromise claims).
7. Non-execution and safety invariants.
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parent.parent
_SRC = _ROOT / "src"
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

import pytest

from agents.suspicious_change_agent import (
    SuspiciousChangeAgent,
    grounding_gate_node,
    _deterministic_reasoning_turn,
)
from change_analyzer import ChangeAnalyzer
from suspicious_changes.typosquatting_detector import candidate_matches
from suspicious_changes.registry_detector import inspect_manifest_dependency_sources

SAFE_ENV = {
    k: v for k, v in os.environ.items()
    if not any(s in k.upper() for s in ("KEY", "TOKEN", "SECRET", "PASSWORD", "AUTH"))
}


def _git(args: list[str], cwd: Path, capture_output: bool = True, text: bool = True) -> subprocess.CompletedProcess:
    return subprocess.run(args, cwd=cwd, capture_output=capture_output, text=text, env=SAFE_ENV, shell=False)


# ==============================================================================
# B. Regression Tests: Typosquatting Algorithm & Ecosystem Conventions
# ==============================================================================

def test_regression_typosquatting_bcrypt_nodejs():
    """bcrypt-nodejs vs bcrypt: implementation affix convention, not deceptive typosquat."""
    matches = candidate_matches("npm", "bcrypt-nodejs", ["bcrypt"])
    assert len(matches) == 1
    m = matches[0]
    assert m["is_ecosystem_convention"] is True
    assert m["is_deceptive"] is False
    assert any("affix (nodejs)" in t for t in m["techniques"])

    # AI Investigation should resolve typosquatting suspicion while maintaining deprecation/maintenance
    agent = SuspiciousChangeAgent(client=None)
    finding = {
        "id": "SUSP-TYPO-BCRYPT-NODEJS",
        "category": "Typosquatting",
        "title": "Package 'bcrypt-nodejs' Shares High Name Similarity with 'bcrypt'",
        "severity": "LOW",
        "affected_file": "package.json",
        "line_number": 8,
        "evidence": "Package \"bcrypt-nodejs\" similar to popular \"bcrypt\" (common affix: nodejs)",
        "technical_explanation": "Package 'bcrypt-nodejs' has an edit distance of 7 from 'bcrypt'. Identified: common affix (nodejs). Package is deprecated.",
    }
    inv = agent.investigate_finding(finding, repo_dir=Path("."))
    assert inv["verdict"] == "BENIGN_EXPLANATION"
    assert inv["confidence"] == "HIGH"
    assert inv["specific_suspicion_resolved"] is not None
    assert "typosquatting" in inv["specific_suspicion_resolved"].lower()
    assert len(inv["contradicting_evidence"]) >= 1
    assert any("convention" in ce["factor"].lower() for ce in inv["contradicting_evidence"])
    assert inv["maintenance_status"] == "DEPRECATED"
    assert len(inv["remaining_security_risks"]) >= 1


def test_regression_typosquatting_object_assign_separator_variant():
    """object-assign vs object.assign: companion separator variant in popular packages catalog."""
    matches = candidate_matches("npm", "object-assign", ["object.assign"])
    assert len(matches) == 1
    m = matches[0]
    assert m["is_ecosystem_convention"] is True
    assert m["is_deceptive"] is False
    assert any("separator" in t for t in m["techniques"])


def test_regression_typosquatting_safe_buffer_companion():
    """safe-buffer vs safer-buffer: companion variant conventions."""
    matches = candidate_matches("npm", "safe-buffer", ["safer-buffer"])
    assert len(matches) == 1
    m = matches[0]
    assert m["is_ecosystem_convention"] is True
    assert m["is_deceptive"] is False
    assert any("companion" in t for t in m["techniques"])


def test_regression_typosquatting_through2_version_fork():
    """through vs through2: numeric version fork convention."""
    matches = candidate_matches("npm", "through2", ["through"])
    assert len(matches) == 1
    m = matches[0]
    assert m["is_ecosystem_convention"] is True
    assert m["is_deceptive"] is False
    assert m["convention_type"] == "version_fork" or any("version" in t for t in m["techniques"])


def test_regression_deceptive_typosquat_detected():
    """Genuine deceptive typosquat (e.g. lodsh vs lodash) MUST be identified as deceptive."""
    matches = candidate_matches("npm", "lodsh", ["lodash"])
    assert len(matches) == 1
    m = matches[0]
    assert m["is_deceptive"] is True
    assert m["is_ecosystem_convention"] is False

    # AI Investigation of deceptive typosquat confirms anomaly
    agent = SuspiciousChangeAgent(client=None)
    finding = {
        "id": "SUSP-TYPO-LODSH",
        "category": "Typosquatting",
        "title": "Package 'lodsh' Shares High Name Similarity with 'lodash'",
        "severity": "HIGH",
        "affected_file": "package.json",
        "line_number": 12,
        "evidence": "Package \"lodsh\" has edit distance 1 from \"lodash\"",
        "technical_explanation": "Single-character deletion targeting high-traffic library lodash.",
    }
    inv = agent.investigate_finding(finding, repo_dir=Path("."))
    assert inv["verdict"] == "CONFIRMED_ANOMALY"
    assert inv["confidence"] == "HIGH"
    assert len(inv["supporting_evidence"]) >= 1


# ==============================================================================
# C. Regression Tests: Prevention of Educational-Context Bias
# ==============================================================================

def test_regression_floating_grunt_env_not_dismissed():
    """Floating constraint (grunt-env: latest) preserved as CONFIRMED_ANOMALY despite educational repo."""
    agent = SuspiciousChangeAgent(client=None)
    finding = {
        "id": "SUSP-DEP-FLOATING-GRUNT-ENV",
        "category": "Dependency Change",
        "title": "Floating Dependency Version Constraint for 'grunt-env'",
        "severity": "HIGH",
        "affected_file": "package.json",
        "line_number": 50,
        "evidence": '"grunt-env": "latest"',
        "technical_explanation": "Floating 'latest' tag prevents deterministic builds and reproducibility.",
    }
    inv = agent.investigate_finding(finding, repo_dir=Path("."))
    assert inv["verdict"] == "CONFIRMED_ANOMALY"
    assert inv["confidence"] == "HIGH"
    assert len(inv["supporting_evidence"]) >= 1
    assert any("floating" in se["factor"].lower() for se in inv["supporting_evidence"])
    assert len(inv["remaining_security_risks"]) >= 1


def test_regression_docker_mongo_eol_not_dismissed():
    """Docker mongo:4.4 EOL preserved as CONFIRMED_ANOMALY with official EOL evidence."""
    agent = SuspiciousChangeAgent(client=None)
    finding = {
        "id": "SUSP-DOCKER-DF012-L14",
        "category": "Docker & CI/CD",
        "title": "Service 'mongo' uses an end-of-life image",
        "severity": "MEDIUM",
        "affected_file": "docker-compose.yml",
        "line_number": 14,
        "evidence": "image: mongo:4.4",
        "technical_explanation": "MongoDB 5.0 and older are end-of-life (lifecycle table reviewed 2026-11).",
    }
    inv = agent.investigate_finding(finding, repo_dir=Path("."))
    assert inv["verdict"] == "CONFIRMED_ANOMALY"
    assert inv["confidence"] == "HIGH"
    assert inv["maintenance_status"] == "END_OF_LIFE"
    assert len(inv["supporting_evidence"]) >= 1
    assert any("end-of-life" in se["factor"].lower() for se in inv["supporting_evidence"])
    assert len(inv["remaining_security_risks"]) >= 1


# ==============================================================================
# D. Regression Tests: Evidence Interpretation (Git dependencies, CI/CD)
# ==============================================================================

def test_regression_git_dependency_immutable_sha_vs_mutable_branch(tmp_path: Path):
    """Git dependencies: 40-character SHA pin has LOW severity; mutable branch has MEDIUM severity."""
    # 1. Pinned commit SHA
    manifest_pinned = {
        "dependencies": {
            "grunt-if": "https://github.com/binarymist/grunt-if/tarball/0123456789abcdef0123456789abcdef01234567"
        }
    }
    findings_pinned = inspect_manifest_dependency_sources(manifest_pinned, "package.json")
    assert len(findings_pinned) == 1
    assert findings_pinned[0]["severity"] == "LOW"
    assert "immutable" in findings_pinned[0]["technical_explanation"].lower()

    # 2. Mutable branch head
    manifest_branch = {
        "dependencies": {
            "grunt-if": "https://github.com/binarymist/grunt-if/tarball/master"
        }
    }
    findings_branch = inspect_manifest_dependency_sources(manifest_branch, "package.json")
    assert len(findings_branch) == 1
    assert findings_branch[0]["severity"] == "MEDIUM"
    assert "mutable" in findings_branch[0]["technical_explanation"].lower()


def test_regression_github_actions_first_party_and_permissions():
    """First-party actions and undeclared permissions are properly contextualized."""
    agent = SuspiciousChangeAgent(client=None)

    # First-party action unpinned tag
    f_action = {
        "id": "SUSP-CICD-GHA001-14",
        "category": "Docker & CI/CD",
        "title": "Action 'actions/checkout' is not pinned to a commit SHA",
        "severity": "LOW",
        "affected_file": ".github/workflows/guardian.yml",
        "line_number": 14,
        "evidence": "uses: actions/checkout@v2",
        "technical_explanation": "Official first-party action referenced by mutable tag.",
    }
    inv_action = agent.investigate_finding(f_action, repo_dir=Path("."))
    assert inv_action["verdict"] == "CONFIRMED_ANOMALY"
    assert inv_action["confidence"] == "MEDIUM"
    assert len(inv_action["contradicting_evidence"]) >= 1
    assert any("official" in ce["factor"].lower() for ce in inv_action["contradicting_evidence"])

    # Undeclared permissions block
    f_perm = {
        "id": "SUSP-CICD-GHA004-1",
        "category": "Docker & CI/CD",
        "title": "No explicit token permissions (defaults may be read-write)",
        "severity": "LOW",
        "affected_file": ".github/workflows/e2e-test.yml",
        "line_number": 1,
        "evidence": "workflow lacks 'permissions:' block",
        "technical_explanation": "No explicit permissions: block; effective rights depend on organization defaults.",
    }
    inv_perm = agent.investigate_finding(f_perm, repo_dir=Path("."))
    assert inv_perm["verdict"] == "CONFIRMED_ANOMALY"
    assert inv_perm["confidence"] == "MEDIUM"
    assert any("default read-only" in ce["factor"].lower() for ce in inv_perm["contradicting_evidence"])


# ==============================================================================
# E. Regression Tests: Grounding Gate Enforcement
# ==============================================================================

def test_grounding_gate_rejects_empty_supporting_evidence_for_anomaly():
    """Grounding gate must reject CONFIRMED_ANOMALY if supporting evidence is empty."""
    state = {
        "finding_id": "TEST-1",
        "finding": {"affected_file": "package.json"},
        "observed_facts": ["File package.json was analyzed."],
        "verdict": "CONFIRMED_ANOMALY",
        "confidence": "HIGH",
        "rationale": "Arbitrary anomaly proposal.",
        "supporting_evidence": [],  # VIOLATION: Empty supporting evidence
        "contradicting_evidence": [],
        "attack_scenario": None,
    }
    res = grounding_gate_node(state)
    assert len(res["grounding_problems"]) >= 1
    assert any("supporting evidence" in p for p in res["grounding_problems"])
    assert res["planner"] == "deterministic_grounded_fallback"


def test_grounding_gate_rejects_educational_bias_dismissals():
    """Grounding gate must reject BENIGN_EXPLANATION if rationale cites educational purpose."""
    state = {
        "finding_id": "TEST-2",
        "finding": {"affected_file": "docker-compose.yml"},
        "observed_facts": ["File docker-compose.yml was analyzed."],
        "verdict": "BENIGN_EXPLANATION",
        "confidence": "HIGH",
        "rationale": "This finding is safe because NodeGoat is an educational repository for learning.",
        "supporting_evidence": [],
        "contradicting_evidence": [{"factor": "Educational", "detail": "NodeGoat is for learning"}],
        "attack_scenario": None,
    }
    res = grounding_gate_node(state)
    assert len(res["grounding_problems"]) >= 1
    assert any("educational" in p.lower() for p in res["grounding_problems"])
    assert res["planner"] == "deterministic_grounded_fallback"


def test_grounding_gate_rejects_unproven_compromise_claims():
    """Grounding gate must reject claims of confirmed breach based on static indicators."""
    state = {
        "finding_id": "TEST-3",
        "finding": {"affected_file": "package.json"},
        "observed_facts": ["File package.json was analyzed."],
        "verdict": "SUSPECTED_SUPPLY_CHAIN_ATTACK",
        "confidence": "HIGH",
        "rationale": "Static inspection confirmed the system is pwned and active breach occurred on host.",
        "supporting_evidence": [{"factor": "Script", "detail": "postinstall script"}],
        "contradicting_evidence": [],
        "attack_scenario": "Host takeover",
    }
    res = grounding_gate_node(state)
    assert len(res["grounding_problems"]) >= 1
    assert any("compromise or breach" in p for p in res["grounding_problems"])
    assert res["planner"] == "deterministic_grounded_fallback"
