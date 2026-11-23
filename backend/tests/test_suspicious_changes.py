"""
Tests for Milestone 4: Suspicious Supply Chain Change Detection
Validates detection engines across:
1. Dependency Change & Manifest Inconsistency Analysis
2. Typosquatting & Package Masquerading Detection
3. Lifecycle Script Static Analysis
4. Docker & CI/CD Security Analysis
5. Output Artifact Schema & Explainability
"""

import json
import sys
from pathlib import Path
import pytest

WORKSPACE_ROOT = Path(__file__).resolve().parent.parent.parent
if str(WORKSPACE_ROOT) not in sys.path:
    sys.path.insert(0, str(WORKSPACE_ROOT))

from detectors.dependency_changes import analyze_dependency_changes
from detectors.typosquatting import analyze_typosquatting
from detectors.lifecycle_scripts import analyze_lifecycle_scripts
from detectors.cicd_docker import analyze_cicd_and_docker
SCAN_PATH = WORKSPACE_ROOT / "artifacts" / "scans" / "suspicious_changes.json"


@pytest.fixture(scope="module")
def suspicious_data():
    assert SCAN_PATH.exists(), f"Suspicious changes scan file not found at {SCAN_PATH}"
    with open(SCAN_PATH, "r", encoding="utf-8") as f:
        return json.load(f)


def test_suspicious_artifact_schema(suspicious_data):
    """Verify artifact schema, metrics aggregation, and evidence completeness."""
    assert suspicious_data.get("analysis_type") == "Suspicious Supply Chain Change Detection"
    assert suspicious_data.get("target") == "OWASP NodeGoat"
    assert "metrics" in suspicious_data
    assert "findings" in suspicious_data

    metrics = suspicious_data["metrics"]
    findings = suspicious_data["findings"]

    assert metrics.get("total_findings") == len(findings)
    assert metrics.get("total_findings") >= 20

    # Ensure all 4 detection categories are represented
    category_counts = metrics.get("category_counts", {})
    expected_categories = [
        "Docker & CI/CD",
        "Typosquatting",
        "Lifecycle Script",
        "Dependency Change"
    ]
    for cat in expected_categories:
        assert cat in category_counts, f"Missing category {cat} in metrics"
        assert category_counts[cat] > 0, f"Category {cat} has 0 findings"

    # Verify severity distributions
    severity_counts = metrics.get("severity_counts", {})
    assert severity_counts.get("HIGH", 0) > 0
    assert severity_counts.get("MEDIUM", 0) > 0
    assert severity_counts.get("LOW", 0) > 0

    # Check each individual finding schema
    seen_ids = set()
    required_keys = {
        "id", "category", "severity", "affected_file",
        "line_number", "evidence", "explanation", "confidence",
        "recommended_action"
    }

    for f in findings:
        fid = f.get("id")
        assert fid, "Finding missing 'id'"
        assert fid not in seen_ids, f"Duplicate finding id: {fid}"
        seen_ids.add(fid)

        assert required_keys.issubset(f.keys()), f"Finding {fid} missing required keys"
        assert f["category"] in expected_categories
        assert f["severity"] in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
        assert f["confidence"] in ["CONFIRMED", "HIGH", "MEDIUM", "LOW"]
        assert len(f["evidence"].strip()) > 0, f"Finding {fid} has empty evidence"
        assert len(f["explanation"].strip()) > 0, f"Finding {fid} has empty explanation"
        assert len(f["recommended_action"].strip()) > 0, f"Finding {fid} has empty recommended action"
        assert len(f["affected_file"].strip()) > 0, f"Finding {fid} has empty affected_file"


def test_dependency_changes_detector():
    """Verify manifest-lockfile inconsistencies and unpinned version detection."""
    findings = analyze_dependency_changes(WORKSPACE_ROOT)
    assert len(findings) >= 2

    # Verify unpinned "latest" constraint detection
    latest_finding = next((f for f in findings if "grunt-env" in f["evidence"]), None)
    assert latest_finding is not None, "Failed to detect floating 'latest' constraint for grunt-env"
    assert latest_finding["category"] == "Dependency Change"
    assert latest_finding["severity"] == "HIGH"
    assert latest_finding["confidence"] == "CONFIRMED"
    assert "package.json" in latest_finding["affected_file"]
    assert latest_finding["line_number"] == 50


def test_typosquatting_detector():
    """Verify typosquatting and package masquerading detection with explainable confidence."""
    findings = analyze_typosquatting(WORKSPACE_ROOT)
    assert len(findings) >= 5

    # Check bcrypt-nodejs detection against canonical bcrypt
    bcrypt_finding = next((f for f in findings if "bcrypt-nodejs" in f["id"].lower()), None)
    assert bcrypt_finding is not None, "Failed to detect bcrypt-nodejs similarity against bcrypt"
    assert bcrypt_finding["category"] == "Typosquatting"
    assert "bcrypt" in bcrypt_finding["explanation"].lower()
    # Verify caution: similarity alone is not labeled malicious
    assert "similarity alone does not confirm malicious" in bcrypt_finding["explanation"].lower() or \
           "confidence" in bcrypt_finding["explanation"].lower() or \
           "typosquat" in bcrypt_finding["explanation"].lower()

    # Check node-esapi vs esapi
    esapi_finding = next((f for f in findings if "node-esapi" in f["id"].lower()), None)
    assert esapi_finding is not None, "Failed to detect node-esapi prefix brand candidate"


def test_lifecycle_scripts_detector():
    """Verify static analysis of package.json lifecycle scripts and lockfile install hooks."""
    findings = analyze_lifecycle_scripts(WORKSPACE_ROOT)
    assert len(findings) >= 4

    # Verify detection of docker-mongo script in package.json
    mongo_finding = next((f for f in findings if "docker-mongo" in f["id"].lower()), None)
    assert mongo_finding is not None, "Failed to detect docker-mongo script in package.json"
    assert mongo_finding["category"] == "Lifecycle Script"
    assert "mongo:latest" in mongo_finding["evidence"]

    # Verify detection of install hooks in lockfile dependencies (cypress, nodemon, fsevents)
    hook_findings = [f for f in findings if "INSTALL-HOOK" in f["id"]]
    assert len(hook_findings) >= 3
    hook_pkgs = [f["evidence"] for f in hook_findings]
    assert any("cypress" in p for p in hook_pkgs)
    assert any("nodemon" in p for p in hook_pkgs)


def test_cicd_docker_detector():
    """Verify detection of unpinned Docker base images and mutable GitHub Actions."""
    findings = analyze_cicd_and_docker(WORKSPACE_ROOT)
    assert len(findings) >= 10

    # Verify Dockerfile unpinned tag detection
    docker_findings = [f for f in findings if "DOCKER-UNPINNED" in f["id"]]
    assert len(docker_findings) >= 2  # lines 1 and 7 in Dockerfile
    assert all("Dockerfile" in f["affected_file"] for f in docker_findings)
    assert any(f["line_number"] == 1 for f in docker_findings)
    assert any(f["line_number"] == 7 for f in docker_findings)

    # Verify GitHub Actions mutable tag detection
    action_findings = [f for f in findings if "SUSP-CICD-UNPINNED-ACTION" in f["id"]]
    assert len(action_findings) >= 6
    assert any("actions/checkout@v2" in f["evidence"] for f in action_findings)
    assert any("actions/setup-node@v1" in f["evidence"] for f in action_findings)

    # Verify GitHub Actions missing permissions block detection
    perm_findings = [f for f in findings if "SUSP-CICD-PERM" in f["id"]]
    assert len(perm_findings) >= 2  # e2e-test.yml and lint.yml
    assert all("workflow" in f["explanation"].lower() for f in perm_findings)
