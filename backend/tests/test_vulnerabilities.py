"""
Tests for Milestone 3: Vulnerability Detection
Validates OSV-Scanner outputs, reconciliation with component-inventory,
provenance preservation, no duplicates, and graph enrichment.
"""

import json
from pathlib import Path
import pytest

WORKSPACE_ROOT = Path(__file__).resolve().parent.parent.parent
SCAN_PATH = WORKSPACE_ROOT / "artifacts" / "scans" / "nodegoat-vulnerabilities.json"
GRAPH_PATH = WORKSPACE_ROOT / "nodegoat-dependency-graph.json"
INVENTORY_PATH = WORKSPACE_ROOT / "component-inventory.json"


@pytest.fixture(scope="module")
def scan_data():
    assert SCAN_PATH.exists(), f"Vulnerabilities scan file not found at {SCAN_PATH}"
    with open(SCAN_PATH, "r", encoding="utf-8") as f:
        return json.load(f)


@pytest.fixture(scope="module")
def graph_data():
    assert GRAPH_PATH.exists(), f"Graph file not found at {GRAPH_PATH}"
    with open(GRAPH_PATH, "r", encoding="utf-8") as f:
        return json.load(f)


@pytest.fixture(scope="module")
def inventory_data():
    assert INVENTORY_PATH.exists(), f"Inventory file not found at {INVENTORY_PATH}"
    with open(INVENTORY_PATH, "r", encoding="utf-8") as f:
        return json.load(f)


def test_vulnerabilities_artifact_structure(scan_data):
    """Verify high-level metadata and scanner information."""
    assert scan_data.get("scanner") == "Google OSV-Scanner"
    assert "metrics" in scan_data
    metrics = scan_data["metrics"]

    assert metrics.get("total_packages_scanned") == 1091
    assert metrics.get("vulnerable_packages_count") == 98
    assert metrics.get("total_vulnerabilities") == 200
    assert metrics.get("unique_advisory_ids") == 141

    prod_vulns = metrics.get("production_vulnerabilities", 0)
    dev_vulns = metrics.get("development_vulnerabilities", 0)
    assert prod_vulns + dev_vulns == metrics["total_vulnerabilities"]

    severity_counts = metrics.get("severity_counts", {})
    assert severity_counts.get("CRITICAL", 0) > 0
    assert severity_counts.get("HIGH", 0) > 0
    assert severity_counts.get("MODERATE", 0) > 0
    assert severity_counts.get("LOW", 0) > 0


def test_no_duplicate_findings_per_package(scan_data):
    """Ensure identical package identities do not contain duplicated vulnerability advisories."""
    findings = scan_data.get("findings", [])
    seen = set()

    for f in findings:
        key = (f["id"], f["package_name"], f["version"])
        assert key not in seen, f"Duplicate vulnerability finding detected: {key}"
        seen.add(key)


def test_vulnerability_evidence_fields(scan_data):
    """Verify all findings preserve strict evidence (CVE/OSV ID, PURL, fixed version, refs)."""
    findings = scan_data.get("findings", [])
    assert len(findings) == 200

    valid_severities = {"CRITICAL", "HIGH", "MODERATE", "LOW", "UNKNOWN"}

    for f in findings:
        assert f.get("id"), "Missing vulnerability ID"
        assert f.get("osv_id"), "Missing canonical OSV ID"
        assert f.get("package_name"), "Missing package name"
        assert f.get("version"), "Missing package version"
        assert f.get("purl", "").startswith("pkg:npm/"), f"Invalid PURL format: {f.get('purl')}"
        assert f.get("severity") in valid_severities, f"Invalid severity: {f.get('severity')}"
        assert f.get("environment") in ("production", "development"), f"Invalid environment: {f.get('environment')}"
        assert f.get("dependency_type") in ("direct", "transitive"), f"Invalid dep type: {f.get('dependency_type')}"
        assert isinstance(f.get("installation_paths", []), list), "Installation paths must be a list"
        assert len(f.get("installation_paths", [])) >= 1, "Must preserve at least one installation path"
        assert isinstance(f.get("dependency_lineage", []), list), "Dependency lineage must be a list"
        assert len(f.get("dependency_lineage", [])) >= 2, "Lineage must connect from root to target"


def test_inventory_mapping(scan_data, inventory_data):
    """Verify that every vulnerable package exists in the component inventory."""
    inventory_comps = {f"{c['name']}@{c['version']}": c for c in inventory_data.get("components", [])}

    for vp in scan_data.get("vulnerable_packages", []):
        comp_id = f"{vp['name']}@{vp['version']}"
        assert comp_id in inventory_comps, f"Vulnerable package {comp_id} not found in inventory"
        inv_item = inventory_comps[comp_id]
        assert vp["environment"] == inv_item["environment"], f"Environment mismatch for {comp_id}"


def test_graph_enrichment(graph_data, scan_data):
    """Verify that graph nodes are enriched with vulnerability metadata."""
    nodes = graph_data.get("nodes", [])
    vulnerable_nodes = [n for n in nodes if n.get("has_vulnerability")]

    assert len(vulnerable_nodes) == 98, f"Expected 98 vulnerable nodes in graph, found {len(vulnerable_nodes)}"

    for vn in vulnerable_nodes:
        assert vn.get("vulnerability_count", 0) > 0
        assert vn.get("max_severity") in {"CRITICAL", "HIGH", "MODERATE", "LOW"}
        assert len(vn.get("vulnerabilities", [])) == vn["vulnerability_count"]
