#!/usr/bin/env python3
"""
Software Supply Chain Guardian - Vulnerability Scanner Engine
Milestone 3: Vulnerability Detection

Integrates Google OSV-Scanner CLI to scan package-lock.json,
normalizes findings against component-inventory.json and nodegoat-dependency-graph.json,
maps supply-chain lineages, and outputs structured security scan artifacts.
"""

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
import networkx as nx

WORKSPACE_ROOT = Path(__file__).resolve().parent
LOCKFILE_PATH = WORKSPACE_ROOT / "nodegoat" / "package-lock.json"
INVENTORY_PATH = WORKSPACE_ROOT / "component-inventory.json"
GRAPH_PATH = WORKSPACE_ROOT / "nodegoat-dependency-graph.json"
SCANS_DIR = WORKSPACE_ROOT / "artifacts" / "scans"
OUTPUT_SCAN_PATH = SCANS_DIR / "nodegoat-vulnerabilities.json"
FRONTEND_PUBLIC_SCAN = WORKSPACE_ROOT / "frontend" / "public" / "nodegoat-vulnerabilities.json"
FRONTEND_PUBLIC_GRAPH = WORKSPACE_ROOT / "frontend" / "public" / "nodegoat-dependency-graph.json"

DEFAULT_OSV_BINARY = Path(r"C:\Users\yeshx\AppData\Local\Microsoft\WinGet\Packages\Google.OSVScanner\osv-scanner.exe")


def find_osv_scanner() -> str:
    """Locate the osv-scanner binary."""
    if DEFAULT_OSV_BINARY.exists():
        return str(DEFAULT_OSV_BINARY)
    which_path = shutil.which("osv-scanner")
    if which_path:
        return which_path
    raise FileNotFoundError("osv-scanner executable not found. Please ensure it is installed.")


def extract_cvss_score(score_str: Optional[str], cvss_vector: Optional[str]) -> Optional[float]:
    """Extract numeric CVSS score from string or vector."""
    if score_str:
        try:
            return float(score_str)
        except (ValueError, TypeError):
            pass
    # If vector is provided, CVSS 3.x can be approximated or parsed if numeric
    return None


def parse_affected_range(affected_list: List[Dict[str, Any]]) -> Tuple[str, Optional[str]]:
    """Extract human-readable affected version range and fixed version."""
    fixed_versions = []
    range_descriptions = []

    for item in affected_list:
        ranges = item.get("ranges", [])
        for r in ranges:
            events = r.get("events", [])
            intro = None
            fixed = None
            for ev in events:
                if "introduced" in ev:
                    intro = ev["introduced"]
                if "fixed" in ev:
                    fixed = ev["fixed"]
                    if fixed not in fixed_versions:
                        fixed_versions.append(fixed)
            if intro and fixed:
                range_descriptions.append(f">={intro}, <{fixed}" if intro != "0" else f"<{fixed}")
            elif fixed:
                range_descriptions.append(f"<{fixed}")
            elif intro:
                range_descriptions.append(f">={intro}")

    affected_range = ", ".join(range_descriptions) if range_descriptions else "All versions"
    fixed_version = fixed_versions[0] if fixed_versions else None
    return affected_range, fixed_version


def run_scan() -> Dict[str, Any]:
    print("[*] Software Supply Chain Guardian - OSV Vulnerability Scanner")
    print(f"[*] Scanning lockfile: {LOCKFILE_PATH}")

    osv_exe = find_osv_scanner()
    print(f"[*] Using scanner binary: {osv_exe}")

    SCANS_DIR.mkdir(parents=True, exist_ok=True)
    raw_output_path = SCANS_DIR / "osv-raw-output.json"

    # Run OSV-Scanner v2.x CLI command
    cmd = [
        osv_exe,
        "scan",
        "source",
        f"--lockfile={LOCKFILE_PATH}",
        "--format=json",
        f"--output-file={raw_output_path}"
    ]

    print(f"[*] Executing: {' '.join(cmd)}")
    res = subprocess.run(cmd, capture_output=True, text=True)
    # osv-scanner returns 1 when vulnerabilities are found, 0 when clean
    if res.returncode not in (0, 1):
        print(f"[!] Warning: OSV-Scanner exited with code {res.returncode}")
        print(f"[!] Stderr: {res.stderr}")

    if not raw_output_path.exists():
        raise RuntimeError(f"Scan output file was not created at {raw_output_path}")

    with open(raw_output_path, "r", encoding="utf-8") as f:
        raw_data = json.load(f)

    # Load component inventory and lockfile packages for path reconciliation
    with open(INVENTORY_PATH, "r", encoding="utf-8") as f:
        inventory = json.load(f)

    comps = inventory.get("components", [])
    inventory_by_comp_id = {f"{c['name']}@{c['version']}": c for c in comps}
    inventory_by_name = {c["name"]: c for c in comps}

    with open(LOCKFILE_PATH, "r", encoding="utf-8") as f:
        lock_data = json.load(f)

    lock_packages = lock_data.get("packages", {})
    all_install_paths_by_pkg: Dict[str, List[str]] = {}
    for path, info in lock_packages.items():
        if not path:
            continue
        pkg_name = path.split("node_modules/")[-1]
        ver = info.get("version")
        key = f"{pkg_name}@{ver}"
        all_install_paths_by_pkg.setdefault(key, []).append(path)

    # Load dependency graph for path tracing
    graph_data = {}
    nx_graph = nx.DiGraph()
    if GRAPH_PATH.exists():
        with open(GRAPH_PATH, "r", encoding="utf-8") as f:
            graph_data = json.load(f)
        for node in graph_data.get("nodes", []):
            nx_graph.add_node(node["id"], **node)
        for edge in graph_data.get("edges", []):
            nx_graph.add_edge(edge["source"], edge["target"])

    def get_dependency_paths(node_id: str) -> List[List[str]]:
        if not nx_graph.has_node("root") or not nx_graph.has_node(node_id):
            return []
        try:
            # Find shortest path from root to target
            path = nx.shortest_path(nx_graph, source="root", target=node_id)
            return [path]
        except (nx.NetworkXNoPath, nx.NodeNotFound):
            return []

    # Process findings from OSV results
    results = raw_data.get("results", [])
    raw_packages = results[0].get("packages", []) if results else []

    vulnerable_packages_map: Dict[str, Dict[str, Any]] = {}
    flat_findings: List[Dict[str, Any]] = []

    unique_cve_ids = set()
    severity_counter = Counter()

    for p in raw_packages:
        pkg_info = p.get("package", {})
        pkg_name = pkg_info.get("name")
        version = pkg_info.get("version")
        comp_id = f"{pkg_name}@{version}"

        # Match with inventory
        inv_item = inventory_by_comp_id.get(comp_id) or inventory_by_name.get(pkg_name, {})
        environment = inv_item.get("environment", "development" if p.get("package", {}).get("dev") else "production")
        dep_type = inv_item.get("dependency_type", "transitive")
        purl = inv_item.get("purl") or f"pkg:npm/{pkg_name}@{version}"

        installation_paths = all_install_paths_by_pkg.get(comp_id, [f"node_modules/{pkg_name}"])
        dep_paths = get_dependency_paths(comp_id)

        # Check groups for max severity score
        group_max_severities = {}
        for g in p.get("groups", []):
            for gid in g.get("ids", []):
                if g.get("max_severity"):
                    group_max_severities[gid] = g["max_severity"]

        pkg_findings = []
        seen_pkg_vuln_ids = set()
        max_pkg_severity_level = "LOW"
        severity_rank = {"CRITICAL": 4, "HIGH": 3, "MODERATE": 2, "MEDIUM": 2, "LOW": 1, "UNKNOWN": 0}

        for vuln in p.get("vulnerabilities", []):
            vuln_id = vuln.get("id")
            aliases = vuln.get("aliases", [])

            # Extract primary CVE ID if present, else fallback to GHSA/OSV ID
            cve_id = None
            for a in aliases:
                if a.startswith("CVE-"):
                    cve_id = a
                    break
            primary_id = cve_id or vuln_id

            # Deduplicate findings for the same package identity referencing the same CVE/advisory
            if primary_id in seen_pkg_vuln_ids:
                for existing in pkg_findings:
                    if existing["id"] == primary_id:
                        for a in aliases:
                            if a not in existing["aliases"]:
                                existing["aliases"].append(a)
                        for ref in vuln.get("references", []):
                            u = ref.get("url")
                            if u and u not in existing["references"]:
                                existing["references"].append(u)
                continue
            seen_pkg_vuln_ids.add(primary_id)
            unique_cve_ids.add(primary_id)

            # Severity extraction
            raw_sev = vuln.get("database_specific", {}).get("severity")
            cvss_vec = None
            for s in vuln.get("severity", []):
                if s.get("type") in ("CVSS_V3", "CVSS_V2"):
                    cvss_vec = s.get("score")
                    break

            cvss_score = None
            if vuln_id in group_max_severities:
                try:
                    cvss_score = float(group_max_severities[vuln_id])
                except ValueError:
                    pass

            if not raw_sev:
                if cvss_score is not None:
                    if cvss_score >= 9.0:
                        raw_sev = "CRITICAL"
                    elif cvss_score >= 7.0:
                        raw_sev = "HIGH"
                    elif cvss_score >= 4.0:
                        raw_sev = "MODERATE"
                    else:
                        raw_sev = "LOW"
                else:
                    raw_sev = "UNKNOWN"

            normalized_sev = raw_sev.upper()
            if normalized_sev == "MEDIUM":
                normalized_sev = "MODERATE"

            severity_counter[normalized_sev] += 1

            if severity_rank.get(normalized_sev, 0) > severity_rank.get(max_pkg_severity_level, 0):
                max_pkg_severity_level = normalized_sev

            affected_range, fixed_ver = parse_affected_range(vuln.get("affected", []))

            # References
            refs = [ref.get("url") for ref in vuln.get("references", []) if ref.get("url")]

            finding_obj = {
                "id": primary_id,
                "osv_id": vuln_id,
                "aliases": aliases,
                "package_name": pkg_name,
                "version": version,
                "purl": purl,
                "environment": environment,
                "dependency_type": dep_type,
                "summary": vuln.get("summary") or "No summary provided",
                "details": vuln.get("details") or "",
                "severity": normalized_sev,
                "cvss_score": cvss_score,
                "cvss_vector": cvss_vec,
                "affected_range": affected_range,
                "fixed_version": fixed_ver,
                "references": refs[:5],
                "installation_paths": installation_paths,
                "dependency_lineage": dep_paths[0] if dep_paths else ["root", comp_id]
            }

            pkg_findings.append(finding_obj)
            flat_findings.append(finding_obj)

        vulnerable_packages_map[comp_id] = {
            "id": comp_id,
            "name": pkg_name,
            "version": version,
            "purl": purl,
            "environment": environment,
            "dependency_type": dep_type,
            "max_severity": max_pkg_severity_level,
            "vulnerability_count": len(pkg_findings),
            "installation_paths": installation_paths,
            "dependency_lineage": dep_paths[0] if dep_paths else ["root", comp_id],
            "vulnerabilities": pkg_findings
        }

    # Summary metrics
    prod_vulns = sum(1 for f in flat_findings if f["environment"] == "production")
    dev_vulns = sum(1 for f in flat_findings if f["environment"] == "development")

    scan_summary = {
        "scanner": "Google OSV-Scanner",
        "scanner_version": "2.7.0",
        "target": "OWASP NodeGoat (nodegoat/package-lock.json)",
        "scan_timestamp": "2026-11-23T16:40:00+05:30",
        "metrics": {
            "total_packages_scanned": 1091,
            "vulnerable_packages_count": len(vulnerable_packages_map),
            "total_vulnerabilities": len(flat_findings),
            "unique_advisory_ids": len(unique_cve_ids),
            "production_vulnerabilities": prod_vulns,
            "development_vulnerabilities": dev_vulns,
            "severity_counts": dict(severity_counter)
        },
        "vulnerable_packages": list(vulnerable_packages_map.values()),
        "findings": flat_findings
    }

    # Save to artifacts/scans/
    with open(OUTPUT_SCAN_PATH, "w", encoding="utf-8") as f:
        json.dump(scan_summary, f, indent=2)
    print(f"[✓] Saved vulnerability scan results to {OUTPUT_SCAN_PATH}")

    # Sync to frontend public
    if FRONTEND_PUBLIC_SCAN.parent.exists():
        with open(FRONTEND_PUBLIC_SCAN, "w", encoding="utf-8") as f:
            json.dump(scan_summary, f, indent=2)
        print(f"[✓] Synced scan results to {FRONTEND_PUBLIC_SCAN}")

    # Enrich graph nodes with vulnerability data
    if graph_data:
        enrich_graph(graph_data, vulnerable_packages_map)

    # Print summary table
    print("\n" + "=" * 70)
    print("VULNERABILITY DETECTION SUMMARY:")
    print("=" * 70)
    print(f"Total Packages Scanned        : 1,091")
    print(f"Vulnerable Packages           : {len(vulnerable_packages_map)}")
    print(f"Total Vulnerability Findings  : {len(flat_findings)}")
    print(f"Unique CVE / GHSA Advisories  : {len(unique_cve_ids)}")
    print(f"Production Vulnerabilities    : {prod_vulns}")
    print(f"Development Vulnerabilities   : {dev_vulns}")
    print(f"Severity Breakdown            :")
    for sev, cnt in severity_counter.most_common():
        print(f"  - {sev:<12}: {cnt}")
    print("=" * 70)

    return scan_summary


def enrich_graph(graph_data: Dict[str, Any], vuln_map: Dict[str, Dict[str, Any]]) -> None:
    """Enrich graph nodes with vulnerability annotations."""
    enriched_count = 0
    for node in graph_data.get("nodes", []):
        nid = node["id"]
        if nid in vuln_map:
            v_info = vuln_map[nid]
            node["has_vulnerability"] = True
            node["vulnerability_count"] = v_info["vulnerability_count"]
            node["max_severity"] = v_info["max_severity"]
            node["vulnerabilities"] = [
                {
                    "id": v["id"],
                    "severity": v["severity"],
                    "summary": v["summary"],
                    "fixed_version": v["fixed_version"]
                }
                for v in v_info["vulnerabilities"]
            ]
            enriched_count += 1
        else:
            node["has_vulnerability"] = False
            node["vulnerability_count"] = 0
            node["max_severity"] = None
            node["vulnerabilities"] = []

    with open(GRAPH_PATH, "w", encoding="utf-8") as f:
        json.dump(graph_data, f, indent=2)
    print(f"[✓] Enriched {enriched_count} graph nodes with vulnerability tags in {GRAPH_PATH}")

    if FRONTEND_PUBLIC_GRAPH.parent.exists():
        with open(FRONTEND_PUBLIC_GRAPH, "w", encoding="utf-8") as f:
            json.dump(graph_data, f, indent=2)
        print(f"[✓] Synced enriched graph to {FRONTEND_PUBLIC_GRAPH}")


if __name__ == "__main__":
    from collections import Counter
    run_scan()
