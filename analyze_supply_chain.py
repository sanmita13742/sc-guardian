#!/usr/bin/env python3
"""
Software Supply Chain Guardian - Master Suspicious Supply Chain Analyzer
Milestone 4: Suspicious Supply Chain Change Detection

Orchestrates all specialized detection engines:
1. Dependency Change & Manifest Inconsistency Analysis
2. Typosquatting & Package Masquerading Detection
3. Lifecycle Script Static Analysis
4. Docker & CI/CD Security Analysis

Outputs standardized suspicious_changes.json artifact.
"""

import json
from pathlib import Path
from typing import Any, Dict, List
from collections import Counter

from detectors.dependency_changes import analyze_dependency_changes
from detectors.typosquatting import analyze_typosquatting
from detectors.lifecycle_scripts import analyze_lifecycle_scripts
from detectors.cicd_docker import analyze_cicd_and_docker

WORKSPACE_ROOT = Path(__file__).resolve().parent
SCANS_DIR = WORKSPACE_ROOT / "artifacts" / "scans"
OUTPUT_SCAN_PATH = SCANS_DIR / "suspicious_changes.json"
ROOT_SCAN_PATH = WORKSPACE_ROOT / "suspicious_changes.json"
FRONTEND_PUBLIC_SCAN = WORKSPACE_ROOT / "frontend" / "public" / "suspicious_changes.json"


def run_analysis() -> Dict[str, Any]:
    print("=" * 80)
    print("SOFTWARE SUPPLY CHAIN GUARDIAN - SUSPICIOUS CHANGE DETECTION (MILESTONE 4)")
    print("=" * 80)

    all_findings: List[Dict[str, Any]] = []

    # 1. Dependency Change Analysis
    print("[*] 1/4 Running Dependency Change & Manifest Integrity Analyzer...")
    dep_findings = analyze_dependency_changes(WORKSPACE_ROOT)
    all_findings.extend(dep_findings)
    print(f"    [+] Found {len(dep_findings)} dependency change / manifest finding(s)")

    # 2. Typosquatting Detection
    print("[*] 2/4 Running Typosquatting & Name Similarity Detector...")
    typo_findings = analyze_typosquatting(WORKSPACE_ROOT)
    all_findings.extend(typo_findings)
    print(f"    [+] Found {len(typo_findings)} typosquatting candidate(s)")

    # 3. Lifecycle Script Analysis
    print("[*] 3/4 Running Lifecycle Script Static Analyzer...")
    script_findings = analyze_lifecycle_scripts(WORKSPACE_ROOT)
    all_findings.extend(script_findings)
    print(f"    [+] Found {len(script_findings)} lifecycle script finding(s)")

    # 4. Docker and CI/CD Analysis
    print("[*] 4/4 Running Docker & CI/CD Security Analyzer...")
    cicd_findings = analyze_cicd_and_docker(WORKSPACE_ROOT)
    all_findings.extend(cicd_findings)
    print(f"    [+] Found {len(cicd_findings)} Docker & CI/CD security finding(s)")

    # Deduplicate findings by finding ID
    unique_findings: List[Dict[str, Any]] = []
    seen_ids = set()
    for f in all_findings:
        fid = f["id"]
        if fid not in seen_ids:
            seen_ids.add(fid)
            unique_findings.append(f)

    # Compute aggregate metrics
    category_counts = Counter(f["category"] for f in unique_findings)
    severity_counts = Counter(f["severity"] for f in unique_findings)
    confidence_counts = Counter(f["confidence"] for f in unique_findings)

    scan_artifact = {
        "analysis_type": "Suspicious Supply Chain Change Detection",
        "timestamp": "2026-11-23T17:30:00+05:30",
        "target": "OWASP NodeGoat",
        "metrics": {
            "total_findings": len(unique_findings),
            "category_counts": dict(category_counts),
            "severity_counts": dict(severity_counts),
            "confidence_counts": dict(confidence_counts)
        },
        "findings": unique_findings
    }

    # Save to artifacts/scans/
    SCANS_DIR.mkdir(parents=True, exist_ok=True)
    with open(OUTPUT_SCAN_PATH, "w", encoding="utf-8") as f:
        json.dump(scan_artifact, f, indent=2)
    print(f"\n[✓] Saved suspicious changes report to {OUTPUT_SCAN_PATH}")

    # Copy to root and frontend public
    with open(ROOT_SCAN_PATH, "w", encoding="utf-8") as f:
        json.dump(scan_artifact, f, indent=2)

    if FRONTEND_PUBLIC_SCAN.parent.exists():
        with open(FRONTEND_PUBLIC_SCAN, "w", encoding="utf-8") as f:
            json.dump(scan_artifact, f, indent=2)
        print(f"[✓] Synced report to {FRONTEND_PUBLIC_SCAN}")

    print("\n" + "=" * 80)
    print("DETECTION SUMMARY:")
    print("=" * 80)
    print(f"Total Suspicious Findings     : {len(unique_findings)}")
    print("Category Breakdown            :")
    for cat, cnt in category_counts.most_common():
        print(f"  - {cat:<28}: {cnt}")
    print("Severity Breakdown            :")
    for sev, cnt in severity_counts.most_common():
        print(f"  - {sev:<28}: {cnt}")
    print("Confidence Breakdown          :")
    for conf, cnt in confidence_counts.most_common():
        print(f"  - {conf:<28}: {cnt}")
    print("=" * 80)

    return scan_artifact


if __name__ == "__main__":
    run_analysis()
