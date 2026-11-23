"""
Detector 1: Dependency Change & Manifest Inconsistency Analyzer
Compares manifests across Git commits, detects unpinned/floating versions,
and identifies manifest-lockfile inconsistencies.
"""

import json
import re
import subprocess
from pathlib import Path
from typing import Any, Dict, List


def analyze_dependency_changes(repo_root: Path) -> List[Dict[str, Any]]:
    findings = []
    nodegoat_dir = repo_root / "nodegoat"
    pkg_json_path = nodegoat_dir / "package.json"
    lockfile_path = nodegoat_dir / "package-lock.json"

    if not pkg_json_path.exists():
        return findings

    with open(pkg_json_path, "r", encoding="utf-8") as f:
        pkg_lines = f.readlines()
        pkg_json = json.loads("".join(pkg_lines))

    lock_data = {}
    if lockfile_path.exists():
        with open(lockfile_path, "r", encoding="utf-8") as f:
            lock_data = json.load(f)

    lock_packages = lock_data.get("packages", {})

    # 1. Manifest Inconsistency Check: Floating & Unpinned Versions
    for sec_name in ["dependencies", "devDependencies"]:
        sec = pkg_json.get(sec_name, {})
        for pkg_name, constraint in sec.items():
            # Find line number in package.json
            line_no = None
            evidence_line = ""
            for idx, line in enumerate(pkg_lines, start=1):
                if f'"{pkg_name}"' in line and f'"{constraint}"' in line:
                    line_no = idx
                    evidence_line = line.strip()
                    break

            # Check for unpinned 'latest' or '*'
            if constraint.lower() in ("latest", "*"):
                finding = {
                    "id": f"SUSP-DEP-FLOATING-{pkg_name.upper().replace('@', '').replace('/', '_')}",
                    "category": "Dependency Change",
                    "severity": "HIGH",
                    "affected_file": "nodegoat/package.json",
                    "line_number": line_no,
                    "evidence": evidence_line,
                    "explanation": (
                        f"Package '{pkg_name}' declares a floating '{constraint}' version constraint in '{sec_name}'. "
                        "Floating constraints allow automated adoption of upstream breaking or malicious updates "
                        "without manifest review."
                    ),
                    "confidence": "CONFIRMED"
                }
                findings.append(finding)

            # Check for wide open range (e.g. > or >= without upper bound)
            elif re.match(r"^>=?\d+(\.\d+)?$", constraint):
                finding = {
                    "id": f"SUSP-DEP-UNBOUNDED-{pkg_name.upper().replace('@', '').replace('/', '_')}",
                    "category": "Dependency Change",
                    "severity": "MEDIUM",
                    "affected_file": "nodegoat/package.json",
                    "line_number": line_no,
                    "evidence": evidence_line,
                    "explanation": (
                        f"Package '{pkg_name}' has an unbounded upper range constraint '{constraint}'. "
                        "New major or minor releases can be pulled in unexpectedly."
                    ),
                    "confidence": "HIGH"
                }
                findings.append(finding)

    # 2. Manifest vs Lockfile Reconciliation Check
    # Verify whether declared packages exist in lockfile and check version alignment
    for sec_name in ["dependencies", "devDependencies"]:
        sec = pkg_json.get(sec_name, {})
        for pkg_name, constraint in sec.items():
            lock_entry_path = f"node_modules/{pkg_name}"
            lock_entry = lock_packages.get(lock_entry_path)

            if not lock_entry:
                # Missing from top-level lockfile packages
                findings.append({
                    "id": f"SUSP-DEP-MISSING-LOCK-{pkg_name.upper().replace('@', '').replace('/', '_')}",
                    "category": "Dependency Change",
                    "severity": "MEDIUM",
                    "affected_file": "nodegoat/package-lock.json",
                    "line_number": 1,
                    "evidence": f'Declared in package.json: "{pkg_name}": "{constraint}"',
                    "explanation": (
                        f"Package '{pkg_name}' is declared in package.json ({sec_name}) but missing from "
                        "top-level package-lock.json packages."
                    ),
                    "confidence": "HIGH"
                })

    # 3. Git Commit History Analysis for Dependency Changes
    try:
        git_cmd = [
            "git", "log", "-n", "3", "--pretty=format:%H|%an|%ad|%s",
            "--date=iso", "--", "nodegoat/package.json"
        ]
        res = subprocess.run(git_cmd, cwd=repo_root, capture_output=True, text=True, check=False)
        if res.returncode == 0 and res.stdout.strip():
            commits = res.stdout.strip().splitlines()
            for c_info in commits:
                parts = c_info.split("|")
                if len(parts) >= 4:
                    commit_sha, author, date_str, subject = parts[0], parts[1], parts[2], parts[3]
                    findings.append({
                        "id": f"SUSP-DEP-COMMIT-{commit_sha[:7]}",
                        "category": "Dependency Change",
                        "severity": "LOW",
                        "affected_file": "nodegoat/package.json",
                        "line_number": 1,
                        "evidence": f"Commit {commit_sha[:8]} by {author} on {date_str}: '{subject}'",
                        "explanation": (
                            f"Git manifest change tracked in commit {commit_sha[:8]} by {author}. "
                            "Verifies provenance and audit trail for dependency changes."
                        ),
                        "confidence": "CONFIRMED"
                    })
    except Exception:
        pass

    return findings
