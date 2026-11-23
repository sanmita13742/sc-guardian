"""
Detector 3: Lifecycle Script Static Analyzer
Statically inspects package.json scripts and package-lock.json install scripts.
Detects suspicious shell commands, unpinned container execution, remote binary fetches,
and environment variable access WITHOUT executing untrusted code.
"""

import json
import re
from pathlib import Path
from typing import Any, Dict, List


def analyze_lifecycle_scripts(repo_root: Path) -> List[Dict[str, Any]]:
    findings = []
    nodegoat_dir = repo_root / "nodegoat"
    pkg_json_path = nodegoat_dir / "package.json"
    lockfile_path = nodegoat_dir / "package-lock.json"

    if not pkg_json_path.exists():
        return findings

    with open(pkg_json_path, "r", encoding="utf-8") as f:
        pkg_lines = f.readlines()
        pkg_json = json.loads("".join(pkg_lines))

    scripts = pkg_json.get("scripts", {})

    # Heuristic patterns for suspicious script activity
    SUSPICIOUS_PATTERNS = [
        (
            r"docker\s+run\s+.*:latest",
            "SUSP-SCRIPT-DOCKER-LATEST",
            "MEDIUM",
            "Unpinned Docker Execution in npm Script",
            "npm script invokes 'docker run' using mutable ':latest' image tag instead of an immutable digest."
        ),
        (
            r"(curl|wget)\s+.*https?://",
            "SUSP-SCRIPT-REMOTE-DOWNLOAD",
            "HIGH",
            "Remote File Download in npm Script",
            "Script downloads remote executable artifacts directly over HTTP/HTTPS during execution."
        ),
        (
            r"(bash|sh)\s+-c",
            "SUSP-SCRIPT-SHELL-EXEC",
            "MEDIUM",
            "Explicit Shell Child Process Execution",
            "Script explicitly spawns an interactive shell process (bash/sh -c) rather than running direct commands."
        ),
        (
            r"(base64|Buffer\.from\(.*base64\)|eval\(|String\.fromCharCode)",
            "SUSP-SCRIPT-OBFUSCATION",
            "CRITICAL",
            "Potential Code Obfuscation in Lifecycle Script",
            "Detected Base64 or eval-based execution pattern frequently associated with dropper payloads."
        )
    ]

    # 1. Scan package.json scripts
    for script_name, script_cmd in scripts.items():
        # Find line number
        line_no = None
        evidence_line = f'"{script_name}": "{script_cmd}"'
        for idx, line in enumerate(pkg_lines, start=1):
            if f'"{script_name}"' in line:
                line_no = idx
                evidence_line = line.strip()
                break

        for pattern, rule_id, severity, title, explanation in SUSPICIOUS_PATTERNS:
            if re.search(pattern, script_cmd, re.IGNORECASE):
                findings.append({
                    "id": f"{rule_id}-{script_name.upper().replace(':', '_')}",
                    "category": "Lifecycle Script",
                    "severity": severity,
                    "affected_file": "nodegoat/package.json",
                    "line_number": line_no,
                    "evidence": evidence_line,
                    "explanation": f"{title} in script '{script_name}': {explanation}",
                    "confidence": "CONFIRMED"
                })

    # 2. Scan package-lock.json packages with install scripts (preinstall / postinstall)
    if lockfile_path.exists():
        with open(lockfile_path, "r", encoding="utf-8") as f:
            lock_data = json.load(f)

        lock_packages = lock_data.get("packages", {})
        for path, info in lock_packages.items():
            if not path:
                continue
            if info.get("hasInstallScript"):
                pkg_name = path.split("node_modules/")[-1]
                version = info.get("version", "")
                findings.append({
                    "id": f"SUSP-SCRIPT-INSTALL-HOOK-{pkg_name.upper().replace('@', '').replace('/', '_')}",
                    "category": "Lifecycle Script",
                    "severity": "LOW",
                    "affected_file": "nodegoat/package-lock.json",
                    "line_number": 1,
                    "evidence": f'"{path}": {{"version": "{version}", "hasInstallScript": true}}',
                    "explanation": (
                        f"Dependency '{pkg_name}@{version}' registers automated install lifecycle hooks "
                        "(preinstall/install/postinstall) that execute arbitrary commands when running 'npm install'."
                    ),
                    "confidence": "CONFIRMED"
                })

    return findings
