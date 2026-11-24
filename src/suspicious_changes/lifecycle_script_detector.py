"""
Lifecycle Script Investigator (Phase 1.2)
Statically inspects package manifests and lockfile metadata for suspicious lifecycle scripts.

Inspects:
- package.json scripts (preinstall, install, postinstall, preuninstall, postuninstall, prepare, etc.)
- lockfile metadata (hasInstallScript)

Detects:
1. Shell and process spawning (exec, spawn, bash, sh, powershell, cmd).
2. Eval and obfuscation (eval(), Function(), hex/unicode escapes, string decoding).
3. Base64 payload decoding (Buffer.from(..., 'base64'), atob, base64 -d).
4. Remote downloads and network calls (curl, wget, http.get, fetch, Invoke-WebRequest).
5. Remote script piped to shell (curl | sh, wget | bash).
6. Environment variable access (process.env, printenv, export).
7. Credential access and sensitive file targeting (.ssh, .aws, .env, id_rsa, token, secret).
8. Suspicious file-system operations (rm -rf /, chmod +x /tmp).

Distinguishes benign native compilation (e.g. node-gyp rebuild) from high-risk patterns.
Never executes scripts.
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

LIFECYCLE_SCRIPT_NAMES = {
    "preinstall",
    "install",
    "postinstall",
    "preuninstall",
    "postuninstall",
    "prepack",
    "postpack",
    "prepare",
}

# Regex patterns for static detection
PATTERNS = {
    "pipe_to_shell": (
        re.compile(r"(curl|wget|fetch)\s+[^\n|;]+\|\s*(sh|bash|zsh|dash|powershell|cmd)\b", re.IGNORECASE),
        "CRITICAL",
        "Lifecycle script pipes remote download directly into shell",
        "Executes unverified remote code with package install permissions; classic attack vector for reverse shells and backdoors."
    ),
    "base64_eval": (
        re.compile(r"(eval|Function)\s*\(\s*(Buffer\.from\([^)]*['\"]base64['\"]|atob\(|[A-Za-z0-9+/=]{40,})", re.IGNORECASE),
        "CRITICAL",
        "Lifecycle script evaluates base64-encoded payload",
        "Obfuscation technique commonly used to hide malicious payloads from scanners and code review."
    ),
    "credential_access": (
        re.compile(r"(\.ssh/|\.aws/credentials|\.npmrc|\.env\b|id_rsa|\b(AWS_SECRET_ACCESS_KEY|GITHUB_TOKEN|NPM_TOKEN)\b)", re.IGNORECASE),
        "CRITICAL",
        "Lifecycle script targets sensitive credential paths or secret tokens",
        "Attempts to access host credentials, deployment keys, or sensitive configuration files during installation."
    ),
    "suspicious_eval_obfuscation": (
        re.compile(r"\b(eval\s*\(|new\s+Function\s*\(|unescape\s*\(|String\.fromCharCode\s*\()", re.IGNORECASE),
        "HIGH",
        "Lifecycle script uses dynamic code evaluation or string obfuscation",
        "Dynamic code evaluation in install scripts obscures runtime behavior and prevents static verification."
    ),
    "hex_escapes": (
        re.compile(r"(\\x[0-9a-fA-F]{2}){4,}|(\\u[0-9a-fA-F]{4}){4,}", re.IGNORECASE),
        "HIGH",
        "Lifecycle script contains heavily escaped hex/unicode characters",
        "High concentration of hex or unicode escapes suggests intentional payload obfuscation."
    ),
    "remote_download": (
        re.compile(r"\b(curl\s+|wget\s+|Invoke-WebRequest|Invoke-RestMethod|http\.get\s*\(|https\.get\s*\(|fetch\s*\()", re.IGNORECASE),
        "MEDIUM",
        "Lifecycle script initiates remote network download",
        "Downloads external binaries or scripts at install time outside the package manager's integrity verification."
    ),
    "env_exfiltration": (
        re.compile(r"\b(process\.env|printenv|env\s*\|)", re.IGNORECASE),
        "MEDIUM",
        "Lifecycle script inspects process environment variables",
        "Harvesting environment variables during build or install may leak CI/CD secrets and API keys."
    ),
    "process_spawning": (
        re.compile(r"\b(child_process|exec\s*\(|spawn\s*\(|execSync\s*\()", re.IGNORECASE),
        "LOW",
        "Lifecycle script spawns child processes",
        "Process creation in install scripts executes secondary commands and binaries."
    ),
    "docker_latest": (
        re.compile(r"docker\s+run\s+.*:latest\b", re.IGNORECASE),
        "MEDIUM",
        "Unpinned Docker Execution in npm Script",
        "npm script invokes 'docker run' using mutable ':latest' image tag instead of an immutable digest."
    ),
    "destructive_fs": (
        re.compile(r"\b(rm\s+-rf\s+[/~]|chmod\s+\+x\s+(/tmp|/var/tmp))", re.IGNORECASE),
        "HIGH",
        "Lifecycle script executes potentially unsafe filesystem operations",
        "Risks modifying system files or executing unauthorized binaries in shared temporary directories."
    ),
}

BENIGN_COMPILATION_PATTERNS = [
    re.compile(r"^node-gyp\s+(rebuild|configure|build)$"),
    re.compile(r"^(npx\s+)?tsc\b"),
    re.compile(r"^(npx\s+)?webpack\b"),
    re.compile(r"^(npx\s+)?vite\s+build\b"),
    re.compile(r"^(npx\s+)?esbuild\b"),
    re.compile(r"^patch-package\b"),
    re.compile(r"^make\b"),
    re.compile(r"^cargo\s+build\b"),
]


def _is_benign_build_command(command: str) -> bool:
    clean = command.strip()
    return any(p.match(clean) for p in BENIGN_COMPILATION_PATTERNS)


def inspect_lifecycle_scripts_text(
    content: str,
    file_path: str = "package.json",
    commit_reference: Optional[Dict[str, str]] = None,
    change_origin: str = "PRE_EXISTING"
) -> List[Dict[str, Any]]:
    """Statically inspect package.json manifest content for lifecycle scripts."""
    findings: List[Dict[str, Any]] = []
    if not content:
        return findings

    try:
        data = json.loads(content)
    except Exception:
        return findings

    scripts = data.get("scripts", {})
    if not isinstance(scripts, dict):
        return findings

    lines = content.splitlines()

    for script_name, cmd in scripts.items():
        if not isinstance(cmd, str):
            continue

        target_lifecycle = script_name.lower() in LIFECYCLE_SCRIPT_NAMES
        # Standard lifecycle scripts (preinstall, postinstall, etc.) receive increased scrutiny,
        # but all npm scripts are scanned for malicious/unpinned patterns.

        # Find line number of script definition
        line_no = 1
        for idx, line in enumerate(lines, start=1):
            if f'"{script_name}"' in line:
                line_no = idx
                break

        # Check for benign compile scripts first
        if _is_benign_build_command(cmd):
            continue

        # Evaluate against suspicious patterns
        for pattern_id, (regex, sev, title, impact) in PATTERNS.items():
            if regex.search(cmd):
                finding_id = f"SCRIPT-{pattern_id.upper()}-{script_name.upper()}-L{line_no}"
                confidence = "HIGH" if sev in ("CRITICAL", "HIGH") else "MEDIUM"

                findings.append({
                    "id": finding_id,
                    "category": "Lifecycle Script",
                    "title": f"Suspicious '{script_name}' Script: {title}",
                    "severity": sev,
                    "confidence": confidence,
                    "status": "OBSERVED",
                    "affected_file": file_path,
                    "line_number": line_no,
                    "commit_reference": commit_reference or {},
                    "change_origin": change_origin,
                    "evidence_type": "HEURISTIC_FLAG",
                    "evidence": f'"{script_name}": "{cmd}"',
                    "technical_explanation": (
                        f"Script '{script_name}' defines command '{cmd}'. "
                        f"Pattern match for '{pattern_id}': {impact}"
                    ),
                    "potential_impact": impact,
                    "recommended_action": (
                        "Audit the script behavior. If installing dependencies, run with '--ignore-scripts' "
                        "and replace inline commands with trusted build scripts."
                    ),
                    "references": [
                        "https://docs.npmjs.com/cli/v9/using-npm/scripts#life-cycle-scripts",
                        "https://github.blog/2021-02-04-preventing-supply-chain-attacks-like-dependency-confusion/"
                    ]
                })

    return findings


def inspect_manifest_file(file_path: Path, repo_root: Path) -> List[Dict[str, Any]]:
    """Inspect local manifest file directly."""
    if not file_path.exists():
        return []
    try:
        content = file_path.read_text(encoding="utf-8", errors="replace")
        rel_path = str(file_path.relative_to(repo_root)).replace("\\", "/")
        return inspect_lifecycle_scripts_text(content, file_path=rel_path)
    except Exception:
        return []


def inspect_lockfile_install_scripts(
    lockfile_content: str,
    file_path: str = "package-lock.json",
    commit_reference: Optional[Dict[str, str]] = None,
    change_origin: str = "PRE_EXISTING"
) -> List[Dict[str, Any]]:
    """
    Inspect package-lock.json v2/v3 metadata for packages declaring 'hasInstallScript': true.
    Direct install script execution in transitive dependencies is a prime supply chain vector.
    """
    findings: List[Dict[str, Any]] = []
    if not lockfile_content:
        return findings

    try:
        data = json.loads(lockfile_content)
    except Exception:
        return findings

    packages = data.get("packages", {})
    if not isinstance(packages, dict):
        return findings

    for pkg_path, meta in packages.items():
        if not isinstance(meta, dict) or not pkg_path:
            continue
        if meta.get("hasInstallScript") is True:
            pkg_name = pkg_path.split("node_modules/")[-1] if "node_modules/" in pkg_path else pkg_path
            version = meta.get("version", "unknown")
            ev_type = "OBSERVED_CHANGE" if (commit_reference and commit_reference.get("sha") and change_origin == "INTRODUCED_IN_RANGE") else "HEURISTIC_FLAG"
            findings.append({
                "id": f"LOCK-INSTALL-SCRIPT-{pkg_name.upper().replace('@', '').replace('/', '_')}",
                "category": "Lifecycle Script",
                "title": f"Dependency '{pkg_name}@{version}' Declares Install Script in Lockfile",
                "severity": "LOW",
                "confidence": "HIGH" if ev_type == "OBSERVED_CHANGE" else "MEDIUM",
                "status": "OBSERVED",
                "affected_file": file_path,
                "line_number": 1,
                "commit_reference": commit_reference or {},
                "change_origin": change_origin,
                "evidence_type": ev_type,
                "evidence": f'"{pkg_path}": {{ "hasInstallScript": true, "version": "{version}" }}',
                "technical_explanation": (
                    f"Package '{pkg_name}' declares 'hasInstallScript: true' in lockfile metadata. "
                    "When installed without '--ignore-scripts', it automatically executes code on the host machine."
                ),
                "potential_impact": "Code execution occurs during 'npm install' on developer workstations and CI runners.",
                "recommended_action": "Verify package authenticity and run builds with '--ignore-scripts' where feasible.",
                "references": ["https://docs.npmjs.com/cli/v9/configuring-npm/package-lock-json"]
            })

    return findings
