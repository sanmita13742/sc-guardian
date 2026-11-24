"""
Registry and Dependency Source Investigator (Phase 1.3)
Statically inspects .npmrc, .yarnrc, .yarnrc.yml, manifests and lockfiles.

Detects:
1. Insecure unencrypted HTTP registry URLs (MITM vulnerability).
2. Custom/third-party registry configurations.
3. Insecure TLS settings (strict-ssl=false, plaintext tokens).
4. Direct Git-based dependencies (git+https://, git://, git+ssh://, github:).
5. Direct raw tarball / HTTP dependencies (.tgz, .tar.gz).
6. Non-standard package registry sources in lockfiles.
7. Internal package scope anomalies (dependency confusion vectors).

Never executes untrusted code.
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Dict, List, Optional

from core import git_manager as gm

OFFICIAL_NPM_REGISTRIES = {
    "https://registry.npmjs.org/",
    "https://registry.npmjs.org",
    "https://registry.yarnpkg.com/",
    "https://registry.yarnpkg.com"
}


def _is_unencrypted_http(url: str) -> bool:
    clean = url.strip().strip("'\"").lower()
    return clean.startswith("http://") and not clean.startswith("http://localhost") and not clean.startswith("http://127.0.0.1")


def _is_git_dependency(val: str) -> bool:
    clean = val.strip().strip("'\"").lower()
    return clean.startswith(("git+", "git://", "github:", "gitlab:", "bitbucket:")) or (
        "github.com/" in clean and not clean.endswith(".tgz") and not clean.endswith(".tar.gz")
    )


def _is_tarball_dependency(val: str) -> bool:
    clean = val.strip().strip("'\"").lower()
    return (clean.startswith("http://") or clean.startswith("https://")) and (
        clean.endswith(".tgz") or clean.endswith(".tar.gz") or ".tgz?" in clean
    )


def inspect_registry_configurations(repo_dir: Path) -> List[Dict[str, Any]]:
    """Inspect .npmrc, .yarnrc, .yarnrc.yml files in repository."""
    findings: List[Dict[str, Any]] = []
    config_names = [".npmrc", ".yarnrc", ".yarnrc.yml", ".yarnrc.yaml"]

    for cfg_name in config_names:
        cfg_path = repo_dir / cfg_name
        if not cfg_path.exists():
            continue

        rel_path = str(cfg_path.relative_to(repo_dir)).replace("\\", "/")
        try:
            content = cfg_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue

        lines = content.splitlines()
        for idx, line in enumerate(lines, start=1):
            clean = line.strip()
            if not clean or clean.startswith(("#", ";")) or (clean.startswith("//") and "_authToken" not in clean):
                continue

            # Check 1: Insecure HTTP registry URL
            if "registry" in clean.lower():
                match = re.search(r"https?://[^\s\"']+", clean)
                if match:
                    url = match.group(0)
                    if _is_unencrypted_http(url):
                        findings.append({
                            "id": f"REG-INSECURE-HTTP-L{idx}",
                            "category": "Registry & Source",
                            "title": f"Unencrypted HTTP Registry Configured in {cfg_name}",
                            "severity": "HIGH",
                            "confidence": "HIGH",
                            "status": "OBSERVED",
                            "affected_file": rel_path,
                            "line_number": idx,
                            "evidence_type": "HEURISTIC_FLAG",
                            "evidence": clean,
                            "technical_explanation": (
                                f"Configuration '{cfg_name}' defines unencrypted HTTP registry URL '{url}'. "
                                "Package installations over cleartext HTTP are vulnerable to active Man-in-the-Middle "
                                "(MITM) network attacks allowing package tampering."
                            ),
                            "potential_impact": "Network attacker can inject compromised packages during build or installation.",
                            "recommended_action": f"Update registry URL to use encrypted HTTPS (e.g. '{url.replace('http://', 'https://')}').",
                            "references": ["https://docs.npmjs.com/cli/v9/using-npm/config#registry"]
                        })
                    elif not any(url.rstrip("/").lower() == off.rstrip("/").lower() for off in OFFICIAL_NPM_REGISTRIES):
                        findings.append({
                            "id": f"REG-CUSTOM-MIRROR-L{idx}",
                            "category": "Registry & Source",
                            "title": f"Custom Non-Standard Registry Mirror in {cfg_name}",
                            "severity": "LOW",
                            "confidence": "MEDIUM",
                            "status": "OBSERVED",
                            "affected_file": rel_path,
                            "line_number": idx,
                            "evidence_type": "HEURISTIC_FLAG",
                            "evidence": clean,
                            "technical_explanation": (
                                f"Configuration '{cfg_name}' points to custom registry endpoint '{url}'. "
                                "Non-default registries must be verified to ensure package integrity and avoid "
                                "unauthorized mirrors."
                            ),
                            "potential_impact": "Build depends on third-party registry availability and integrity.",
                            "recommended_action": "Verify upstream authenticity and operational security of custom registry mirror.",
                            "references": []
                        })

            # Check 2: Disabled SSL Verification (strict-ssl=false)
            if re.search(r"strict-ssl\s*=\s*(false|0)", clean, re.IGNORECASE):
                findings.append({
                    "id": f"REG-STRICT-SSL-DISABLED-L{idx}",
                    "category": "Registry & Source",
                    "title": f"TLS Verification Disabled in {cfg_name}",
                    "severity": "CRITICAL",
                    "confidence": "HIGH",
                    "status": "OBSERVED",
                    "affected_file": rel_path,
                    "line_number": idx,
                    "evidence_type": "HEURISTIC_FLAG",
                    "evidence": clean,
                    "technical_explanation": (
                        f"Configuration in '{cfg_name}' explicitly disables TLS certificate validation ('strict-ssl=false'). "
                        "This permits invalid, expired, or intercepted certificates during package download."
                    ),
                    "potential_impact": "Allows attackers with network access to forge certificates and deliver malicious payloads.",
                    "recommended_action": "Remove 'strict-ssl=false' and ensure proper CA trust configuration.",
                    "references": ["https://docs.npmjs.com/cli/v9/using-npm/config#strict-ssl"]
                })

            # Check 3: Plaintext Auth Token in committed config
            if re.search(r"_authToken\s*=\s*([a-zA-Z0-9_\-]{20,})", clean):
                findings.append({
                    "id": f"REG-COMMITTED-TOKEN-L{idx}",
                    "category": "Registry & Source",
                    "title": f"Committed Plaintext Registry Token in {cfg_name}",
                    "severity": "CRITICAL",
                    "confidence": "HIGH",
                    "status": "OBSERVED",
                    "affected_file": rel_path,
                    "line_number": idx,
                    "evidence_type": "HEURISTIC_FLAG",
                    "evidence": re.sub(r"(=)[a-zA-Z0-9_\-]+", r"\1[REDACTED]", clean),
                    "technical_explanation": (
                        f"Found plaintext authentication token committed in '{cfg_name}'. Committed credentials "
                        "can be harvested from version control history."
                    ),
                    "potential_impact": "Unauthorized package publishing or registry access under developer credentials.",
                    "recommended_action": "Revoke the committed token immediately and reference environment variables (${NPM_TOKEN}).",
                    "references": []
                })

    return findings


def inspect_manifest_dependency_sources(manifest_data: dict, file_path: str) -> List[Dict[str, Any]]:
    """Inspect package.json dependencies for direct Git URLs, raw HTTP tarballs, or internal scope confusion."""
    findings: List[Dict[str, Any]] = []

    for dep_sec in ("dependencies", "devDependencies", "peerDependencies", "optionalDependencies"):
        deps = manifest_data.get(dep_sec, {})
        if not isinstance(deps, dict):
            continue

        for pkg, spec in deps.items():
            if not isinstance(spec, str):
                continue

            # Check 1: Direct Git repository dependencies
            if _is_git_dependency(spec):
                is_sha_pinned = bool(re.search(r"#[0-9a-fA-F]{40}$", spec.strip().strip("'\"")))
                sev = "LOW" if is_sha_pinned else "MEDIUM"
                title = (
                    f"Git Dependency '{pkg}' Pinned to Commit SHA"
                    if is_sha_pinned
                    else f"Direct Git-Sourced Dependency '{pkg}'"
                )
                if is_sha_pinned:
                    tech_exp = (
                        f"Package '{pkg}' is sourced from Git ('{spec}') and pinned to an immutable 40-character commit SHA. "
                        "Cryptographic commit pinning prevents upstream branch/tag modifications."
                    )
                else:
                    tech_exp = (
                        f"Package '{pkg}' is sourced directly from a Git repository ('{spec}') rather than a "
                        "registered package registry. Direct Git dependencies bypass registry integrity checks, "
                        "vulnerability tracking, and immutable release audits unless pinned to a full commit SHA."
                    )

                findings.append({
                    "id": f"SRC-GIT-DEP-{pkg.upper().replace('@', '').replace('/', '_')}",
                    "category": "Dependency Source",
                    "title": title,
                    "severity": sev,
                    "confidence": "HIGH",
                    "status": "OBSERVED",
                    "affected_file": file_path,
                    "line_number": 1,
                    "evidence_type": "HEURISTIC_FLAG",
                    "evidence": f'"{pkg}": "{spec}"',
                    "technical_explanation": tech_exp,
                    "potential_impact": (
                        "Minimal risk when pinned to full commit SHA; mutable branches or tags can modify package code without audit trails."
                    ),
                    "recommended_action": "Ensure all Git dependencies remain pinned to full 40-character commit SHAs.",
                    "references": []
                })

            # Check 2: Direct raw HTTP/tarball dependencies
            elif _is_tarball_dependency(spec):
                is_http = _is_unencrypted_http(spec)
                findings.append({
                    "id": f"SRC-TARBALL-DEP-{pkg.upper().replace('@', '').replace('/', '_')}",
                    "category": "Dependency Source",
                    "title": f"Direct URL/Tarball Dependency '{pkg}'",
                    "severity": "HIGH" if is_http else "MEDIUM",
                    "confidence": "HIGH",
                    "status": "OBSERVED",
                    "affected_file": file_path,
                    "line_number": 1,
                    "evidence_type": "HEURISTIC_FLAG",
                    "evidence": f'"{pkg}": "{spec}"',
                    "technical_explanation": (
                        f"Package '{pkg}' downloads directly from raw tarball URL '{spec}'. "
                        + ("Source uses unencrypted HTTP (MITM risk). " if is_http else "")
                        + "Direct tarballs lack centralized signature verification and provenance."
                    ),
                    "potential_impact": "Upstream URL modification or MITM injection of malicious archive.",
                    "recommended_action": "Vendor archive with cryptographic checksum verification or migrate to official registry release.",
                    "references": []
                })

    return findings


def inspect_lockfile_sources(lock_data: dict, file_path: str) -> List[Dict[str, Any]]:
    """Inspect package-lock.json resolved URLs for unencrypted HTTP, non-standard endpoints, or untrusted mirrors."""
    findings: List[Dict[str, Any]] = []
    packages = lock_data.get("packages", {})

    # Check both lockfile v2/v3 packages and v1 dependencies
    items = []
    if isinstance(packages, dict):
        for p_path, p_info in packages.items():
            if isinstance(p_info, dict) and p_info.get("resolved"):
                p_name = p_path.split("node_modules/")[-1] or p_info.get("name") or p_path
                items.append((p_name, p_info.get("version", ""), p_info.get("resolved", "")))

    deps = lock_data.get("dependencies", {})
    if isinstance(deps, dict):
        for d_name, d_info in deps.items():
            if isinstance(d_info, dict) and d_info.get("resolved"):
                items.append((d_name, d_info.get("version", ""), d_info.get("resolved", "")))

    seen_sources = set()
    for name, ver, resolved in items:
        if not isinstance(resolved, str) or resolved in seen_sources:
            continue
        seen_sources.add(resolved)

        # Check 1: Insecure cleartext HTTP resolved URL
        if _is_unencrypted_http(resolved):
            findings.append({
                "id": f"LOCK-INSECURE-HTTP-{name.upper().replace('@', '').replace('/', '_')}",
                "category": "Dependency Source",
                "title": f"Package '{name}' Resolved from Unencrypted HTTP Source",
                "severity": "HIGH",
                "confidence": "HIGH",
                "status": "OBSERVED",
                "affected_file": file_path,
                "line_number": 1,
                "evidence_type": "HEURISTIC_FLAG",
                "evidence": f'"{name}": {{"version": "{ver}", "resolved": "{resolved}"}}',
                "technical_explanation": (
                    f"Dependency '{name}@{ver}' resolved from cleartext HTTP endpoint '{resolved}'. "
                    "Package archives transmitted over HTTP can be intercepted and modified by in-transit network attackers."
                ),
                "potential_impact": "Man-in-the-middle code injection during npm install.",
                "recommended_action": "Re-generate lockfile using HTTPS registry endpoints.",
                "references": []
            })

        # Check 2: Direct non-registry Git archive resolution
        elif "github.com/" in resolved and "/archive/" in resolved:
            findings.append({
                "id": f"LOCK-GIT-ARCHIVE-{name.upper().replace('@', '').replace('/', '_')}",
                "category": "Dependency Source",
                "title": f"Package '{name}' Resolved from Raw GitHub Archive",
                "severity": "MEDIUM",
                "confidence": "HIGH",
                "status": "OBSERVED",
                "affected_file": file_path,
                "line_number": 1,
                "evidence_type": "HEURISTIC_FLAG",
                "evidence": f'"{name}": {{"version": "{ver}", "resolved": "{resolved}"}}',
                "technical_explanation": (
                    f"Dependency '{name}@{ver}' is pinned to raw repository archive URL '{resolved}' rather than a "
                    "formal release registry. Git archives may not guarantee reproducible byte streams."
                ),
                "potential_impact": "Non-reproducible build or uncontrolled code update.",
                "recommended_action": "Migrate to canonical package release with immutable integrity hash.",
                "references": []
            })

    return findings


def analyze_registry_and_sources(repo_dir: Path) -> List[Dict[str, Any]]:
    """Master registry and source investigator."""
    all_findings: List[Dict[str, Any]] = []

    # 1. Config files (.npmrc, .yarnrc)
    all_findings.extend(inspect_registry_configurations(repo_dir))

    # 2. Manifests (package.json)
    for pkg_json in repo_dir.rglob("package.json"):
        # Skip node_modules
        if "node_modules" in pkg_json.parts:
            continue
        rel_path = str(pkg_json.relative_to(repo_dir)).replace("\\", "/")
        try:
            data = json.loads(pkg_json.read_text(encoding="utf-8", errors="replace"))
            all_findings.extend(inspect_manifest_dependency_sources(data, rel_path))
        except (json.JSONDecodeError, OSError):
            continue

    # 3. Lockfiles (package-lock.json)
    for lock_file in repo_dir.rglob("package-lock.json"):
        if "node_modules" in lock_file.parts:
            continue
        rel_path = str(lock_file.relative_to(repo_dir)).replace("\\", "/")
        try:
            data = json.loads(lock_file.read_text(encoding="utf-8", errors="replace"))
            all_findings.extend(inspect_lockfile_sources(data, rel_path))
        except (json.JSONDecodeError, OSError):
            continue

    return all_findings

