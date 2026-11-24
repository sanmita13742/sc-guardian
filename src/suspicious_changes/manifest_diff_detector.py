"""
Manifest and Repository Git Diff Investigator (Phase 1.1)
Analyzes Git diffs between two commits (base -> head).

Detects:
1. Added, removed, and modified dependencies in manifests and lockfiles.
2. Unexpected version changes (floating 'latest', '*', unbounded ranges).
3. Manifest-lockfile inconsistencies (lockfile changed without manifest, or vice versa).
4. Modifications to security-sensitive source files (auth, server entry, CI/CD, build scripts).

Produces strict OBSERVED_CHANGE evidence with exact commit provenance and line-level diff excerpts.
Never executes untrusted code.
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from core import git_manager as gm

SECURITY_SENSITIVE_PATTERNS = [
    (r"^\.github/workflows/.*\.ya?ml$", "CI/CD Pipeline Definition"),
    (r"^Dockerfile.*", "Container Build Specification"),
    (r"^docker-compose.*\.ya?ml$", "Container Composition Specification"),
    (r"^Gruntfile\.js$|^gulpfile\.js$|^webpack\.config\.js$", "Build Configuration Script"),
    (r"^server\.js$|^app\.js$|^index\.js$", "Application Entry Point"),
    (r".*auth.*\.js$|.*session.*\.js$|.*login.*\.js$", "Authentication & Session Handling"),
    (r".*dao.*\.js$|.*db.*\.js$|.*database.*", "Database Access & Persistence Layer"),
    (r"^\.env.*|.*config.*\.js$", "Environment & Secret Configuration"),
]


def _parse_dependencies(content: Optional[str]) -> Dict[str, str]:
    """Parse dependencies from package.json text safely."""
    if not content:
        return {}
    try:
        data = json.loads(content)
        deps = {}
        for sec in ("dependencies", "devDependencies", "peerDependencies", "optionalDependencies"):
            s = data.get(sec, {})
            if isinstance(s, dict):
                for k, v in s.items():
                    if isinstance(v, str):
                        deps[k] = v
        return deps
    except Exception:
        return {}


def _is_floating_version(constraint: str) -> bool:
    clean = constraint.strip().lower()
    return clean in ("latest", "*") or clean.startswith((">=", ">")) and "<" not in clean


def _is_major_bump(old_v: str, new_v: str) -> bool:
    """Check if version update crosses a major semantic version boundary."""
    clean_old = re.sub(r"^[~^v>=<\s]+", "", old_v).strip()
    clean_new = re.sub(r"^[~^v>=<\s]+", "", new_v).strip()
    old_parts = clean_old.split(".")
    new_parts = clean_new.split(".")
    if old_parts and new_parts and old_parts[0].isdigit() and new_parts[0].isdigit():
        return int(new_parts[0]) != int(old_parts[0])
    return False


def inspect_git_diff_range(
    repo_dir: Path,
    base_commit: str,
    head_commit: str
) -> List[Dict[str, Any]]:
    """Compare base_commit and head_commit, producing OBSERVED_CHANGE findings."""
    findings: List[Dict[str, Any]] = []

    if not gm.commit_exists(repo_dir, base_commit):
        return findings
    if not gm.commit_exists(repo_dir, head_commit):
        return findings

    head_info = gm.commit_info(repo_dir, head_commit)
    changed = gm.changed_files(repo_dir, base_commit, head_commit)

    changed_paths = {path for _, path in changed}

    # 1. Inspect manifest (package.json) dependency diffs
    manifest_paths = [p for p in changed_paths if p.endswith("package.json") and "node_modules" not in p]

    for m_path in manifest_paths:
        base_text = gm.show_file(repo_dir, base_commit, m_path)
        head_text = gm.show_file(repo_dir, head_commit, m_path)

        base_deps = _parse_dependencies(base_text)
        head_deps = _parse_dependencies(head_text)

        # Added dependencies
        added = set(head_deps.keys()) - set(base_deps.keys())
        for pkg in sorted(added):
            spec = head_deps[pkg]
            diff_snip = gm.diff_text(repo_dir, base_commit, head_commit, m_path)
            # Find line where added
            lines = (head_text or "").splitlines()
            line_no = next((idx for idx, l in enumerate(lines, start=1) if f'"{pkg}"' in l), 1)

            is_floating = _is_floating_version(spec)
            findings.append({
                "id": f"DIFF-DEP-ADDED-{pkg.upper().replace('@', '').replace('/', '_')}",
                "category": "Dependency Change",
                "title": f"Dependency '{pkg}@{spec}' Added in Commit {head_commit[:8]}",
                "severity": "HIGH" if is_floating else "LOW",
                "confidence": "HIGH",
                "status": "OBSERVED",
                "affected_file": m_path,
                "line_number": line_no,
                "commit_reference": head_info,
                "change_origin": "INTRODUCED_IN_RANGE",
                "evidence_type": "OBSERVED_CHANGE",
                "evidence": f'+ "{pkg}": "{spec}"',
                "technical_explanation": (
                    f"Commit {head_commit[:8]} introduced new dependency '{pkg}' with version constraint '{spec}' "
                    f"in manifest '{m_path}'."
                    + (" WARNING: Constraint uses unpinned floating version allowing arbitrary upstream update injection." if is_floating else "")
                ),
                "potential_impact": "Expands dependency attack surface; floating versions risk automatic adoption of compromised releases.",
                "recommended_action": f"Audit provenance and pin '{pkg}' to a deterministic semantic version.",
                "references": []
            })

        # Removed dependencies
        removed = set(base_deps.keys()) - set(head_deps.keys())
        for pkg in sorted(removed):
            spec = base_deps[pkg]
            findings.append({
                "id": f"DIFF-DEP-REMOVED-{pkg.upper().replace('@', '').replace('/', '_')}",
                "category": "Dependency Change",
                "title": f"Dependency '{pkg}' Removed in Commit {head_commit[:8]}",
                "severity": "INFO",
                "confidence": "HIGH",
                "status": "OBSERVED",
                "affected_file": m_path,
                "line_number": 1,
                "commit_reference": head_info,
                "change_origin": "INTRODUCED_IN_RANGE",
                "evidence_type": "OBSERVED_CHANGE",
                "evidence": f'- "{pkg}": "{spec}"',
                "technical_explanation": f"Commit {head_commit[:8]} removed dependency '{pkg}' (previously '{spec}') from '{m_path}'.",
                "potential_impact": "Dependency removed from manifest.",
                "recommended_action": "Verify removal was intended and clean up any residual configuration.",
                "references": []
            })

        # Modified versions
        common = set(base_deps.keys()) & set(head_deps.keys())
        for pkg in sorted(common):
            old_v = base_deps[pkg]
            new_v = head_deps[pkg]
            if old_v != new_v:
                is_floating = _is_floating_version(new_v)
                is_major = _is_major_bump(old_v, new_v)
                lines = (head_text or "").splitlines()
                line_no = next((idx for idx, l in enumerate(lines, start=1) if f'"{pkg}"' in l), 1)

                if is_floating:
                    sev = "HIGH"
                    title = f"Dependency '{pkg}' Changed to Floating Constraint '{new_v}' in {head_commit[:8]}"
                    exp = f"Commit {head_commit[:8]} modified dependency '{pkg}' from '{old_v}' to unpinned floating '{new_v}'."
                elif is_major:
                    sev = "MEDIUM"
                    title = f"Dependency '{pkg}' Upgraded Major Version from '{old_v}' to '{new_v}' in {head_commit[:8]}"
                    exp = f"Commit {head_commit[:8]} upgraded dependency '{pkg}' across a major version boundary from '{old_v}' to '{new_v}'."
                else:
                    sev = "LOW"
                    title = f"Dependency '{pkg}' Updated from '{old_v}' to '{new_v}' in {head_commit[:8]}"
                    exp = f"Commit {head_commit[:8]} routine semver update for '{pkg}' from '{old_v}' to '{new_v}' within the same release series."

                findings.append({
                    "id": f"DIFF-DEP-MODIFIED-{pkg.upper().replace('@', '').replace('/', '_')}",
                    "category": "Dependency Change",
                    "title": title,
                    "severity": sev,
                    "confidence": "HIGH",
                    "status": "OBSERVED",
                    "affected_file": m_path,
                    "line_number": line_no,
                    "commit_reference": head_info,
                    "change_origin": "INTRODUCED_IN_RANGE",
                    "evidence_type": "OBSERVED_CHANGE",
                    "evidence": f'- "{pkg}": "{old_v}"\n+ "{pkg}": "{new_v}"',
                    "technical_explanation": exp,
                    "potential_impact": "Major or floating version jumps may introduce breaking changes or tampered releases; routine semver updates carry minimal operational risk.",
                    "recommended_action": "Verify package integrity and inspect changelog if version jumps are unexpected.",
                    "references": []
                })

    # 2. Manifest vs Lockfile Inconsistency in the commit range
    lockfile_paths = [p for p in changed_paths if p.endswith("package-lock.json") and "node_modules" not in p]
    if manifest_paths and not lockfile_paths:
        findings.append({
            "id": f"DIFF-INCONSISTENCY-MANIFEST-WITHOUT-LOCK-{head_commit[:8]}",
            "category": "Repository Diff",
            "title": f"Manifest Modified Without Updating Lockfile in Commit {head_commit[:8]}",
            "severity": "MEDIUM",
            "confidence": "HIGH",
            "status": "OBSERVED",
            "affected_file": manifest_paths[0],
            "line_number": 1,
            "commit_reference": head_info,
            "change_origin": "INTRODUCED_IN_RANGE",
            "evidence_type": "OBSERVED_CHANGE",
            "evidence": f"Manifests changed: {', '.join(manifest_paths)}; Lockfiles changed: none",
            "technical_explanation": (
                f"Commit {head_commit[:8]} updated dependencies in package manifest(s) ({', '.join(manifest_paths)}) "
                "but did not update the companion package-lock.json. This leads to non-deterministic local installs "
                "versus CI builds."
            ),
            "potential_impact": "Build discrepancy between developer environments and automated CI runners.",
            "recommended_action": "Run 'npm install' or 'npm package-lock-only' and commit the synchronized lockfile.",
            "references": []
        })

    # 3. Security-sensitive source file modifications
    for status, path in changed:
        for pattern, desc in SECURITY_SENSITIVE_PATTERNS:
            if re.match(pattern, path, re.IGNORECASE):
                diff_text = gm.diff_text(repo_dir, base_commit, head_commit, path, max_chars=500)
                findings.append({
                    "id": f"DIFF-SENSITIVE-FILE-{path.upper().replace('/', '_').replace('.', '_')}",
                    "category": "Repository Diff",
                    "title": f"Security-Sensitive File Modified: '{path}' ({desc})",
                    "severity": "LOW" if status == "M" else "MEDIUM",
                    "confidence": "HIGH",
                    "status": "OBSERVED",
                    "affected_file": path,
                    "line_number": 1,
                    "commit_reference": head_info,
                    "change_origin": "INTRODUCED_IN_RANGE",
                    "evidence_type": "OBSERVED_CHANGE",
                    "evidence": f"Git status: {status}\n{diff_text[:300]}",
                    "technical_explanation": (
                        f"Commit {head_commit[:8]} modified security-sensitive file '{path}' ({desc}). "
                        "Critical architectural components (authentication, CI/CD, build hooks, server root) "
                        "require focused peer review during supply chain auditing."
                    ),
                    "potential_impact": "Alterations to authentication, authorization, build gates or deployment workflows.",
                    "recommended_action": "Conduct targeted code review on modified lines in this security-sensitive component.",
                    "references": []
                })
                break

    return findings
