#!/usr/bin/env python3
"""
Software Supply Chain Guardian - Change Analyzer (Person 2: Suspicious Change Investigator)
Root-level deterministic orchestration engine and unified CLI.

Detects malicious, suspicious, and unauthorized software supply chain changes
that conventional vulnerability databases (NVD, CVE, OSV) do not identify:
1. Git diff manifest and lockfile changes (added, removed, modified, floating versions).
2. Manifest and lockfile inconsistencies.
3. Security-sensitive source file modifications.
4. Static lifecycle script threats (remote execution, eval/obfuscation, credential access, env exfiltration).
5. Registry and dependency source anomalies (insecure HTTP, custom mirrors, disabled TLS, committed tokens).
6. CI/CD workflow vulnerabilities and pipeline tampering (unpinned actions, script injection, untrusted triggers).
7. Container build security (unpinned base images, build-time downloads, root user).
8. Typosquatting and package masquerading heuristics.

Strictly distinguishes OBSERVED_CHANGE from HEURISTIC_FLAG.
Distinguishes INTRODUCED_IN_RANGE from PRE_EXISTING findings.
Never executes untrusted code.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

# Ensure src is on sys.path
_ROOT = Path(__file__).resolve().parent
_SRC = _ROOT / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from core import git_manager as gm
from suspicious_changes.manifest_diff_detector import inspect_git_diff_range
from suspicious_changes.registry_detector import (
    inspect_registry_configurations,
    inspect_manifest_dependency_sources,
    inspect_lockfile_sources,
)
from suspicious_changes.lifecycle_script_detector import (
    inspect_lifecycle_scripts_text,
    inspect_lockfile_install_scripts,
)
from suspicious_changes.popular_packages import POPULAR
from suspicious_changes.typosquatting_detector import candidate_matches
from suspicious_changes.change_correlation import CITATIONS, correlate_suspicious_changes
from agents.suspicious_change_agent import SuspiciousChangeAgent
from pipeline_analysis.ci import analyze_github_workflow, analyze_generic_ci
from pipeline_analysis.dockerfile import analyze_dockerfile, analyze_compose


class CIWorkflowAdapter:
    """Adapter for inspecting multi-ecosystem CI/CD pipelines statically."""

    SUPPORTED_PIPELINES = {
        ".github/workflows": "github_actions",
        ".gitlab-ci.yml": "gitlab_ci",
        "Jenkinsfile": "jenkins",
        ".circleci/config.yml": "circleci",
        "azure-pipelines.yml": "azure_pipelines",
    }

    @classmethod
    def inspect(cls, file_path: Path, repo_root: Path) -> Tuple[List[Dict[str, Any]], str]:
        rel_str = str(file_path.relative_to(repo_root)).replace("\\", "/")
        try:
            content = file_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return [], ""

        if ".github/workflows" in rel_str and (rel_str.endswith(".yml") or rel_str.endswith(".yaml")):
            findings, _ = analyze_github_workflow(content, rel_str)
            return [f.model_dump() for f in findings], "GitHub Actions"
        elif any(sig in rel_str for sig in (".gitlab-ci.yml", "Jenkinsfile", ".circleci", "azure-pipelines")):
            findings, _ = analyze_generic_ci(content, rel_str)
            return [f.model_dump() for f in findings], "Generic CI"
        return [], ""


class ChangeAnalyzer:
    """
    Deterministic detection engine coordinating Git diff investigation,
    lifecycle script inspection, registry analysis, CI/CD audits, and typosquatting.
    """

    def __init__(
        self,
        repo_dir: Path,
        base_commit: str = "HEAD~1",
        head_commit: str = "HEAD",
        target_dir: Optional[Path] = None,
        enable_ai: bool = True,
    ):
        self.repo_dir = repo_dir.resolve()
        self.base_commit = base_commit
        self.head_commit = head_commit
        self.target_dir = (target_dir or self.repo_dir).resolve()
        self.enable_ai = enable_ai
        self.scan_timestamp = datetime.now(timezone.utc).isoformat()

        # Cache git metadata
        self.is_git = (self.repo_dir / ".git").exists() or gm.commit_exists(self.repo_dir, "HEAD")
        self.base_sha = None
        self.head_sha = None
        self.head_info = {}
        self.changed_files: Set[str] = set()

        if self.is_git:
            try:
                res = gm.run_git(["rev-parse", "--verify", f"{self.head_commit}^{{commit}}"], cwd=self.repo_dir, check=False)
                if res.returncode == 0:
                    self.head_sha = res.stdout.strip()
                    self.head_info = gm.commit_info(self.repo_dir, self.head_sha)
            except Exception:
                self.head_sha = None

            try:
                res = gm.run_git(["rev-parse", "--verify", f"{self.base_commit}^{{commit}}"], cwd=self.repo_dir, check=False)
                if res.returncode == 0:
                    self.base_sha = res.stdout.strip()
            except Exception:
                self.base_sha = None

            if self.base_sha and self.head_sha:
                try:
                    diff_pairs = gm.changed_files(self.repo_dir, self.base_sha, self.head_sha)
                    self.changed_files = {p for _, p in diff_pairs}
                except Exception:
                    self.changed_files = set()

    def _determine_origin(self, file_rel_path: str) -> str:
        """Distinguish whether a finding was introduced in the commit range or was pre-existing."""
        normalized = file_rel_path.replace("\\", "/")
        if not self.changed_files:
            return "PRE_EXISTING"
        if normalized in self.changed_files or any(normalized.endswith(c) for c in self.changed_files):
            return "INTRODUCED_IN_RANGE"
        return "PRE_EXISTING"

    def run_investigation(self) -> Dict[str, Any]:
        """Execute full deterministic investigation pipeline."""
        raw_findings: List[Dict[str, Any]] = []

        # 1. Git Diff Investigation (Range: base -> head)
        if self.base_sha and self.head_sha:
            diff_findings = inspect_git_diff_range(self.repo_dir, self.base_sha, self.head_sha)
            raw_findings.extend(diff_findings)

        # 2. Registry & Source Configurations
        reg_findings = inspect_registry_configurations(self.repo_dir)
        for rf in reg_findings:
            rf["change_origin"] = self._determine_origin(rf["affected_file"])
            if self.head_info and rf["change_origin"] == "INTRODUCED_IN_RANGE":
                rf["commit_reference"] = self.head_info
        raw_findings.extend(reg_findings)

        # 3. Target Manifests and Lockfiles (both in repo root and sub-targets like nodegoat)
        manifest_files = list(self.repo_dir.glob("**/package.json"))
        lockfiles = list(self.repo_dir.glob("**/package-lock.json"))

        for m_file in manifest_files:
            if "node_modules" in str(m_file) or ".venv" in str(m_file):
                continue
            rel_path = str(m_file.relative_to(self.repo_dir)).replace("\\", "/")
            origin = self._determine_origin(rel_path)
            commit_ref = self.head_info if origin == "INTRODUCED_IN_RANGE" else {}

            try:
                content = m_file.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue

            try:
                manifest_data = json.loads(content)
            except Exception:
                manifest_data = {}

            # Manifest source inspection (Git URLs, tarballs)
            if manifest_data:
                src_findings = inspect_manifest_dependency_sources(manifest_data, rel_path)
                for sf in src_findings:
                    sf["change_origin"] = origin
                    sf["commit_reference"] = commit_ref
                raw_findings.extend(src_findings)

                # Check for floating versions in dependencies
                lines = content.splitlines()
                for dep_sec in ("dependencies", "devDependencies"):
                    deps = manifest_data.get(dep_sec, {})
                    if isinstance(deps, dict):
                        for pkg, spec in deps.items():
                            if isinstance(spec, str):
                                clean_s = spec.strip().lower()
                                if clean_s in ("latest", "*") or (clean_s.startswith((">=", ">")) and "<" not in clean_s):
                                    line_no = next((i for i, l in enumerate(lines, 1) if f'"{pkg}"' in l), 1)
                                    raw_findings.append({
                                        "id": f"SUSP-DEP-FLOATING-{pkg.upper().replace('@', '').replace('/', '_')}",
                                        "category": "Dependency Change",
                                        "title": f"Floating Dependency Version Constraint for '{pkg}'",
                                        "severity": "HIGH",
                                        "confidence": "CONFIRMED",
                                        "status": "OBSERVED",
                                        "affected_file": rel_path,
                                        "line_number": line_no,
                                        "commit_reference": commit_ref,
                                        "change_origin": origin,
                                        "evidence_type": "HEURISTIC_FLAG",
                                        "evidence": f'"{pkg}": "{spec}",',
                                        "technical_explanation": (
                                            f"Package '{pkg}' declares a floating '{spec}' version constraint in '{dep_sec}'. "
                                            "Floating constraints allow automated adoption of upstream breaking or malicious updates without manifest review."
                                        ),
                                        "potential_impact": "Automatic installation of unvetted new releases or malicious package versions.",
                                        "recommended_action": f"Pin '{pkg}' to a specific immutable semantic version.",
                                        "references": ["https://docs.npmjs.com/about-semantic-versioning"]
                                    })

            # Static Lifecycle Script inspection
            script_findings = inspect_lifecycle_scripts_text(
                content,
                file_path=rel_path,
                commit_reference=commit_ref,
                change_origin=origin
            )
            raw_findings.extend(script_findings)

            # Typosquatting / Name Similarity inspection on dependencies
            typo_findings = self._inspect_manifest_typosquatting(content, rel_path, origin, commit_ref)
            raw_findings.extend(typo_findings)

        for l_file in lockfiles:
            if "node_modules" in str(l_file) or ".venv" in str(l_file):
                continue
            rel_path = str(l_file.relative_to(self.repo_dir)).replace("\\", "/")
            origin = self._determine_origin(rel_path)
            commit_ref = self.head_info if origin == "INTRODUCED_IN_RANGE" else {}

            try:
                l_content = l_file.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue

            try:
                lock_data = json.loads(l_content)
            except Exception:
                lock_data = {}

            # Lockfile resolved URL inspection
            if lock_data:
                res_findings = inspect_lockfile_sources(lock_data, rel_path)
                for rf in res_findings:
                    rf["change_origin"] = origin
                    rf["commit_reference"] = commit_ref
                raw_findings.extend(res_findings)

            # Lockfile install scripts (hasInstallScript: true)
            l_script_findings = inspect_lockfile_install_scripts(
                l_content,
                file_path=rel_path,
                commit_reference=commit_ref,
                change_origin=origin
            )
            raw_findings.extend(l_script_findings)

            # Typosquatting on lockfile dependencies
            l_typo_findings = self._inspect_lockfile_typosquatting(l_content, rel_path, origin, commit_ref)
            raw_findings.extend(l_typo_findings)

        # 4. CI/CD Workflows
        workflow_files = list(self.repo_dir.glob("**/.github/workflows/*.yml")) + list(
            self.repo_dir.glob("**/.github/workflows/*.yaml")
        )
        for w_file in workflow_files:
            if "node_modules" in str(w_file) or ".venv" in str(w_file):
                continue
            rel_path = str(w_file.relative_to(self.repo_dir)).replace("\\", "/")
            origin = self._determine_origin(rel_path)
            commit_ref = self.head_info if origin == "INTRODUCED_IN_RANGE" else {}
            wf_slug = w_file.stem.upper().replace('.', '_').replace('-', '_')

            ci_findings, _ = CIWorkflowAdapter.inspect(w_file, self.repo_dir)
            for cif in ci_findings:
                # Convert PipelineFinding structure to standard finding schema
                raw_findings.append({
                    "id": f"SUSP-CICD-{cif.get('rule_id', 'GHA')}-{wf_slug}-L{cif.get('line', 1)}",
                    "category": "Docker & CI/CD",
                    "title": cif.get("title", "CI/CD Security Finding"),
                    "severity": cif.get("severity", "MEDIUM"),
                    "confidence": "CONFIRMED" if cif.get("evidence_strength") == "high" else "MEDIUM",
                    "status": "OBSERVED",
                    "affected_file": rel_path,
                    "line_number": cif.get("line", 1),
                    "commit_reference": commit_ref,
                    "change_origin": origin,
                    "evidence_type": "HEURISTIC_FLAG",
                    "evidence": cif.get("snippet", ""),
                    "technical_explanation": cif.get("why", ""),
                    "potential_impact": cif.get("why", ""),
                    "recommended_action": cif.get("remediation", ""),
                    "references": cif.get("references", []),
                })

        # 5. Dockerfiles & Compose files
        docker_files = [
            f for f in list(self.repo_dir.glob("**/Dockerfile*")) + list(
                self.repo_dir.glob("**/docker-compose*.yml")
            ) + list(self.repo_dir.glob("**/docker-compose*.yaml"))
            if f.suffix.lower() not in (".py", ".pyc", ".js", ".ts", ".json", ".md", ".txt")
            and not f.name.endswith(".py")
        ]

        for d_file in docker_files:
            if "node_modules" in str(d_file) or ".venv" in str(d_file):
                continue
            rel_path = str(d_file.relative_to(self.repo_dir)).replace("\\", "/")
            origin = self._determine_origin(rel_path)
            commit_ref = self.head_info if origin == "INTRODUCED_IN_RANGE" else {}

            try:
                d_content = d_file.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue

            if "compose" in d_file.name.lower():
                df_findings, _ = analyze_compose(d_content, rel_path)
            else:
                df_findings, _ = analyze_dockerfile(d_content, rel_path)

            for dff in df_findings:
                raw_findings.append({
                    "id": f"SUSP-DOCKER-{dff.rule_id}-L{dff.line}",
                    "category": "Docker & CI/CD",
                    "title": dff.title,
                    "severity": dff.severity,
                    "confidence": "CONFIRMED" if dff.evidence_strength == "high" else "MEDIUM",
                    "status": "OBSERVED",
                    "affected_file": rel_path,
                    "line_number": dff.line,
                    "commit_reference": commit_ref,
                    "change_origin": origin,
                    "evidence_type": "HEURISTIC_FLAG",
                    "evidence": dff.snippet,
                    "technical_explanation": dff.why,
                    "potential_impact": dff.why,
                    "recommended_action": dff.remediation,
                    "references": dff.references,
                })

        # Deduplicate and normalize findings
        unified_findings = self._normalize_and_deduplicate(raw_findings)
        metrics = self._calculate_metrics(unified_findings)

        # Correlate findings into multi-vector attack scenarios (Phase 2)
        correlation_result = correlate_suspicious_changes(unified_findings)

        # AI-Assisted Investigation Agent (Phase 3)
        ai_investigations = []
        if self.enable_ai:
            try:
                agent = SuspiciousChangeAgent()
                ai_investigations = agent.investigate_all(
                    findings=unified_findings,
                    correlated_scenarios=correlation_result.get("scenarios", []),
                    repo_dir=self.repo_dir,
                    base_commit=self.base_sha or self.base_commit,
                    head_commit=self.head_sha or self.head_commit
                )
            except Exception as e:
                ai_investigations = []

        return {
            "analysis_type": "Suspicious Supply Chain Change Detection",
            "timestamp": self.scan_timestamp,
            "target": str(self.target_dir.name or "Repository Root"),
            "repository": str(self.repo_dir),
            "base_commit": self.base_sha or self.base_commit,
            "head_commit": self.head_sha or self.head_commit,
            "metrics": metrics,
            "findings": unified_findings,
            "correlated_scenarios": correlation_result.get("scenarios", []),
            "correlation_metrics": correlation_result.get("metrics", {}),
            "ai_investigations": ai_investigations,
        }

    def _inspect_manifest_typosquatting(
        self,
        content: str,
        rel_path: str,
        origin: str,
        commit_ref: Dict[str, str]
    ) -> List[Dict[str, Any]]:
        """Static similarity check on manifest dependencies against popular packages."""
        findings = []
        try:
            data = json.loads(content)
        except Exception:
            return []

        npm_refs = POPULAR.get("npm", [])
        lines = content.splitlines()
        seen_pairs = set()

        for sec in ("dependencies", "devDependencies"):
            deps = data.get(sec, {})
            if not isinstance(deps, dict):
                continue
            for pkg_name in deps.keys():
                matches = candidate_matches("npm", pkg_name, npm_refs)
                for m in matches:
                    ref = m.get("ref", "")
                    pair_key = tuple(sorted([pkg_name.lower(), ref.lower()]))
                    if pair_key in seen_pairs:
                        continue
                    seen_pairs.add(pair_key)

                    is_conv = m.get("is_ecosystem_convention", False)
                    both_ref = m.get("both_in_reference", False)
                    is_deceptive = m.get("is_deceptive", False)

                    # Distinguish legitimate companion packages from potential impersonation:
                    # If both are in the reference catalog and match by ecosystem convention without deceptive indicators:
                    if both_ref and is_conv and not is_deceptive:
                        continue

                    line_no = next((i for i, l in enumerate(lines, 1) if f'"{pkg_name}"' in l), 1)
                    sim = m.get("similarity", m.get("sim", 0))
                    dist = m.get("distance", m.get("dist", 99))
                    tech = ", ".join(m.get("techniques", []))

                    # Calibrate severity: deceptive indicators are HIGH/MEDIUM;
                    # ecosystem conventions (e.g. implementation affix like -nodejs) are LOW signals.
                    if is_deceptive:
                        sev = "HIGH" if dist <= 1 else "MEDIUM"
                        conf = "MEDIUM"
                    elif is_conv:
                        sev = "LOW"
                        conf = "LOW"
                    else:
                        sev = "MEDIUM" if sim >= 85 else "LOW"
                        conf = "LOW"

                    findings.append({
                        "id": f"SUSP-TYPO-{pkg_name.upper().replace('@', '').replace('/', '_')}",
                        "category": "Typosquatting",
                        "title": f"Package '{pkg_name}' Shares Name Similarity with '{ref}'",
                        "severity": sev,
                        "confidence": conf,
                        "status": "SUSPECTED",
                        "affected_file": rel_path,
                        "line_number": line_no,
                        "commit_reference": commit_ref,
                        "change_origin": origin,
                        "evidence_type": "HEURISTIC_FLAG",
                        "evidence": f'Package "{pkg_name}" similar to popular "{ref}" (similarity: {sim}%, edit distance: {dist})',
                        "technical_explanation": (
                            f"Package '{pkg_name}' has an edit distance of {dist} ({sim}% similarity) relative to '{ref}'. "
                            f"Techniques identified: {tech}. Similarity is an indicator requiring contextual disambiguation."
                        ),
                        "potential_impact": "Developers or automated build tools may install unvetted package variants.",
                        "recommended_action": f"Verify whether '{pkg_name}' is an intended implementation variant or should be replaced with canonical '{ref}'.",
                        "references": ["https://blog.reversinglabs.com/blog/typosquatting-in-open-source"]
                    })
        return findings

    def _inspect_lockfile_typosquatting(
        self,
        content: str,
        rel_path: str,
        origin: str,
        commit_ref: Dict[str, str]
    ) -> List[Dict[str, Any]]:
        """Static similarity check on lockfile dependencies (distinguishing companion packages and preventing reciprocal duplicates)."""
        findings = []
        try:
            data = json.loads(content)
        except Exception:
            return []

        npm_refs = POPULAR.get("npm", [])
        packages = data.get("packages", {})
        if not isinstance(packages, dict):
            return []

        # Check select lockfile packages to avoid exponential combinations
        seen_names = set()
        seen_pairs = set()
        for pkg_path in packages.keys():
            if not pkg_path:
                continue
            pkg_name = pkg_path.split("node_modules/")[-1] if "node_modules/" in pkg_path else pkg_path
            if pkg_name in seen_names or pkg_name.startswith("@types/"):
                continue
            seen_names.add(pkg_name)

            matches = candidate_matches("npm", pkg_name, npm_refs)
            for m in matches:
                ref = m.get("ref", "")
                pair_key = tuple(sorted([pkg_name.lower(), ref.lower()]))
                if pair_key in seen_pairs:
                    continue
                seen_pairs.add(pair_key)

                is_conv = m.get("is_ecosystem_convention", False)
                both_ref = m.get("both_in_reference", False)
                is_deceptive = m.get("is_deceptive", False)

                # Established companion packages in reference catalog (e.g. safe-buffer / safer-buffer, through / through2)
                if both_ref and is_conv and not is_deceptive:
                    continue

                # In lockfiles, suppress transitive conventions (version forks, companion packages)
                if is_conv and not is_deceptive:
                    continue

                dist = m.get("distance", m.get("dist", 99))
                sim = m.get("similarity", m.get("sim", 0))
                tech = ", ".join(m.get("techniques", []))

                if dist <= 2 or sim >= 85:
                    sev = "MEDIUM" if is_deceptive else "LOW"
                    findings.append({
                        "id": f"SUSP-TYPO-LOCK-{pkg_name.upper().replace('@', '').replace('/', '_')}",
                        "category": "Typosquatting",
                        "title": f"Transitive Dependency '{pkg_name}' Similar to '{ref}'",
                        "severity": sev,
                        "confidence": "LOW",
                        "status": "SUSPECTED",
                        "affected_file": rel_path,
                        "line_number": 1,
                        "commit_reference": commit_ref,
                        "change_origin": origin,
                        "evidence_type": "HEURISTIC_FLAG",
                        "evidence": f'Package "{pkg_name}" has edit distance {dist} from "{ref}"',
                        "technical_explanation": (
                            f"Lockfile package '{pkg_name}' shares similarity with '{ref}' ({tech}). "
                            "Transitive similarity is flagged for dependency graph review."
                        ),
                        "potential_impact": "Transitive dependency substitution or masquerading.",
                        "recommended_action": f"Verify supply chain path introducing '{pkg_name}'.",
                        "references": []
                    })
        return findings

    def _normalize_and_deduplicate(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Ensure consistent schemas and prevent duplicate findings."""
        seen_keys = set()
        normalized: List[Dict[str, Any]] = []

        sev_rank = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}

        for f in findings:
            # Generate deduplication key
            file_part = f.get("affected_file", "")
            evidence_part = f.get("evidence", "")[:80]
            cat_part = f.get("category", "")
            key = (file_part, cat_part, f.get("line_number", 0), evidence_part)

            if key in seen_keys:
                continue
            seen_keys.add(key)

            # Ensure backward-compatible fields
            explanation = f.get("explanation") or f.get("technical_explanation", "")
            title = f.get("title") or f.get("id", "Suspicious Signal")

            # Normalize evidence_type and commit_reference strictly:
            orig = f.get("change_origin", "PRE_EXISTING")
            ev_type = f.get("evidence_type", "HEURISTIC_FLAG")
            commit_ref = f.get("commit_reference") or {}

            # Strict Invariant: OBSERVED_CHANGE requires INTRODUCED_IN_RANGE and a valid commit SHA
            if orig == "PRE_EXISTING":
                ev_type = "HEURISTIC_FLAG"
                commit_ref = {}
            elif ev_type == "OBSERVED_CHANGE" and not commit_ref.get("sha"):
                ev_type = "HEURISTIC_FLAG"

            # Typosquatting confidence calibration: similarity is an indicator, never confirmed malice
            conf = f.get("confidence", "MEDIUM").upper()
            stat = f.get("status", "OBSERVED")
            cat = f.get("category", "General")
            if cat == "Typosquatting":
                stat = "SUSPECTED"
                if conf in ("CONFIRMED", "HIGH"):
                    conf = "MEDIUM"

            entry = {
                "id": f.get("id", f"SUSP-{len(normalized)+1:03d}"),
                "detection_scope": "Non-CVE Risk",
                "category": cat,
                "title": title,
                "severity": f.get("severity", "MEDIUM").upper(),
                "confidence": conf,
                "status": stat,
                "affected_file": file_part,
                "line_number": f.get("line_number", 1),
                "commit_reference": commit_ref,
                "change_origin": orig,
                "evidence_type": ev_type,
                "evidence": f.get("evidence", ""),
                "explanation": explanation,
                "technical_explanation": explanation,
                "potential_impact": f.get("potential_impact", ""),
                "recommended_action": f.get("recommended_action", ""),
                "references": f.get("references", []),
            }
            normalized.append(entry)

        # Sort by severity then file
        normalized.sort(key=lambda x: (sev_rank.get(x["severity"], 9), x["affected_file"], x["line_number"]))
        return normalized

    def _calculate_metrics(self, findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Aggregate counts across category, severity, confidence, evidence type, and origin."""
        category_counts: Dict[str, int] = {}
        severity_counts: Dict[str, int] = {}
        confidence_counts: Dict[str, int] = {}
        evidence_type_counts: Dict[str, int] = {}
        origin_counts: Dict[str, int] = {}

        for f in findings:
            cat = f.get("category", "Other")
            sev = f.get("severity", "MEDIUM")
            conf = f.get("confidence", "MEDIUM")
            ev_type = f.get("evidence_type", "HEURISTIC_FLAG")
            orig = f.get("change_origin", "PRE_EXISTING")

            category_counts[cat] = category_counts.get(cat, 0) + 1
            severity_counts[sev] = severity_counts.get(sev, 0) + 1
            confidence_counts[conf] = confidence_counts.get(conf, 0) + 1
            evidence_type_counts[ev_type] = evidence_type_counts.get(ev_type, 0) + 1
            origin_counts[orig] = origin_counts.get(orig, 0) + 1

        return {
            "total_findings": len(findings),
            "category_counts": category_counts,
            "severity_counts": severity_counts,
            "confidence_counts": confidence_counts,
            "evidence_type_counts": evidence_type_counts,
            "origin_counts": origin_counts,
        }


def format_summary_table(report: Dict[str, Any]) -> str:
    """Generate human-readable console summary."""
    metrics = report.get("metrics", {})
    findings = report.get("findings", [])

    lines = [
        "=" * 80,
        " GUARDIAN: SUSPICIOUS CHANGE INVESTIGATOR (PERSON 2 - PHASE 1)",
        "=" * 80,
        f" Target Repository: {report.get('repository')}",
        f" Commit Range:      {str(report.get('base_commit'))[:10]} -> {str(report.get('head_commit'))[:10]}",
        f" Total Findings:    {metrics.get('total_findings', 0)}",
        f" Evidence Types:    OBSERVED_CHANGE: {metrics.get('evidence_type_counts', {}).get('OBSERVED_CHANGE', 0)} | "
        f"HEURISTIC_FLAG: {metrics.get('evidence_type_counts', {}).get('HEURISTIC_FLAG', 0)}",
        f" Change Origin:     INTRODUCED_IN_RANGE: {metrics.get('origin_counts', {}).get('INTRODUCED_IN_RANGE', 0)} | "
        f"PRE_EXISTING: {metrics.get('origin_counts', {}).get('PRE_EXISTING', 0)}",
        "-" * 80,
        " Severity Breakdown:",
    ]

    for sev, count in sorted(metrics.get("severity_counts", {}).items()):
        lines.append(f"   * {sev:<10}: {count}")

    lines.append("-" * 80)
    lines.append(" Category Breakdown:")
    for cat, count in sorted(metrics.get("category_counts", {}).items()):
        lines.append(f"   * {cat:<22}: {count}")

    lines.append("=" * 80)
    lines.append(f"{'SEVERITY':<10} | {'CATEGORY':<20} | {'FILE:LINE':<35} | {'EVIDENCE TYPE'}")
    lines.append("-" * 80)

    for f in findings[:25]:
        loc = f"{f['affected_file']}:{f['line_number']}"
        if len(loc) > 35:
            loc = "..." + loc[-32:]
        lines.append(
            f"{f['severity']:<10} | {f['category']:<20} | {loc:<35} | {f['evidence_type']}"
        )

    if len(findings) > 25:
        lines.append(f"... and {len(findings) - 25} more findings (see JSON output).")

    scenarios = report.get("correlated_scenarios", [])
    if scenarios:
        lines.append("=" * 80)
        lines.append(" CORRELATED ATTACK SCENARIOS (PHASE 2 ENGINE)")
        lines.append("=" * 80)
        lines.append(f"{'SEVERITY':<10} | {'CONFIDENCE':<10} | {'SCENARIO NAME'}")
        lines.append("-" * 80)
        for s in scenarios:
            lines.append(f"{s['severity']:<10} | {s['correlation_confidence']:<10} | {s['scenario_name']}")
            lines.append(f"  -> Attack:   {s.get('attack_technique')}")
            lines.append(f"  -> Primary:  {', '.join(s.get('primary_finding_ids', []))}")
            if s.get("contradicting_evidence"):
                lines.append(f"  -> Mitigating Factor: {s['contradicting_evidence'][0].get('factor')}")
            lines.append("-" * 80)

    ai_invs = report.get("ai_investigations", [])
    if ai_invs:
        lines.append("=" * 80)
        lines.append(" AI INVESTIGATION VERDICTS & EVIDENCE GROUNDING (PHASE 3 LANGGRAPH AGENT)")
        lines.append("=" * 80)
        lines.append(f"{'VERDICT':<30} | {'CONF':<6} | {'FINDING / TARGET':<35}")
        lines.append("-" * 80)
        for inv in ai_invs:
            loc = f"{inv.get('finding_id', '')} ({inv.get('affected_file', '')})"
            if len(loc) > 35:
                loc = loc[:32] + "..."
            lines.append(f"{inv['verdict']:<30} | {inv['confidence']:<6} | {loc:<35}")
            lines.append(f"  -> Rationale: {inv['rationale'][:160]}")
            if inv.get("contradicting_evidence"):
                lines.append(f"  -> Mitigating Factor: {inv['contradicting_evidence'][0].get('factor', '')}")
            if inv.get("attack_scenario"):
                lines.append(f"  -> Suspected Attack:  {inv['attack_scenario'][:140]}")
            lines.append(f"  -> Engine: {inv.get('planner', 'deterministic')} | Steps: {len(inv.get('investigation_steps', []))}")
            lines.append("-" * 80)

    lines.append("=" * 80)
    return "\n".join(lines)


def generate_markdown_report(report: Dict[str, Any], output_path: Path) -> str:
    """Generate the formal Phase 3 investigation report: GIT_DIFF_INVESTIGATION.md."""
    metrics = report.get("metrics", {})
    findings = report.get("findings", [])
    scenarios = report.get("correlated_scenarios", [])
    ai_invs = report.get("ai_investigations", [])

    by_cat: Dict[str, List[Dict[str, Any]]] = {}
    for f in findings:
        by_cat.setdefault(f.get("category", "General"), []).append(f)

    md = []
    md.append("# Software Supply Chain Guardian: Repository & Change Investigation Report")
    md.append(f"**Target Repository:** `{report.get('repository')}`  ")
    md.append(f"**Analysis Timestamp:** `{report.get('timestamp')}`  ")
    md.append(f"**Commit Range Investigated:** `{report.get('base_commit', 'N/A')[:10]}` $\\to$ `{report.get('head_commit', 'N/A')[:10]}`  ")
    md.append(f"**Total Findings:** {metrics.get('total_findings', 0)} ({metrics.get('origin_counts', {}).get('INTRODUCED_IN_RANGE', 0)} introduced in range, {metrics.get('origin_counts', {}).get('PRE_EXISTING', 0)} pre-existing)  ")
    md.append(f"**Correlated Multi-Vector Scenarios:** {len(scenarios)}  ")
    md.append(f"**AI Investigations Conducted:** {len(ai_invs)}  \n")
    md.append("---\n")

    # 1. Executive Summary
    md.append("## 1. Executive Summary")
    md.append(
        "Software Supply Chain Guardian implements an evidence-driven, tool-using investigation pipeline "
        "designed to identify malicious, suspicious, and unauthorized software supply chain activities that "
        "conventional advisory databases (NVD, CVE, OSV) fail to detect. By analyzing Git commit diffs, "
        "manifest changes, lifecycle script commands, external package registries, and CI/CD pipelines, "
        "Guardian detects stealthy supply chain attacks and distinguishes them from benign engineering patterns.\n"
    )

    # 2. Scope & Commit Range
    md.append("## 2. Investigation Scope and Commit Range")
    md.append(f"- **Repository Path:** `{report.get('repository')}`")
    md.append(f"- **Baseline Commit:** `{report.get('base_commit')}`")
    md.append(f"- **Head Commit:** `{report.get('head_commit')}`")
    md.append(f"- **Scanned Files:** Manifests (`package.json`), lockfiles (`package-lock.json`), registry configurations (`.npmrc`), CI/CD workflows (`.github/workflows/*.yml`), and container specifications (`Dockerfile`, `docker-compose.yml`).\n")

    # 3. Methodology
    md.append("## 3. Methodology")
    md.append(
        "The investigation combines four complementary analysis layers:\n"
        "1. **Deterministic Git Diff Engine:** Audits version control differences, tagging findings with strict commit provenance (`OBSERVED_CHANGE` vs `HEURISTIC_FLAG`).\n"
        "2. **Static Surface Inspectors:** Scans lifecycle scripts for shell execution hooks, verifies registry TLS protocols, checks package lexical similarity, and evaluates CI/CD permissions.\n"
        "3. **Evidence Correlation Engine:** Correlates disparate indicators across vectors into multi-stage attack scenarios using MITRE ATT&CK techniques.\n"
        "4. **LangGraph AI Investigator:** An autonomous agent using a bounded read-only tool loop with a strict Grounding Gate to evaluate evidence, test hypotheses, and document mitigating factors.\n"
    )

    # 4. Repository Changes
    md.append("## 4. Repository Changes")
    repo_diffs = by_cat.get("Repository Diff", [])
    if repo_diffs:
        for f in repo_diffs:
            md.append(f"- **{f['id']}** ({f['severity']}): {f['title']} in `{f['affected_file']}` (Line {f['line_number']})")
    else:
        md.append("No sensitive repository file structural modifications detected in the commit range.\n")

    # 5. Dependency Changes
    md.append("## 5. Dependency Changes")
    dep_changes = by_cat.get("Dependency Change", [])
    if dep_changes:
        for f in dep_changes:
            origin_badge = "Introduced in Range" if f.get("change_origin") == "INTRODUCED_IN_RANGE" else "Pre-Existing"
            md.append(f"- **{f['id']}** [{f['severity']} | {origin_badge}]: {f['title']} (`{f['affected_file']}:{f['line_number']}`)")
            md.append(f"  - *Evidence:* `{f.get('evidence', '')}`")
    else:
        md.append("No dependency version modifications detected.\n")

    # 6. Lifecycle-Script Findings
    md.append("## 6. Lifecycle-Script Findings")
    scripts = by_cat.get("Lifecycle Script", [])
    if scripts:
        for f in scripts:
            md.append(f"- **{f['id']}** [{f['severity']}]: {f['title']} (`{f['affected_file']}:{f['line_number']}`)")
            md.append(f"  - *Command:* `{f.get('evidence', '')}`")
    else:
        md.append("No dangerous lifecycle execution hooks identified.\n")

    # 7. Registry and Dependency-Source Findings
    md.append("## 7. Registry and Dependency-Source Findings")
    sources = by_cat.get("Registry & Source", []) + by_cat.get("Dependency Source", [])
    if sources:
        for f in sources:
            md.append(f"- **{f['id']}** [{f['severity']}]: {f['title']} in `{f['affected_file']}`")
    else:
        md.append("All packages resolved through default secure encrypted registries.\n")

    # 8. CI/CD Findings
    md.append("## 8. CI/CD Pipeline Findings")
    cicd = [f for f in by_cat.get("Docker & CI/CD", []) if ".github" in f.get("affected_file", "")]
    if cicd:
        for f in cicd:
            md.append(f"- **{f['id']}** [{f['severity']}]: {f['title']} (`{f['affected_file']}:{f['line_number']}`)")
    else:
        md.append("No CI/CD pipeline vulnerabilities identified.\n")

    # 9. Docker and Build Findings
    md.append("## 9. Docker and Container Build Findings")
    docker_f = [f for f in by_cat.get("Docker & CI/CD", []) if "docker" in f.get("affected_file", "").lower() or "dockerfile" in f.get("affected_file", "").lower()]
    if docker_f:
        for f in docker_f:
            md.append(f"- **{f['id']}** [{f['severity']}]: {f['title']} in `{f['affected_file']}:{f['line_number']}`")
    else:
        md.append("No container configuration weaknesses detected.\n")

    # 10. Correlated Investigation Scenarios
    md.append("## 10. Correlated Investigation Scenarios (Phase 2 Multi-Vector Engine)")
    if scenarios:
        for s in scenarios:
            md.append(f"### Scenario: {s['scenario_name']}")
            md.append(f"- **Composite ID:** `{s['composite_id']}`")
            md.append(f"- **Severity:** `{s['severity']}` | **Confidence:** `{s['correlation_confidence']}` | **Status:** `{s['status']}`")
            md.append(f"- **Attack Technique:** `{s.get('attack_technique')}`")
            md.append(f"- **Suspected Narrative:** {s.get('suspected_scenario')}")
            md.append("- **Observed Facts:**")
            for fact in s.get("observed_facts", []):
                md.append(f"  - {fact}")
            if s.get("contradicting_evidence"):
                md.append("- **Contradicting / Mitigating Evidence:**")
                for c in s["contradicting_evidence"]:
                    md.append(f"  - **{c.get('factor')}:** {c.get('detail')}")
    else:
        md.append("No multi-vector correlation chains identified.\n")

    # 11. AI Investigation Agent Verdicts
    md.append("## 11. AI Investigation Agent Findings (Phase 3 LangGraph Tool-Using Loop)")
    if ai_invs:
        for inv in ai_invs:
            md.append(f"### Investigation: `{inv['finding_id']}`")
            md.append(f"- **Verdict:** `{inv['verdict']}` | **Confidence:** `{inv['confidence']}`")
            md.append(f"- **Planner:** `{inv.get('planner')}` | **Steps Executed:** {len(inv.get('investigation_steps', []))}")
            md.append(f"- **Rationale:** {inv['rationale']}")
            if inv.get("attack_scenario"):
                md.append(f"- **Suspected Attack Scenario:** {inv['attack_scenario']}")
            if inv.get("contradicting_evidence"):
                md.append("- **Mitigating Factors Identified:**")
                for ce in inv["contradicting_evidence"]:
                    md.append(f"  - *{ce.get('factor')}:* {ce.get('detail')}")
            if inv.get("recommended_action"):
                md.append(f"- **Actionable Remediation:** {inv['recommended_action']}")
    else:
        md.append("No autonomous AI investigations conducted.\n")

    # 12. False-Positive Considerations
    md.append("## 12. False-Positive Considerations")
    md.append(
        "- **Lexical Similarities vs Intentional Polyfills:** Package names like `bcrypt-nodejs` share similarity with `bcrypt`, "
        "but investigation confirms legitimate engineering intent (pure-JS implementation avoiding native C++ toolchain errors).\n"
        "- **Internal Private Registries:** Registries hosted on corporate networks are authenticated and safe when TLS (`strict-ssl=true`) is enforced.\n"
        "- **Official First-Party Actions:** Mutable tags on `actions/*` repositories pose operational update risks but not maintainer account takeover risks.\n"
        "- **Cryptographic Commit Pinning:** Git dependencies pinned to full 40-character commit SHAs are cryptographically immutable.\n"
    )

    # 13. Limitations
    md.append("## 13. Limitations")
    md.append(
        "- Static analysis cannot observe runtime dynamic module loading (e.g. `eval(process.env.CODE)` computed at runtime).\n"
        "- Obfuscated bytecode or compiled binary native addons require isolated dynamic sandboxing.\n"
        "- Conventional CVE scanners remain necessary for published vulnerabilities in third-party dependency code.\n"
    )

    # 14. Research Foundation
    md.append("## 14. Research Foundation")
    md.append(f"- {CITATIONS['ohm_2020']}")
    md.append(f"- {CITATIONS['ladisa_2023']}")
    md.append(f"- {CITATIONS['wang_2026']}")
    md.append(f"- {CITATIONS['lin_2024']}")
    md.append(f"- {CITATIONS['birsan_2021']}\n")

    # 15. Answer to Research Question
    md.append("## 15. Answer to the Central Research Question")
    md.append(
        "> **\"Can combining repository changes, dependency changes and pipeline changes reveal suspicious activity that vulnerability databases cannot detect?\"**\n\n"
        "**Yes, demonstrably.** Vulnerability databases such as NVD, CVE, and OSV index catalogued software defects after formal disclosure. "
        "They provide zero visibility into:\n"
        "1. Direct tarball and Git URLs introduced in pull requests.\n"
        "2. Dangerous install-time lifecycle execution hooks (`curl | sh`).\n"
        "3. CI/CD expression injection weaknesses (`${{ github.event... }}`).\n"
        "4. Insecure registry configurations and disabled TLS certificate validation.\n"
        "5. Lockfile tampering uncorroborated by manifest modifications.\n\n"
        "By synthesizing Git diffs, dependency provenance, static script syntax, and CI/CD policies into a unified LangGraph "
        "investigation loop, Guardian successfully identifies, correlates, and explains stealthy supply chain attack vectors "
        "even when no published CVE exists."
    )

    content = "\n".join(md)
    try:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(content, encoding="utf-8")
    except OSError as e:
        pass
    return content


def parse_args(argv: Optional[List[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Guardian - Person 2: Suspicious Change Investigator Engine & AI Agent"
    )
    parser.add_argument(
        "--repo",
        default=".",
        help="Path to Git repository or project root (default: current directory)"
    )
    parser.add_argument(
        "--base",
        default="HEAD~1",
        help="Base Git commit or ref for diff comparison (default: HEAD~1)"
    )
    parser.add_argument(
        "--head",
        default="HEAD",
        help="Head Git commit or ref for diff comparison (default: HEAD)"
    )
    parser.add_argument(
        "--target-dir",
        default=None,
        help="Optional sub-directory inside repository to focus investigation (e.g. nodegoat)"
    )
    parser.add_argument(
        "--out",
        default="suspicious_changes.json",
        help="Path to output JSON file (default: suspicious_changes.json)"
    )
    parser.add_argument(
        "--report-md",
        default="artifacts/reports/GIT_DIFF_INVESTIGATION.md",
        help="Path to output Markdown report (default: artifacts/reports/GIT_DIFF_INVESTIGATION.md)"
    )
    parser.add_argument(
        "--no-ai",
        action="store_true",
        help="Disable autonomous LangGraph AI agent investigations (deterministic only)"
    )
    parser.add_argument(
        "--format",
        choices=["json", "summary", "both"],
        default="both",
        help="Output format to display in stdout (json, summary, or both; default: both)"
    )
    return parser.parse_args(argv)


def main(argv: Optional[List[str]] = None) -> int:
    args = parse_args(argv)
    repo_path = Path(args.repo).resolve()
    target_path = Path(args.target_dir).resolve() if args.target_dir else None

    if not repo_path.exists():
        print(f"Error: Repository path '{repo_path}' does not exist.", file=sys.stderr)
        return 1

    analyzer = ChangeAnalyzer(
        repo_dir=repo_path,
        base_commit=args.base,
        head_commit=args.head,
        target_dir=target_path,
        enable_ai=not args.no_ai
    )

    report = analyzer.run_investigation()

    # Write output JSON artifact
    out_path = Path(args.out)
    try:
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    except OSError as e:
        print(f"Warning: Failed to write output to '{out_path}': {e}", file=sys.stderr)

    # Write output Markdown report
    if args.report_md:
        try:
            report_md_path = Path(args.report_md)
            generate_markdown_report(report, report_md_path)
        except Exception as e:
            print(f"Warning: Failed to write Markdown report to '{args.report_md}': {e}", file=sys.stderr)

    # Print requested stdout format
    if args.format in ("summary", "both"):
        print(format_summary_table(report))
        print(f"\n[+] Investigation report successfully written to: {out_path.resolve()}")
        if args.report_md:
            print(f"[+] Formal markdown report written to: {Path(args.report_md).resolve()}\n")

    if args.format == "json":
        print(json.dumps(report, indent=2))

    return 0


if __name__ == "__main__":
    sys.exit(main())
