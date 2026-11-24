"""
Evidence Correlation Engine (Person 2 - Phase 2)
Deterministic cross-signal correlation across repository commits, dependencies,
lifecycle scripts, registry configurations, CI/CD pipelines, and container build files.

Correlates individual signals into defensible multi-vector supply-chain attack scenarios:
1. Malicious Dependency Injection with Install-Time Hook (Ohm et al., 2020)
2. CI/CD Pipeline Hijacking & Supply Chain Pivot (Wang et al., 2026)
3. Dependency Confusion & Registry Source Tampering (Ladisa et al., 2023; Birsan, 2021)
4. Typosquatting / Package Masquerading with Shadow Execution (Ohm et al., 2020)
5. Container Build Poisoning via Mutable Base Images & Build-Time Downloads (Docker CIS)
6. Lockfile-Manifest Desynchronization / Covert Dependency Tampering (Ladisa et al., 2023)

Strict Invariants:
- Preserves all original finding IDs and source references.
- Records both supporting and contradicting evidence for every scenario.
- Strictly distinguishes observed facts from suspected attack scenarios.
- Assigns severity and confidence deterministically based on evidence composition.
- Generates composite findings with traceable graph relationships.
- Does not invoke LLMs or non-deterministic heuristics.
"""
from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Set, Tuple
from pydantic import BaseModel, Field

# Research Citations
CITATIONS = {
    "ohm_2020": "Ohm et al. (2020), Backstabber's Knife Collection: A Review of Open Source Software Supply Chain Attacks",
    "ladisa_2023": "Ladisa et al. (2023), SoK: Taxonomy of Attacks on Open-Source Software Supply Chains",
    "wang_2026": "Wang et al. (2026), Demystifying and Detecting Agentic Workflow Injection Vulnerabilities in GitHub Actions",
    "lin_2024": "Lin et al. (2024), UntrustIDE: Exploiting Weaknesses in VS Code Extensions",
    "birsan_2021": "Birsan (2021), Dependency Confusion: How I Hacked Into Apple, Microsoft and Dozens of Other Companies",
}

SEVERITY_LEVELS = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
CONFIDENCE_LEVELS = ["HIGH", "MEDIUM", "LOW"]


class TraceableRelationship(BaseModel):
    source_id: str
    target_id: str
    relationship: str
    rationale: str


class CompositeFinding(BaseModel):
    composite_id: str
    scenario_name: str
    scenario_type: str
    attack_technique: str
    primary_finding_ids: List[str]
    related_files: List[str]
    correlation_confidence: str  # HIGH, MEDIUM, LOW
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW
    status: str  # CONFIRMED_MULTI_VECTOR, SUSPECTED_SCENARIO
    observed_facts: List[str]
    suspected_scenario: str
    supporting_evidence: List[Dict[str, Any]]
    contradicting_evidence: List[Dict[str, Any]]
    traceable_relationships: List[TraceableRelationship]
    reasoning_chain: List[str]
    recommended_investigation_steps: List[str]
    citations: List[str]


class ChangeCorrelator:
    """
    Deterministic correlation engine that synthesizes individual findings
    into evidence-backed attack scenarios.
    """

    def __init__(self, findings: List[Dict[str, Any]]):
        self.raw_findings = findings
        # Index findings by ID, category, file, and package name
        self.by_id: Dict[str, Dict[str, Any]] = {f.get("id", ""): f for f in findings if f.get("id")}
        self.by_category: Dict[str, List[Dict[str, Any]]] = {}
        self.by_file: Dict[str, List[Dict[str, Any]]] = {}
        self.by_package: Dict[str, List[Dict[str, Any]]] = {}

        for f in findings:
            cat = f.get("category", "General")
            self.by_category.setdefault(cat, []).append(f)

            file_path = f.get("affected_file", "")
            if file_path:
                self.by_file.setdefault(file_path, []).append(f)

            pkg = self._extract_package_name(f)
            if pkg:
                self.by_package.setdefault(pkg.lower(), []).append(f)

    def _extract_package_name(self, finding: Dict[str, Any]) -> Optional[str]:
        """Extract associated package name from ID, title, or evidence."""
        fid = finding.get("id", "")
        evidence = finding.get("evidence", "")
        title = finding.get("title", "")

        # Lock install script: LOCK-INSTALL-SCRIPT-<PKG>
        m = re.match(r"^LOCK-INSTALL-SCRIPT-([A-Z0-9_\-]+)", fid)
        if m:
            return m.group(1).lower().replace("_", "-")

        # Dependency change: SUSP-DEP-FLOATING-<PKG> or DIFF-DEP-ADDED-<PKG>
        m = re.match(r"^(?:SUSP-DEP-FLOATING|DIFF-DEP-ADDED|DIFF-DEP-MODIFIED|DIFF-DEP-REMOVED)-([A-Z0-9_\-]+)", fid)
        if m:
            return m.group(1).lower().replace("_", "-")

        # Typosquatting: SUSP-TYPO-<PKG> or SUSP-TYPO-LOCK-<PKG>
        m = re.match(r"^SUSP-TYPO-(?:LOCK-)?([A-Z0-9_\-]+)", fid)
        if m:
            return m.group(1).lower().replace("_", "-")

        # Source dependency: SRC-GIT-DEP-<PKG> or SRC-TARBALL-DEP-<PKG>
        m = re.match(r"^SRC-(?:GIT|TARBALL)-DEP-([A-Z0-9_\-]+)", fid)
        if m:
            return m.group(1).lower().replace("_", "-")

        # Look in title: Dependency 'pkg' or Package 'pkg'
        m = re.search(r"(?:Dependency|Package)\s+'([^']+)'", title)
        if m:
            return m.group(1).lower()

        # Look in evidence: "pkg": ...
        m = re.search(r'"([a-zA-Z0-9_\-/@]+)":\s*(?:\{|")', evidence)
        if m and not m.group(1).startswith("node_modules/"):
            return m.group(1).lower()

        return None

    def correlate(self) -> List[CompositeFinding]:
        """Execute all deterministic correlation rules."""
        composites: List[CompositeFinding] = []

        # Rule 1: Dependency Injection + Install-Time Execution Hook
        composites.extend(self._correlate_dep_and_install_execution())

        # Rule 2: CI/CD Pipeline Hijacking (Unpinned Action + Elevated Token / Script Injection)
        composites.extend(self._correlate_ci_pipeline_tampering())

        # Rule 3: Dependency Confusion & Registry Source Tampering
        composites.extend(self._correlate_registry_and_sources())

        # Rule 4: Typosquatting Masquerading with Execution Vector
        composites.extend(self._correlate_typosquat_execution())

        # Rule 5: Container Build Poisoning (Unpinned Base Image + Build-Time Fetch / Root)
        composites.extend(self._correlate_container_poisoning())

        # Rule 6: Lockfile-Manifest Desynchronization
        composites.extend(self._correlate_lockfile_desync())

        # Deterministic sorting: severity rank, then confidence, then composite_id
        sev_order = {s: i for i, s in enumerate(SEVERITY_LEVELS)}
        conf_order = {c: i for i, c in enumerate(CONFIDENCE_LEVELS)}
        composites.sort(key=lambda x: (sev_order.get(x.severity, 99), conf_order.get(x.correlation_confidence, 99), x.composite_id))

        return composites

    # --------------------------------------------------------------------------
    # Scenario 1: Dependency Injection + Install-Time Hook
    # --------------------------------------------------------------------------
    def _correlate_dep_and_install_execution(self) -> List[CompositeFinding]:
        results: List[CompositeFinding] = []
        dep_findings = self.by_category.get("Dependency Change", []) + self.by_category.get("Dependency Source", [])
        script_findings = self.by_category.get("Lifecycle Script", [])

        if not dep_findings or not script_findings:
            return results

        # 1A. Package-level correlation (same package has both dependency anomaly and install hook)
        matched_packages = set()
        for pkg, p_findings in self.by_package.items():
            deps = [f for f in p_findings if f.get("category") in ("Dependency Change", "Dependency Source")]
            scripts = [f for f in p_findings if f.get("category") == "Lifecycle Script"]

            if deps and scripts:
                matched_packages.add(pkg)
                results.append(self._build_dep_install_composite(pkg, deps, scripts))

        # 1B. Manifest-level correlation: Unpinned/floating dependency added in manifest AND manifest has dangerous install script
        manifest_files = {f.get("affected_file") for f in dep_findings if f.get("affected_file", "").endswith("package.json")}
        for m_file in manifest_files:
            file_deps = [f for f in self.by_file.get(m_file, []) if f.get("category") in ("Dependency Change", "Dependency Source")]
            file_scripts = [f for f in self.by_file.get(m_file, []) if f.get("category") == "Lifecycle Script" and f.get("severity") in ("CRITICAL", "HIGH")]

            if file_deps and file_scripts:
                comp_id = f"CORR-MANIFEST-INSTALL-CHAIN-{len(results)+1:03d}"
                results.append(self._build_manifest_chain_composite(comp_id, m_file, file_deps, file_scripts))

        return results

    def _build_dep_install_composite(self, pkg: str, deps: List[Dict[str, Any]], scripts: List[Dict[str, Any]]) -> CompositeFinding:
        primary_ids = [f["id"] for f in deps + scripts]
        files = sorted(list({f.get("affected_file", "") for f in deps + scripts if f.get("affected_file")}))

        # Collect supporting evidence
        supporting = []
        for d in deps:
            supporting.append({
                "finding_id": d["id"],
                "role": "Dependency Specification",
                "detail": d.get("explanation", ""),
                "evidence": d.get("evidence", "")
            })
        for s in scripts:
            supporting.append({
                "finding_id": s["id"],
                "role": "Install Execution Hook",
                "detail": s.get("explanation", ""),
                "evidence": s.get("evidence", "")
            })

        # Evaluate contradicting evidence
        contradicting = []
        is_pinned = any(
            "SHA" in d.get("explanation", "")
            or "SHA" in d.get("title", "")
            or "@sha" in d.get("evidence", "").lower()
            or bool(re.search(r"#[0-9a-fA-F]{40}", d.get("evidence", "")))
            for d in deps
        )
        if is_pinned:
            contradicting.append({
                "factor": "Exact Cryptographic Pinning",
                "detail": "Dependency is pinned to an immutable commit SHA or hash rather than a floating tag.",
                "mitigation_strength": "HIGH"
            })

        is_benign_build = any("node-gyp" in s.get("evidence", "").lower() or "tsc" in s.get("evidence", "").lower() for s in scripts)
        if is_benign_build:
            contradicting.append({
                "factor": "Standard Native Compilation",
                "detail": "Install script command matches standard native build tools (node-gyp/tsc).",
                "mitigation_strength": "MEDIUM"
            })

        # Deterministic severity and confidence calculation
        has_critical_script = any(s.get("severity") == "CRITICAL" for s in scripts)
        has_floating_dep = any("floating" in d.get("title", "").lower() or "latest" in d.get("evidence", "").lower() for d in deps)
        all_introduced_in_range = all(f.get("change_origin") == "INTRODUCED_IN_RANGE" for f in deps + scripts)

        if has_critical_script:
            sev = "CRITICAL"
        elif has_floating_dep and any(s.get("severity") in ("HIGH", "MEDIUM") for s in scripts):
            sev = "HIGH"
        else:
            sev = "MEDIUM"

        if contradicting and any(c["mitigation_strength"] == "HIGH" for c in contradicting):
            # Downgrade severity by 1 level due to strong contradiction
            idx = SEVERITY_LEVELS.index(sev)
            sev = SEVERITY_LEVELS[min(idx + 1, len(SEVERITY_LEVELS) - 1)]

        # Confidence
        if all_introduced_in_range and not contradicting:
            conf = "HIGH"
            status = "CONFIRMED_MULTI_VECTOR"
        elif any(f.get("evidence_type") == "OBSERVED_CHANGE" for f in deps + scripts):
            conf = "MEDIUM"
            status = "SUSPECTED_SCENARIO"
        else:
            conf = "LOW" if contradicting else "MEDIUM"
            status = "SUSPECTED_SCENARIO"

        # Build traceable relationships
        relationships = []
        for d in deps:
            for s in scripts:
                relationships.append(TraceableRelationship(
                    source_id=d["id"],
                    target_id=s["id"],
                    relationship="triggers_execution_of",
                    rationale=f"Dependency '{pkg}' declared in manifest triggers install hook declared in lockfile/manifest upon 'npm install'."
                ))

        observed_facts = [
            f"Package '{pkg}' is referenced across multiple configuration layers: {', '.join(files)}.",
            f"Dependency configuration defines: {[d.get('evidence', '') for d in deps]}.",
            f"Package registers automated install hook: {[s.get('evidence', '') for s in scripts]}."
        ]

        reasoning = [
            f"Step 1: Analyzed package '{pkg}' across dependency manifest and lockfile declarations.",
            f"Step 2: Identified dependency anomaly ({', '.join(d['id'] for d in deps)}) indicating unpinned or direct sourcing.",
            f"Step 3: Correlated corresponding lifecycle hook ({', '.join(s['id'] for s in scripts)}) executing on host during installation.",
            f"Step 4: Evaluated mitigations (identified {len(contradicting)} contradicting factor(s)).",
            f"Step 5: Concluded {'CONFIRMED' if status == 'CONFIRMED_MULTI_VECTOR' else 'SUSPECTED'} install-time execution risk."
        ]

        return CompositeFinding(
            composite_id=f"CORR-DEP-INSTALL-{pkg.upper().replace('@', '').replace('/', '_')}",
            scenario_name=f"Install-Time Code Execution via Dependency '{pkg}'",
            scenario_type="dependency_install_execution",
            attack_technique="MITRE ATT&CK T1195.001 (Compromise Software Dependencies)",
            primary_finding_ids=primary_ids,
            related_files=files,
            correlation_confidence=conf,
            severity=sev,
            status=status,
            observed_facts=observed_facts,
            suspected_scenario=(
                f"An attacker leverages unpinned or direct dependency '{pkg}' to automatically trigger arbitrary "
                "code execution on developer workstations and CI/CD build environments at install time."
            ),
            supporting_evidence=supporting,
            contradicting_evidence=contradicting,
            traceable_relationships=relationships,
            reasoning_chain=reasoning,
            recommended_investigation_steps=[
                f"Inspect the complete tarball and source code repository of '{pkg}'.",
                "Execute build using 'npm install --ignore-scripts' in an isolated container to block lifecycle hooks.",
                "Replace floating or direct URL constraints with pinned semantic versions verified against official registries."
            ],
            citations=[CITATIONS["ohm_2020"], CITATIONS["ladisa_2023"]]
        )

    def _build_manifest_chain_composite(
        self, comp_id: str, m_file: str, deps: List[Dict[str, Any]], scripts: List[Dict[str, Any]]
    ) -> CompositeFinding:
        primary_ids = [f["id"] for f in deps + scripts]
        has_critical = any(s.get("severity") == "CRITICAL" for s in scripts)
        has_observed = any(f.get("evidence_type") == "OBSERVED_CHANGE" for f in deps + scripts)
        all_introduced = all(f.get("change_origin") == "INTRODUCED_IN_RANGE" for f in deps + scripts)

        sev = "CRITICAL" if has_critical else "HIGH"
        conf = "HIGH" if (has_observed and all_introduced) else "MEDIUM"
        status = "CONFIRMED_MULTI_VECTOR" if (has_observed and all_introduced) else "SUSPECTED_SCENARIO"

        return CompositeFinding(
            composite_id=comp_id,
            scenario_name=f"Co-Located Dependency Anomaly and Dangerous Lifecycle Hook in '{m_file}'",
            scenario_type="manifest_lifecycle_chain",
            attack_technique="MITRE ATT&CK T1195.001 (Compromise Software Dependencies)",
            primary_finding_ids=primary_ids,
            related_files=[m_file],
            correlation_confidence=conf,
            severity=sev,
            status=status,
            observed_facts=[
                f"Manifest '{m_file}' defines unpinned dependencies: {[d.get('evidence') for d in deps]}.",
                f"Manifest '{m_file}' defines high-severity install script commands: {[s.get('evidence') for s in scripts]}."
            ],
            suspected_scenario="Coordinated modification introducing both external dependencies and shell execution in the same project manifest.",
            supporting_evidence=[{"finding_id": f["id"], "evidence": f.get("evidence", "")} for f in deps + scripts],
            contradicting_evidence=[],
            traceable_relationships=[
                TraceableRelationship(
                    source_id=deps[0]["id"],
                    target_id=scripts[0]["id"],
                    relationship="co_located_in_manifest",
                    rationale=f"Both dependency specification and execution hook reside within '{m_file}'."
                )
            ],
            reasoning_chain=[
                f"Step 1: Detected dependency constraint anomalies in '{m_file}'.",
                f"Step 2: Detected dangerous script commands in the same manifest.",
                "Step 3: Correlated as a single co-located project configuration risk."
            ],
            recommended_investigation_steps=[
                "Review Git commit history for who introduced the script commands and unpinned dependencies.",
                "Audit build scripts for exfiltration or secondary payload downloads."
            ],
            citations=[CITATIONS["ohm_2020"]]
        )

    # --------------------------------------------------------------------------
    # Scenario 2: CI/CD Pipeline Hijacking & Supply Chain Pivot
    # --------------------------------------------------------------------------
    def _correlate_ci_pipeline_tampering(self) -> List[CompositeFinding]:
        results: List[CompositeFinding] = []
        ci_findings = self.by_category.get("Docker & CI/CD", [])
        if not ci_findings:
            return results

        # Group by workflow file
        workflows = {f.get("affected_file", "") for f in ci_findings if ".github/workflows" in f.get("affected_file", "")}

        for wf in workflows:
            wf_findings = [f for f in ci_findings if f.get("affected_file") == wf]
            unpinned_actions = [f for f in wf_findings if "UNPINNED" in f.get("id", "") or "GHA001" in f.get("id", "") or "DF001" in f.get("id", "")]
            priv_or_perm = [f for f in wf_findings if "PERM" in f.get("id", "") or "GHA004" in f.get("id", "") or "GHA002" in f.get("id", "")]
            injection = [f for f in wf_findings if "GHA003" in f.get("id", "") or "injection" in f.get("title", "").lower()]
            remote_shell = [f for f in wf_findings if "GHA007" in f.get("id", "") or "curl|sh" in f.get("evidence", "").lower()]

            # Distinguish first-party (actions/*, github/*) from third-party actions
            first_party_actions = [
                f for f in unpinned_actions
                if any(fp in f.get("evidence", "").lower() for fp in ("actions/", "github/"))
            ]
            third_party_actions = [
                f for f in unpinned_actions
                if not any(fp in f.get("evidence", "").lower() for fp in ("actions/", "github/"))
            ]
            has_third_party = len(third_party_actions) > 0
            all_first_party = len(unpinned_actions) > 0 and not has_third_party

            # Pipeline attack scenario correlation requires an actual untrusted external attack vector:
            # either an unpinned third-party action, an expression injection, or a remote shell execution.
            # Official first-party actions without injection or remote download represent maintenance risks,
            # not exploitable multi-vector supply-chain attacks.
            has_attack_vector = has_third_party or len(injection) > 0 or len(remote_shell) > 0

            if has_attack_vector and (priv_or_perm or injection):
                primary_ids = [f["id"] for f in unpinned_actions + priv_or_perm + injection + remote_shell]
                wf_name = wf.rsplit("/", 1)[-1]
                comp_id = f"CORR-PIPELINE-{wf_name.upper().replace('.', '_').replace('-', '_')}"

                action_scope_label = (
                    "Third-Party GitHub Action" if has_third_party else "First-Party GitHub-Maintained Action"
                )

                supporting = [{"finding_id": f["id"], "title": f["title"], "evidence": f.get("evidence", "")} for f in unpinned_actions + priv_or_perm + injection + remote_shell]

                contradicting = []
                if all_first_party:
                    contradicting.append({
                        "factor": "First-Party Action Maintained by GitHub",
                        "detail": (
                            "All unpinned actions in this workflow originate from official GitHub-maintained "
                            "repositories (actions/*, github/*). While tag mutation is theoretically possible, "
                            "it does not present third-party maintainer account takeover risk."
                        ),
                        "mitigation_strength": "HIGH"
                    })

                # Evaluate permissions accurately: do not assume missing permissions = write access
                has_explicit_write = any("write-all" in f.get("evidence", "").lower() or "write scopes" in f.get("evidence", "").lower() for f in priv_or_perm)
                missing_explicit_perm = any("no `permissions:`" in f.get("evidence", "").lower() or "lacks 'permissions:'" in f.get("evidence", "").lower() for f in priv_or_perm)

                if missing_explicit_perm and not has_explicit_write:
                    perm_fact = (
                        f"Workflow '{wf}' does not specify an explicit 'permissions:' block; effective token privileges "
                        "depend on repository/organization default settings (which default to read-only in modern GitHub "
                        "organizations, but may grant write access in legacy or self-hosted settings)."
                    )
                else:
                    perm_fact = f"Workflow '{wf}' explicitly configures elevated or unconstrained token permissions."

                # Calibrated severity and confidence:
                # - Script injection or explicit write permissions + third-party action: HIGH
                # - Third-party unpinned action without explicit write: MEDIUM
                # - Only first-party actions unpinned and no injection: LOW (due to HIGH mitigation)
                if injection or (has_third_party and has_explicit_write):
                    sev = "HIGH"
                    conf = "HIGH" if any(f.get("change_origin") == "INTRODUCED_IN_RANGE" for f in wf_findings) else "MEDIUM"
                elif has_third_party:
                    sev = "MEDIUM"
                    conf = "MEDIUM"
                else:
                    # All first party, no injection
                    sev = "LOW"
                    conf = "LOW"

                relationships = []
                if unpinned_actions and priv_or_perm:
                    relationships.append(TraceableRelationship(
                        source_id=unpinned_actions[0]["id"],
                        target_id=priv_or_perm[0]["id"],
                        relationship="inherits_permissions_of",
                        rationale=(
                            f"{action_scope_label} executes inside a runner whose effective token authorization "
                            f"is governed by {priv_or_perm[0]['id']}."
                        )
                    ))
                if injection and priv_or_perm:
                    relationships.append(TraceableRelationship(
                        source_id=injection[0]["id"],
                        target_id=priv_or_perm[0]["id"],
                        relationship="executes_with_privilege",
                        rationale="Injected script commands expand in runner context and inherit effective GITHUB_TOKEN permissions."
                    ))

                scenario_title = (
                    f"Third-Party CI/CD Pipeline Attack Vector in '{wf_name}'"
                    if has_third_party
                    else f"Unpinned First-Party Action Maintenance Risk in '{wf_name}'"
                )

                suspected_narrative = (
                    f"An attacker compromises upstream third-party action repository tags in '{wf_name}' "
                    "or leverages script injection to execute commands with runner privileges."
                    if has_third_party or injection
                    else f"Workflow '{wf_name}' references mutable first-party action tags (@v1, @v2) without SHA pinning. "
                    "While published by GitHub, moving tags can introduce unexpected breaking changes or runtime updates."
                )

                results.append(CompositeFinding(
                    composite_id=comp_id,
                    scenario_name=scenario_title,
                    scenario_type="pipeline_hijack",
                    attack_technique="MITRE ATT&CK T1195.002 (Compromise CI/CD Toolchain) / T1059 (Command and Scripting Interpreter)",
                    primary_finding_ids=primary_ids,
                    related_files=[wf],
                    correlation_confidence=conf,
                    severity=sev,
                    status="SUSPECTED_SCENARIO",
                    observed_facts=[
                        perm_fact,
                        f"Workflow incorporates unpinned references or command expansions: {[f.get('evidence', '') for f in unpinned_actions + injection]}."
                    ],
                    suspected_scenario=suspected_narrative,
                    supporting_evidence=supporting,
                    contradicting_evidence=contradicting,
                    traceable_relationships=relationships,
                    reasoning_chain=[
                        f"Step 1: Evaluated CI/CD workflow security controls in '{wf}'.",
                        f"Step 2: Analyzed action provenance ({len(third_party_actions)} third-party, {len(first_party_actions)} first-party).",
                        f"Step 3: Assessed token permissions (explicit write: {has_explicit_write}, missing block: {missing_explicit_perm}).",
                        f"Step 4: Applied mitigating factors (first-party actions: {all_first_party}).",
                        f"Step 5: Synthesized calibrated {sev} severity pipeline scenario with {conf} confidence."
                    ],
                    recommended_investigation_steps=[
                        "Pin actions to full 40-character commit SHAs (e.g. actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11).",
                        "Add a top-level 'permissions: contents: read' block to declare explicit least privilege.",
                        "Pass untrusted input through environment variables rather than direct inline expansion."
                    ],
                    citations=[CITATIONS["wang_2026"], CITATIONS["ladisa_2023"]]
                ))

        return results

    # --------------------------------------------------------------------------
    # Scenario 3: Dependency Confusion & Registry Source Tampering
    # --------------------------------------------------------------------------
    def _correlate_registry_and_sources(self) -> List[CompositeFinding]:
        results: List[CompositeFinding] = []
        reg_findings = self.by_category.get("Registry & Source", [])
        src_findings = self.by_category.get("Dependency Source", [])

        if not reg_findings and not src_findings:
            return results

        # Insecure HTTP registry or disabled TLS + direct raw tarball / Git URLs
        insecure_transports = [f for f in reg_findings if "INSECURE" in f["id"] or "STRICT-SSL" in f["id"]]
        raw_sources = [f for f in src_findings if "TARBALL" in f["id"] or "GIT" in f["id"] or "HTTP" in f["id"]]

        # Isolate unpinned or cleartext sources that represent actual tampering exposure
        suspicious_sources = [
            f for f in raw_sources
            if "HTTP" in f.get("id", "")
            or ("TARBALL" in f.get("id", "") and "https://" not in f.get("evidence", ""))
            or ("GIT" in f.get("id", "") and not re.search(r"#[0-9a-fA-F]{40}", f.get("evidence", "")))
        ]

        if insecure_transports or (len(suspicious_sources) >= 1 and reg_findings):
            primary_ids = [f["id"] for f in insecure_transports + raw_sources]
            files = sorted(list({f.get("affected_file", "") for f in insecure_transports + raw_sources if f.get("affected_file")}))

            supporting = [{"finding_id": f["id"], "evidence": f.get("evidence", ""), "detail": f.get("explanation", "")} for f in insecure_transports + raw_sources]
            contradicting = []

            # Check if source is official GitHub HTTPS URL or commit-pinned
            for rs in raw_sources:
                ev = rs.get("evidence", "")
                if re.search(r"#[0-9a-fA-F]{40}", ev):
                    contradicting.append({
                        "factor": "Exact Cryptographic Commit Pinning",
                        "detail": f"Git dependency in '{rs.get('affected_file')}' is pinned to an immutable 40-character commit SHA.",
                        "mitigation_strength": "HIGH"
                    })
                elif "https://github.com" in ev:
                    contradicting.append({
                        "factor": "Encrypted Upstream Host",
                        "detail": f"Tarball/Git dependency in '{rs.get('affected_file')}' is fetched over HTTPS from GitHub infrastructure.",
                        "mitigation_strength": "LOW"
                    })

            has_cleartext = any("HTTP" in f.get("id", "") for f in insecure_transports + raw_sources)
            sev = "HIGH" if has_cleartext else "MEDIUM"
            conf = "HIGH" if any(f.get("change_origin") == "INTRODUCED_IN_RANGE" for f in insecure_transports + raw_sources) else "MEDIUM"

            if contradicting and any(c["mitigation_strength"] == "HIGH" for c in contradicting) and not has_cleartext:
                idx = SEVERITY_LEVELS.index(sev)
                sev = SEVERITY_LEVELS[min(idx + 1, len(SEVERITY_LEVELS) - 1)]
                conf = "LOW"

            relationships = []
            if insecure_transports and raw_sources:
                relationships.append(TraceableRelationship(
                    source_id=insecure_transports[0]["id"],
                    target_id=raw_sources[0]["id"],
                    relationship="downgrades_security_of",
                    rationale="Insecure registry transport configurations permit interception of package fetches."
                ))

            results.append(CompositeFinding(
                composite_id=f"CORR-REGISTRY-SOURCE-CHAIN-{len(results)+1:03d}",
                scenario_name="Unencrypted Transport / Non-Standard Dependency Source Vector",
                scenario_type="registry_source_confusion",
                attack_technique="MITRE ATT&CK T1195.001 (Compromise Software Dependencies)",
                primary_finding_ids=primary_ids,
                related_files=files,
                correlation_confidence=conf,
                severity=sev,
                status="SUSPECTED_SCENARIO",
                observed_facts=[
                    f"Configuration files specify insecure or external sources: {[f.get('evidence', '') for f in insecure_transports + raw_sources]}."
                ],
                suspected_scenario=(
                    "An adversary positioned on the network (MITM) or leveraging public package namespace confusion "
                    "intercepts or replaces dependencies downloaded outside standard authenticated registries."
                ),
                supporting_evidence=supporting,
                contradicting_evidence=contradicting,
                traceable_relationships=relationships,
                reasoning_chain=[
                    "Step 1: Evaluated registry transport protocols and external package sources.",
                    "Step 2: Identified unencrypted HTTP transport or direct tarball references bypassing central validation.",
                    "Step 3: Correlated transport exposure with dependency resolution risks.",
                    "Step 4: Evaluated mitigations (TLS presence, trusted hostnames).",
                    "Step 5: Generated composite registry and source correlation."
                ],
                recommended_investigation_steps=[
                    "Ensure all registry endpoints in .npmrc and .yarnrc enforce 'https://'.",
                    "Remove 'strict-ssl=false' and configure valid CA trust stores.",
                    "Pin tarball dependencies with SHA-512 cryptographic subresource integrity hashes."
                ],
                citations=[CITATIONS["birsan_2021"], CITATIONS["ladisa_2023"]]
            ))

        return results

    # --------------------------------------------------------------------------
    # Scenario 4: Typosquatting Masquerading + Shadow Execution Vector
    # --------------------------------------------------------------------------
    def _correlate_typosquat_execution(self) -> List[CompositeFinding]:
        results: List[CompositeFinding] = []
        typo_findings = self.by_category.get("Typosquatting", [])
        if not typo_findings:
            return results

        for tf in typo_findings:
            pkg = self._extract_package_name(tf)
            if not pkg:
                continue

            # Look for related lifecycle scripts or floating versions for this typosquat package
            related_scripts = [f for f in self.by_package.get(pkg, []) if f.get("category") == "Lifecycle Script"]
            related_deps = [f for f in self.by_package.get(pkg, []) if f.get("category") == "Dependency Change"]

            if related_scripts or related_deps:
                primary_ids = [tf["id"]] + [f["id"] for f in related_scripts + related_deps]
                files = sorted(list({f.get("affected_file", "") for f in [tf] + related_scripts + related_deps if f.get("affected_file")}))

                supporting = [
                    {"finding_id": tf["id"], "evidence": tf.get("evidence", ""), "detail": tf.get("explanation", "")}
                ]
                for rs in related_scripts:
                    supporting.append({"finding_id": rs["id"], "evidence": rs.get("evidence", ""), "detail": "Automated install script execution"})
                for rd in related_deps:
                    supporting.append({"finding_id": rd["id"], "evidence": rd.get("evidence", ""), "detail": "Dependency specification anomaly"})

                # Contradicting evidence: Is this a well-known legacy package?
                contradicting = []
                if "bcrypt-nodejs" in pkg:
                    contradicting.append({
                        "factor": "Established Legacy Implementation",
                        "detail": "'bcrypt-nodejs' is a historically recognized pure-JavaScript implementation of bcrypt created to avoid native build dependencies, not a malicious typosquat.",
                        "mitigation_strength": "HIGH"
                    })
                elif "object-assign" in pkg:
                    contradicting.append({
                        "factor": "Standard Polyfill/Ponyfill",
                        "detail": "'object-assign' is a widely utilized ECMAScript 6 polyfill maintained by standard community members with millions of weekly downloads.",
                        "mitigation_strength": "HIGH"
                    })

                # Severity: never CRITICAL for typosquatting heuristics
                sev = "LOW" if contradicting else "MEDIUM"
                conf = "LOW" if contradicting else "MEDIUM"

                relationships = []
                for rs in related_scripts:
                    relationships.append(TraceableRelationship(
                        source_id=tf["id"],
                        target_id=rs["id"],
                        relationship="executes_code_via",
                        rationale=f"Similar-named package '{pkg}' registers an active install hook."
                    ))

                results.append(CompositeFinding(
                    composite_id=f"CORR-TYPOSQUAT-EXEC-{pkg.upper().replace('@', '').replace('/', '_')}",
                    scenario_name=f"Typosquatting Masquerading Risk for '{pkg}'",
                    scenario_type="typosquat_masquerading",
                    attack_technique="MITRE ATT&CK T1036.005 (Masquerading: Match Legitimate Name)",
                    primary_finding_ids=primary_ids,
                    related_files=files,
                    correlation_confidence=conf,
                    severity=sev,
                    status="SUSPECTED_SCENARIO",
                    observed_facts=[
                        f"Package '{pkg}' shares string similarity with popular canonical package: {tf.get('evidence', '')}.",
                        f"Package declarations in repository: {[f.get('evidence', '') for f in related_scripts + related_deps]}."
                    ],
                    suspected_scenario=(
                        f"A developer intended to install a popular library but mistakenly specified '{pkg}', "
                        "which registers automated install lifecycle behavior."
                    ),
                    supporting_evidence=supporting,
                    contradicting_evidence=contradicting,
                    traceable_relationships=relationships,
                    reasoning_chain=[
                        f"Step 1: Computed string distance and affix variations for '{pkg}'.",
                        f"Step 2: Identified related execution hooks or version anomalies.",
                        f"Step 3: Evaluated package legitimacy and history ({len(contradicting)} mitigating factor(s)).",
                        "Step 4: Formulated balanced typosquatting assessment without arbitrary elevation."
                    ],
                    recommended_investigation_steps=[
                        f"Verify if the project explicitly requires '{pkg}' or intended the canonical package.",
                        "Check the publisher reputation and download statistics on npmjs.com.",
                        "Audit the package contents before executing install scripts."
                    ],
                    citations=[CITATIONS["ohm_2020"]]
                ))

        return results

    # --------------------------------------------------------------------------
    # Scenario 5: Container Build Poisoning (Mutable Base Image + Remote Download)
    # --------------------------------------------------------------------------
    def _correlate_container_poisoning(self) -> List[CompositeFinding]:
        results: List[CompositeFinding] = []
        docker_findings = [f for f in self.by_category.get("Docker & CI/CD", []) if "Dockerfile" in f.get("affected_file", "") or "compose" in f.get("affected_file", "")]
        if not docker_findings:
            return results

        unpinned_bases = [f for f in docker_findings if "DF001" in f.get("id", "") or "DF002" in f.get("id", "") or "DF012" in f.get("id", "")]
        build_downloads = [f for f in docker_findings if "DF004" in f.get("id", "") or "DF005" in f.get("id", "")]

        if unpinned_bases and len(unpinned_bases) >= 1:
            primary_ids = [f["id"] for f in unpinned_bases + build_downloads]
            files = sorted(list({f.get("affected_file", "") for f in unpinned_bases + build_downloads if f.get("affected_file")}))

            supporting = [{"finding_id": f["id"], "evidence": f.get("evidence", ""), "detail": f.get("explanation", "")} for f in unpinned_bases + build_downloads]
            contradicting = []

            # Check if base image is official (node, alpine, mongo)
            for ub in unpinned_bases:
                ev = ub.get("evidence", "").lower()
                if any(official in ev for official in ("from node:", "from alpine:", "image: mongo:")):
                    contradicting.append({
                        "factor": "Official Base Image Publisher",
                        "detail": f"Base image in '{ub.get('affected_file')}' originates from an official Docker Hub verified repository.",
                        "mitigation_strength": "LOW"
                    })

            sev = "HIGH" if build_downloads else "MEDIUM"
            conf = "HIGH" if any(f.get("change_origin") == "INTRODUCED_IN_RANGE" for f in unpinned_bases + build_downloads) else "MEDIUM"

            results.append(CompositeFinding(
                composite_id=f"CORR-CONTAINER-POISONING-{len(results)+1:03d}",
                scenario_name="Container Image Supply Chain Vulnerability",
                scenario_type="container_poisoning",
                attack_technique="MITRE ATT&CK T1525 (Implant Internal Image)",
                primary_finding_ids=primary_ids,
                related_files=files,
                correlation_confidence=conf,
                severity=sev,
                status="SUSPECTED_SCENARIO",
                observed_facts=[
                    f"Container build specifications reference mutable base image tags: {[f.get('evidence', '') for f in unpinned_bases]}."
                ],
                suspected_scenario=(
                    "Container build specifications do not pin base images by cryptographic sha256 digest. "
                    "Upstream tag mutations or compromised registry layers could silently alter build output."
                ),
                supporting_evidence=supporting,
                contradicting_evidence=contradicting,
                traceable_relationships=[],
                reasoning_chain=[
                    "Step 1: Inspected Dockerfiles and Docker Compose build files.",
                    f"Step 2: Identified {len(unpinned_bases)} unpinned or end-of-life base image declaration(s).",
                    "Step 3: Assessed reproducibility and immutable layer integrity.",
                    "Step 4: Evaluated mitigations (official Docker Hub publishers).",
                    "Step 5: Formulated container supply chain correlation."
                ],
                recommended_investigation_steps=[
                    "Pin container base images using immutable SHA-256 digests (e.g. FROM node:12-alpine@sha256:...).",
                    "Migrate end-of-life runtimes (e.g. Node 12, Mongo 4.4) to actively supported LTS releases.",
                    "Avoid build-time remote downloads without cryptographic verification."
                ],
                citations=[CITATIONS["ladisa_2023"]]
            ))

        return results

    # --------------------------------------------------------------------------
    # Scenario 6: Lockfile-Manifest Desynchronization
    # --------------------------------------------------------------------------
    def _correlate_lockfile_desync(self) -> List[CompositeFinding]:
        results: List[CompositeFinding] = []
        lock_findings = [f for f in self.raw_findings if "DIFF-LOCK-MANIFEST-MISMATCH" in f.get("id", "") or "LOCK-UNEXPLAINED" in f.get("id", "")]

        for lf in lock_findings:
            results.append(CompositeFinding(
                composite_id=f"CORR-LOCKFILE-DESYNC-{len(results)+1:03d}",
                scenario_name="Lockfile Manipulation without Manifest Modification",
                scenario_type="lockfile_tampering",
                attack_technique="MITRE ATT&CK T1195.001 (Compromise Software Dependencies)",
                primary_finding_ids=[lf["id"]],
                related_files=[lf.get("affected_file", "")],
                correlation_confidence="HIGH" if lf.get("evidence_type") == "OBSERVED_CHANGE" else "MEDIUM",
                severity="HIGH",
                status="CONFIRMED_MULTI_VECTOR" if lf.get("evidence_type") == "OBSERVED_CHANGE" else "SUSPECTED_SCENARIO",
                observed_facts=[f"Lockfile was modified in commit history without corresponding manifest changes: {lf.get('evidence', '')}."],
                suspected_scenario="Covert dependency substitution or tampering executed directly against the lockfile to bypass manifest reviews.",
                supporting_evidence=[{"finding_id": lf["id"], "evidence": lf.get("evidence", ""), "detail": lf.get("explanation", "")}],
                contradicting_evidence=[],
                traceable_relationships=[],
                reasoning_chain=[
                    "Step 1: Compared Git diff between package.json and package-lock.json.",
                    "Step 2: Detected lockfile changes uncorroborated by manifest intent.",
                    "Step 3: Flagged as potential covert dependency modification."
                ],
                recommended_investigation_steps=[
                    "Regenerate package-lock.json cleanly from package.json using 'npm install --package-lock-only'.",
                    "Diff the generated lockfile against version control to isolate unexplained records."
                ],
                citations=[CITATIONS["ladisa_2023"]]
            ))

        return results


def correlate_suspicious_changes(findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Public entry point: Correlates raw findings and generates structured composite findings.
    Returns:
    {
        "total_composites": int,
        "scenarios": [CompositeFinding.model_dump(), ...],
        "metrics": {
            "by_severity": {...},
            "by_scenario_type": {...},
            "by_confidence": {...}
        }
    }
    """
    correlator = ChangeCorrelator(findings)
    composites = correlator.correlate()

    sev_counts: Dict[str, int] = {}
    type_counts: Dict[str, int] = {}
    conf_counts: Dict[str, int] = {}

    for c in composites:
        sev_counts[c.severity] = sev_counts.get(c.severity, 0) + 1
        type_counts[c.scenario_type] = type_counts.get(c.scenario_type, 0) + 1
        conf_counts[c.correlation_confidence] = conf_counts.get(c.correlation_confidence, 0) + 1

    return {
        "total_composites": len(composites),
        "scenarios": [c.model_dump() for c in composites],
        "metrics": {
            "by_severity": sev_counts,
            "by_scenario_type": type_counts,
            "by_confidence": conf_counts,
        }
    }
