# Software Supply Chain Guardian: Repository & Change Investigation Report
**Target Repository:** `E:\Bosch`  
**Analysis Timestamp:** `2026-11-24T06:56:11.087173+00:00`  
**Commit Range Investigated:** `8632dea787` $\to$ `78fdbfc56e`  
**Total Findings:** 29 (1 introduced in range, 28 pre-existing)  
**Correlated Multi-Vector Scenarios:** 1  
**AI Investigations Conducted:** 8  

---

## 1. Executive Summary
Software Supply Chain Guardian implements an evidence-driven, tool-using investigation pipeline designed to identify malicious, suspicious, and unauthorized software supply chain activities that conventional advisory databases (NVD, CVE, OSV) fail to detect. By analyzing Git commit diffs, manifest changes, lifecycle script commands, external package registries, and CI/CD pipelines, Guardian detects stealthy supply chain attacks and distinguishes them from benign engineering patterns.

## 2. Investigation Scope and Commit Range
- **Repository Path:** `E:\Bosch`
- **Baseline Commit:** `8632dea787d4ec1fe1c333265ed5421c30a39584`
- **Head Commit:** `78fdbfc56e301bc3458232f38b4284c363d6b057`
- **Scanned Files:** Manifests (`package.json`), lockfiles (`package-lock.json`), registry configurations (`.npmrc`), CI/CD workflows (`.github/workflows/*.yml`), and container specifications (`Dockerfile`, `docker-compose.yml`).

## 3. Methodology
The investigation combines four complementary analysis layers:
1. **Deterministic Git Diff Engine:** Audits version control differences, tagging findings with strict commit provenance (`OBSERVED_CHANGE` vs `HEURISTIC_FLAG`).
2. **Static Surface Inspectors:** Scans lifecycle scripts for shell execution hooks, verifies registry TLS protocols, checks package lexical similarity, and evaluates CI/CD permissions.
3. **Evidence Correlation Engine:** Correlates disparate indicators across vectors into multi-stage attack scenarios using MITRE ATT&CK techniques.
4. **LangGraph AI Investigator:** An autonomous agent using a bounded read-only tool loop with a strict Grounding Gate to evaluate evidence, test hypotheses, and document mitigating factors.

## 4. Repository Changes
- **DIFF-SENSITIVE-FILE-_ENV_EXAMPLE** (LOW): Security-Sensitive File Modified: '.env.example' (Environment & Secret Configuration) in `.env.example` (Line 1)
## 5. Dependency Changes
- **SUSP-DEP-FLOATING-GRUNT-ENV** [HIGH | Pre-Existing]: Floating Dependency Version Constraint for 'grunt-env' (`nodegoat/package.json:50`)
  - *Evidence:* `"grunt-env": "latest",`
## 6. Lifecycle-Script Findings
- **SCRIPT-DOCKER_LATEST-DOCKER-MONGO-L36** [MEDIUM]: Suspicious 'docker-mongo' Script: Unpinned Docker Execution in npm Script (`nodegoat/package.json:36`)
  - *Command:* `"docker-mongo": "docker run -p 27017:27017 --name mongo  mongo:latest"`
- **LOCK-INSTALL-SCRIPT-CYPRESS** [LOW]: Dependency 'cypress@3.3.1' Declares Install Script in Lockfile (`nodegoat/package-lock.json:1`)
  - *Command:* `"node_modules/cypress": { "hasInstallScript": true, "version": "3.3.1" }`
- **LOCK-INSTALL-SCRIPT-FSEVENTS** [LOW]: Dependency 'fsevents@1.2.9' Declares Install Script in Lockfile (`nodegoat/package-lock.json:1`)
  - *Command:* `"node_modules/fsevents": { "hasInstallScript": true, "version": "1.2.9" }`
- **LOCK-INSTALL-SCRIPT-NODEMON** [LOW]: Dependency 'nodemon@1.19.1' Declares Install Script in Lockfile (`nodegoat/package-lock.json:1`)
  - *Command:* `"node_modules/nodemon": { "hasInstallScript": true, "version": "1.19.1" }`
## 7. Registry and Dependency-Source Findings
- **SRC-GIT-DEP-GRUNT-IF** [MEDIUM]: Direct Git-Sourced Dependency 'grunt-if' in `nodegoat/package.json`
## 8. CI/CD Pipeline Findings
- **SUSP-CICD-GHA001-14** [LOW]: Action 'actions/checkout' is not pinned to a commit SHA (`.github/workflows/guardian.yml:14`)
- **SUSP-CICD-GHA001-15** [LOW]: Action 'actions/setup-python' is not pinned to a commit SHA (`.github/workflows/guardian.yml:15`)
- **SUSP-CICD-GHA001-23** [LOW]: Action 'github/codeql-action' is not pinned to a commit SHA (`.github/workflows/guardian.yml:23`)
- **SUSP-CICD-GHA004-1** [LOW]: No explicit token permissions (defaults may be read-write) (`nodegoat/.github/workflows/e2e-test.yml:1`)
- **SUSP-CICD-GHA001-16** [LOW]: Action 'actions/checkout' is not pinned to a commit SHA (`nodegoat/.github/workflows/e2e-test.yml:16`)
- **SUSP-CICD-GHA001-21** [LOW]: Action 'actions/setup-node' is not pinned to a commit SHA (`nodegoat/.github/workflows/e2e-test.yml:21`)
- **SUSP-CICD-GHA001-26** [LOW]: Action 'actions/cache' is not pinned to a commit SHA (`nodegoat/.github/workflows/e2e-test.yml:26`)
- **SUSP-CICD-GHA001-58** [LOW]: Action 'actions/upload-artifact' is not pinned to a commit SHA (`nodegoat/.github/workflows/e2e-test.yml:58`)
- **SUSP-CICD-GHA004-1** [LOW]: No explicit token permissions (defaults may be read-write) (`nodegoat/.github/workflows/lint.yml:1`)
- **SUSP-CICD-GHA001-16** [LOW]: Action 'actions/checkout' is not pinned to a commit SHA (`nodegoat/.github/workflows/lint.yml:16`)
- **SUSP-CICD-GHA001-21** [LOW]: Action 'actions/setup-node' is not pinned to a commit SHA (`nodegoat/.github/workflows/lint.yml:21`)
## 9. Docker and Container Build Findings
- **SUSP-DOCKER-DF012-L14** [MEDIUM]: Service 'mongo' uses an end-of-life image in `nodegoat/docker-compose.yml:14`
- **SUSP-DOCKER-DF002-L1** [LOW]: Base image tag is not pinned by digest in `nodegoat/Dockerfile:1`
- **SUSP-DOCKER-DF008-L5** [LOW]: `npm install` ignores the lockfile pin in `nodegoat/Dockerfile:5`
- **SUSP-DOCKER-DF002-L7** [LOW]: Base image tag is not pinned by digest in `nodegoat/Dockerfile:7`
## 10. Correlated Investigation Scenarios (Phase 2 Multi-Vector Engine)
### Scenario: Container Image Supply Chain Vulnerability
- **Composite ID:** `CORR-CONTAINER-POISONING-001`
- **Severity:** `MEDIUM` | **Confidence:** `MEDIUM` | **Status:** `SUSPECTED_SCENARIO`
- **Attack Technique:** `MITRE ATT&CK T1525 (Implant Internal Image)`
- **Suspected Narrative:** Container build specifications do not pin base images by cryptographic sha256 digest. Upstream tag mutations or compromised registry layers could silently alter build output.
- **Observed Facts:**
  - Container build specifications reference mutable base image tags: ['image: mongo:4.4', 'FROM node:12-alpine', 'FROM node:12-alpine'].
- **Contradicting / Mitigating Evidence:**
  - **Official Base Image Publisher:** Base image in 'nodegoat/docker-compose.yml' originates from an official Docker Hub verified repository.
  - **Official Base Image Publisher:** Base image in 'nodegoat/Dockerfile' originates from an official Docker Hub verified repository.
  - **Official Base Image Publisher:** Base image in 'nodegoat/Dockerfile' originates from an official Docker Hub verified repository.
## 11. AI Investigation Agent Findings (Phase 3 LangGraph Tool-Using Loop)
### Investigation: `SUSP-TYPO-BCRYPT-NODEJS`
- **Verdict:** `BENIGN_EXPLANATION` | **Confidence:** `HIGH`
- **Planner:** `llm:gemini:gemini-3.5-flash-lite` | **Steps Executed:** 2
- **Rationale:** The package 'bcrypt-nodejs' is a well-known, historically significant Node.js module used as a pure JavaScript fallback for the native 'bcrypt' library. While it shares name similarity with 'bcrypt', it is an established legacy package rather than a malicious typosquatting attempt, commonly found in older applications like NodeGoat.
- **Mitigating Factors Identified:**
  - *Legacy Ecosystem Usage:* 'bcrypt-nodejs' is a recognized legacy package providing pure JavaScript bcrypt hashing functionality, widely documented and used in older training applications such as OWASP NodeGoat.
- **Actionable Remediation:** Migrate the dependency from 'bcrypt-nodejs' to the modern, actively maintained 'bcrypt' or 'bcryptjs' package to ensure long-term security and compatibility.
### Investigation: `SUSP-DEP-FLOATING-GRUNT-ENV`
- **Verdict:** `BENIGN_EXPLANATION` | **Confidence:** `HIGH`
- **Planner:** `llm:gemini:gemini-3.5-flash-lite` | **Steps Executed:** 1
- **Rationale:** The package.json configuration uses 'latest' for 'grunt-env' within a known vulnerable intentionally-insecure training application (OWASP NodeGoat). NodeGoat intentionally maintains outdated, unpinned, or vulnerable dependencies for educational and testing purposes. There is no active supply chain compromise or malicious injection indicated by the git diff history.
- **Mitigating Factors Identified:**
  - *Intentional Vulnerability Design:* Unpinned or floating dependency versions are standard practice in intentionally vulnerable training apps to demonstrate risks rather than indicating a real-world supply chain attack.
- **Actionable Remediation:** Pin dependency versions to specific stable releases if hardening the application for production use.
### Investigation: `SUSP-DOCKER-DF012-L14`
- **Verdict:** `BENIGN_EXPLANATION` | **Confidence:** `HIGH`
- **Planner:** `llm:gemini:gemini-3.5-flash-lite` | **Steps Executed:** 1
- **Rationale:** The finding flags the use of an older MongoDB image version (mongo:4.4) in a docker-compose configuration. NodeGoat is an intentionally vulnerable Node.js application designed for security training, education, and testing purposes, where legacy and vulnerable dependencies/services are expected and intentional components of the architecture.
- **Mitigating Factors Identified:**
  - *Not a Supply Chain Attack:* The use of an end-of-life upstream image in a purposefully insecure training application does not constitute a software supply chain compromise or malicious injection.
- **Actionable Remediation:** No remediation required if this repository is used strictly for educational or testing purposes. For production deployments, upgrade the MongoDB service to a supported, non-EOL version.
### Investigation: `SUSP-TYPO-LOCK-OBJECT-ASSIGN`
- **Verdict:** `CONFIRMED_ANOMALY` | **Confidence:** `MEDIUM`
- **Planner:** `deterministic` | **Steps Executed:** 2
- **Rationale:** Verified anomalous configuration in 'nodegoat/package-lock.json': Transitive Dependency 'object-assign' Similar to 'object.assign'.
- **Actionable Remediation:** Verify supply chain path introducing 'object-assign'.
### Investigation: `SRC-GIT-DEP-GRUNT-IF`
- **Verdict:** `SUSPECTED_SUPPLY_CHAIN_ATTACK` | **Confidence:** `HIGH`
- **Planner:** `llm:gemini:gemini-3.5-flash-lite` | **Steps Executed:** 1
- **Rationale:** The package.json file specifies a direct git tarball URL for the dependency 'grunt-if' pointing to a specific GitHub repository branch ('master'). Fetching dependencies directly from arbitrary Git URLs or branches bypasses registry integrity guarantees (like cryptographic checksum verification provided by npm/yarn lockfiles) and introduces a significant supply chain vector where the upstream branch content can be modified arbitrarily without version changes.
- **Suspected Attack Scenario:** An attacker compromises the external repository 'binarymist/grunt-if' on the 'master' branch or performs a DNS/repositiory spoofing attack, replacing the legitimate tarball content with malicious code that executes during the installation lifecycle scripts when developers run 'npm install'.
- **Actionable Remediation:** Replace the direct git tarball dependency with a securely published version from the official package registry, or pin the dependency to an immutable cryptographic commit hash with a verified lockfile entry.
### Investigation: `SCRIPT-DOCKER_LATEST-DOCKER-MONGO-L36`
- **Verdict:** `CONFIRMED_ANOMALY` | **Confidence:** `MEDIUM`
- **Planner:** `deterministic` | **Steps Executed:** 2
- **Rationale:** Verified anomalous configuration in 'nodegoat/package.json': Suspicious 'docker-mongo' Script: Unpinned Docker Execution in npm Script.
- **Actionable Remediation:** Audit the script behavior. If installing dependencies, run with '--ignore-scripts' and replace inline commands with trusted build scripts.
### Investigation: `DIFF-SENSITIVE-FILE-_ENV_EXAMPLE`
- **Verdict:** `BENIGN_EXPLANATION` | **Confidence:** `HIGH`
- **Planner:** `llm:gemini:gemini-3.5-flash-lite` | **Steps Executed:** 1
- **Rationale:** The modification to '.env.example' is a standard documentation and configuration template update for optional environment variables (such as NVD API keys and LLM settings). It does not contain hardcoded secrets or credentials, as `.env.example` files are strictly meant to serve as templates for developers to configure their local environments.
- **Mitigating Factors Identified:**
  - *Standard Development Practice:* Updating template configuration files when new optional features or configuration parameters are introduced is a standard software engineering practice.
- **Actionable Remediation:** No remediation required. Ensure that actual production secrets or populated '.env' files are excluded via `.gitignore`.
### Investigation: `SUSP-CICD-GHA001-14`
- **Verdict:** `BENIGN_EXPLANATION` | **Confidence:** `HIGH`
- **Planner:** `llm:gemini:gemini-3.5-flash-lite` | **Steps Executed:** 2
- **Rationale:** The workflow uses the standard official GitHub Action 'actions/checkout@v4', which is a widely accepted and ubiquitous practice across GitHub Actions workflows. Although pinning by full commit SHA provides a higher degree of immutability against tag mutation, using major version tags (like '@v4') is standard industry practice and does not represent an active supply chain attack or severe vulnerability by itself.
- **Mitigating Factors Identified:**
  - *Tag Mutability:* Using '@v4' relies on mutable tags rather than immutable commit SHAs, which leaves a theoretical window for tag redirection if the repository were ever compromised.
- **Actionable Remediation:** Pin GitHub Actions to full immutable commit SHAs (e.g., actions/checkout@b4ffde65f46332ab88eb53be808477a3936bae11) for enhanced supply chain hardening, or utilize automated dependency update tools like Dependabot to manage SHA pinning.
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