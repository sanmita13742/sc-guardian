# Software Supply Chain Guardian: Repository & Change Investigation Report
**Target Repository:** `E:\Bosch\nodegoat`  
**Analysis Timestamp:** `2026-11-24T11:11:42.027631+00:00`  
**Commit Range Investigated:** `ea6d3f7182` $\to$ `c472eec7ff`  
**Total Findings:** 19 (0 introduced in range, 19 pre-existing)  
**Correlated Multi-Vector Scenarios:** 1  
**AI Investigations Conducted:** 8  

---

## 1. Executive Summary
Software Supply Chain Guardian implements an evidence-driven, tool-using investigation pipeline designed to identify malicious, suspicious, and unauthorized software supply chain activities that conventional advisory databases (NVD, CVE, OSV) fail to detect. By analyzing Git commit diffs, manifest changes, lifecycle script commands, external package registries, and CI/CD pipelines, Guardian detects stealthy supply chain attacks and distinguishes them from benign engineering patterns.

## 2. Investigation Scope and Commit Range
- **Repository Path:** `E:\Bosch\nodegoat`
- **Baseline Commit:** `ea6d3f7182d25b8c7a6402b4927409bd2621ba22`
- **Head Commit:** `c472eec7ff83a6197d6eb552f059e62132090269`
- **Scanned Files:** Manifests (`package.json`), lockfiles (`package-lock.json`), registry configurations (`.npmrc`), CI/CD workflows (`.github/workflows/*.yml`), and container specifications (`Dockerfile`, `docker-compose.yml`).

## 3. Methodology
The investigation combines four complementary analysis layers:
1. **Deterministic Git Diff Engine:** Audits version control differences, tagging findings with strict commit provenance (`OBSERVED_CHANGE` vs `HEURISTIC_FLAG`).
2. **Static Surface Inspectors:** Scans lifecycle scripts for shell execution hooks, verifies registry TLS protocols, checks package lexical similarity, and evaluates CI/CD permissions.
3. **Evidence Correlation Engine:** Correlates disparate indicators across vectors into multi-stage attack scenarios using MITRE ATT&CK techniques.
4. **LangGraph AI Investigator:** An autonomous agent using a bounded read-only tool loop with a strict Grounding Gate to evaluate evidence, test hypotheses, and document mitigating factors.

## 4. Repository Changes
No sensitive repository file structural modifications detected in the commit range.

## 5. Dependency Changes
- **SUSP-DEP-FLOATING-GRUNT-ENV** [HIGH | Pre-Existing]: Floating Dependency Version Constraint for 'grunt-env' (`package.json:50`)
  - *Evidence:* `"grunt-env": "latest",`
## 6. Lifecycle-Script Findings
- **SCRIPT-DOCKER_LATEST-DOCKER-MONGO-L36** [MEDIUM]: Suspicious 'docker-mongo' Script: Unpinned Docker Execution in npm Script (`package.json:36`)
  - *Command:* `"docker-mongo": "docker run -p 27017:27017 --name mongo  mongo:latest"`
- **LOCK-INSTALL-SCRIPT-CYPRESS** [LOW]: Dependency 'cypress@3.3.1' Declares Install Script in Lockfile (`package-lock.json:1`)
  - *Command:* `"node_modules/cypress": { "hasInstallScript": true, "version": "3.3.1" }`
- **LOCK-INSTALL-SCRIPT-FSEVENTS** [LOW]: Dependency 'fsevents@1.2.9' Declares Install Script in Lockfile (`package-lock.json:1`)
  - *Command:* `"node_modules/fsevents": { "hasInstallScript": true, "version": "1.2.9" }`
- **LOCK-INSTALL-SCRIPT-NODEMON** [LOW]: Dependency 'nodemon@1.19.1' Declares Install Script in Lockfile (`package-lock.json:1`)
  - *Command:* `"node_modules/nodemon": { "hasInstallScript": true, "version": "1.19.1" }`
## 7. Registry and Dependency-Source Findings
- **SRC-GIT-DEP-GRUNT-IF** [MEDIUM]: Direct Git-Sourced Dependency 'grunt-if' (Mutable Branch) in `package.json`
## 8. CI/CD Pipeline Findings
- **SUSP-CICD-GHA004-E2E_TEST-L1** [LOW]: No explicit token permissions declared (`.github/workflows/e2e-test.yml:1`)
- **SUSP-CICD-GHA001-E2E_TEST-L16** [LOW]: First-party (official) Action 'actions/checkout' is not pinned to a commit SHA (`.github/workflows/e2e-test.yml:16`)
- **SUSP-CICD-GHA001-E2E_TEST-L21** [LOW]: First-party (official) Action 'actions/setup-node' is not pinned to a commit SHA (`.github/workflows/e2e-test.yml:21`)
- **SUSP-CICD-GHA001-E2E_TEST-L26** [LOW]: First-party (official) Action 'actions/cache' is not pinned to a commit SHA (`.github/workflows/e2e-test.yml:26`)
- **SUSP-CICD-GHA001-E2E_TEST-L58** [LOW]: First-party (official) Action 'actions/upload-artifact' is not pinned to a commit SHA (`.github/workflows/e2e-test.yml:58`)
- **SUSP-CICD-GHA004-LINT-L1** [LOW]: No explicit token permissions declared (`.github/workflows/lint.yml:1`)
- **SUSP-CICD-GHA001-LINT-L16** [LOW]: First-party (official) Action 'actions/checkout' is not pinned to a commit SHA (`.github/workflows/lint.yml:16`)
- **SUSP-CICD-GHA001-LINT-L21** [LOW]: First-party (official) Action 'actions/setup-node' is not pinned to a commit SHA (`.github/workflows/lint.yml:21`)
## 9. Docker and Container Build Findings
- **SUSP-DOCKER-DF012-L14** [MEDIUM]: Service 'mongo' uses an end-of-life image in `docker-compose.yml:14`
- **SUSP-DOCKER-DF002-L1** [LOW]: Base image tag is not pinned by digest in `Dockerfile:1`
- **SUSP-DOCKER-DF008-L5** [LOW]: `npm install` used in container build instead of `npm ci` in `Dockerfile:5`
- **SUSP-DOCKER-DF002-L7** [LOW]: Base image tag is not pinned by digest in `Dockerfile:7`
## 10. Correlated Investigation Scenarios (Phase 2 Multi-Vector Engine)
### Scenario: Container Image Supply Chain Vulnerability
- **Composite ID:** `CORR-CONTAINER-POISONING-001`
- **Severity:** `MEDIUM` | **Confidence:** `MEDIUM` | **Status:** `SUSPECTED_SCENARIO`
- **Attack Technique:** `MITRE ATT&CK T1525 (Implant Internal Image)`
- **Suspected Narrative:** Container build specifications do not pin base images by cryptographic sha256 digest. Upstream tag mutations or compromised registry layers could silently alter build output.
- **Observed Facts:**
  - Container build specifications reference mutable base image tags: ['image: mongo:4.4', 'FROM node:12-alpine', 'FROM node:12-alpine'].
- **Contradicting / Mitigating Evidence:**
  - **Official Base Image Publisher:** Base image in 'docker-compose.yml' originates from an official Docker Hub verified repository.
  - **Official Base Image Publisher:** Base image in 'Dockerfile' originates from an official Docker Hub verified repository.
  - **Official Base Image Publisher:** Base image in 'Dockerfile' originates from an official Docker Hub verified repository.
## 11. AI Investigation Agent Findings (Phase 3 LangGraph Tool-Using Loop)
### Investigation: `SUSP-DEP-FLOATING-GRUNT-ENV`
- **Verdict:** `CONFIRMED_ANOMALY` | **Confidence:** `HIGH`
- **Planner:** `llm:gemini:gemini-3.5-flash-lite` | **Steps Executed:** 1
- **Rationale:** The dependency 'grunt-env' is pinned to the 'latest' tag in package.json, representing a floating dependency version constraint. Floating tags introduce supply chain risks as they allow arbitrary code updates to be pulled automatically during builds without integrity verification.
- **Suspected Attack Scenario:** An attacker compromising the 'grunt-env' package registry entry or performing dependency confusion/typosquatting could push malicious payloads under the 'latest' tag, causing automatic execution of malicious code in subsequent CI/CD pipelines or developer environments.
- **Actionable Remediation:** Pin 'grunt-env' to a specific, immutable version number instead of 'latest' and utilize a lockfile.
### Investigation: `SUSP-DOCKER-DF012-L14`
- **Verdict:** `CONFIRMED_ANOMALY` | **Confidence:** `HIGH`
- **Planner:** `deterministic` | **Steps Executed:** 1
- **Rationale:** Container configuration inspection in 'docker-compose.yml' confirmed an end-of-life base image declaration. Upstream maintainers no longer provide security patches or vulnerability remediations for this release stream.
- **Actionable Remediation:** Upgrade the base image to an actively maintained, supported long-term support (LTS) release line.
### Investigation: `SRC-GIT-DEP-GRUNT-IF`
- **Verdict:** `CONFIRMED_ANOMALY` | **Confidence:** `HIGH`
- **Planner:** `llm:gemini:gemini-3.5-flash-lite` | **Steps Executed:** 1
- **Rationale:** The package.json file specifies a direct dependency on 'grunt-if' using a mutable remote Git branch URL (tarball/master). Relying on mutable branches or remote tarballs introduces supply chain vulnerabilities, as the underlying code can change without notice, bypassing package registry integrity checks and versioning guarantees.
- **Suspected Attack Scenario:** An attacker with write access to the upstream repository (binarymist/grunt-if) or the ability to perform a man-in-the-middle / DNS poisoning attack against the tarball download URL could inject malicious code into the master branch. When the victim runs npm install, the mutable tarball URL retrieves the compromised code, leading to arbitrary code execution in the build or deployment pipeline.
- **Actionable Remediation:** Replace the direct URL dependency on the mutable master branch with a stable, versioned release from a trusted package registry (or pin the dependency to an immutable commit hash if the Git source must be used).
### Investigation: `SCRIPT-DOCKER_LATEST-DOCKER-MONGO-L36`
- **Verdict:** `BENIGN_EXPLANATION` | **Confidence:** `HIGH`
- **Planner:** `llm:gemini:gemini-3.5-flash-lite` | **Steps Executed:** 1
- **Rationale:** The npm script executes a standard local container instance of MongoDB using 'mongo:latest' for development or testing purposes. While using the 'latest' tag is an anti-pattern for reproducibility and poses minor supply chain stability risks, it is a common convention in local developer convenience scripts rather than a malicious injection or supply chain attack.
- **Mitigating Factors Identified:**
  - *Absence of Malicious Indicators:* There are no obfuscated commands, external payload downloads, or unauthorized exfiltration steps in the npm script.
- **Actionable Remediation:** Pin the Docker image version to a specific digest or minor release (e.g., 'mongo:7.0.4') to ensure build reproducibility and security consistency.
### Investigation: `SUSP-TYPO-BCRYPT-NODEJS`
- **Verdict:** `BENIGN_EXPLANATION` | **Confidence:** `HIGH`
- **Planner:** `llm:gemini:gemini-3.5-flash-lite` | **Steps Executed:** 1
- **Rationale:** The package 'bcrypt-nodejs' is a historically well-known, pure-JavaScript implementation of bcrypt created as an alternative to the native-binding 'bcrypt' package to ease installation on Windows and serverless platforms without C++ build tools. While sharing naming similarity, it is a legitimate legacy package rather than a malicious typosquatting attempt.
- **Mitigating Factors Identified:**
  - *Edit Distance vs Purpose:* Although edit distance flags similarity, the naming convention explicitly designates it as a port/alternative for Node.js rather than a deceptive typo.
- **Actionable Remediation:** Migrate dependency from 'bcrypt-nodejs' to the officially maintained 'bcrypt' package or modern alternatives.
### Investigation: `SUSP-CICD-GHA004-E2E_TEST-L1`
- **Verdict:** `CONFIRMED_ANOMALY` | **Confidence:** `HIGH`
- **Planner:** `llm:gemini:gemini-3.5-flash-lite` | **Steps Executed:** 1
- **Rationale:** The GitHub Actions workflow file '.github/workflows/e2e-test.yml' lacks an explicit 'permissions' block at either the workflow or job level. By default, GitHub Actions assigns broad read/write permissions to the GITHUB_TOKEN depending on repository settings, increasing the blast radius if the workflow or any included step is compromised.
- **Suspected Attack Scenario:** An attacker who introduces malicious code or exploits a vulnerability in the e2e test workflow steps can leverage the overly permissive default GITHUB_TOKEN to modify repository contents, tamper with releases, or abuse API endpoints beyond the principle of least privilege.
- **Actionable Remediation:** Add an explicit 'permissions' block at the top level of '.github/workflows/e2e-test.yml' adhering to the principle of least privilege (e.g., 'permissions: contents: read').
### Investigation: `SUSP-CICD-GHA001-E2E_TEST-L16`
- **Verdict:** `BENIGN_EXPLANATION` | **Confidence:** `HIGH`
- **Planner:** `llm:gemini:gemini-3.5-flash-lite` | **Steps Executed:** 2
- **Rationale:** The GitHub Actions workflow uses the official 'actions/checkout' action tagged at '@v2'. While not pinned to an immutable full-length commit SHA, it is a first-party, trusted GitHub action, presenting standard supply chain hygiene considerations rather than a malicious anomaly or supply chain attack.
- **Mitigating Factors Identified:**
  - *No Third-Party Risk:* No unverified third-party actions are included in the workflow file.
- **Actionable Remediation:** Pin GitHub Actions to immutable full-length commit SHAs (with a comment noting the version) to ensure deterministic and tamper-proof builds.
### Investigation: `SUSP-CICD-GHA001-E2E_TEST-L21`
- **Verdict:** `BENIGN_EXPLANATION` | **Confidence:** `HIGH`
- **Planner:** `llm:gemini:gemini-3.5-flash-lite` | **Steps Executed:** 1
- **Rationale:** The workflow uses the official, first-party GitHub Action 'actions/setup-node' referenced via a version tag (v1) rather than a full commit SHA. While pinning to a full commit SHA is a best practice for supply chain hardening to protect against tag mutation, using a first-party verified action from the official 'actions' organization presents an exceptionally low risk of malicious tag hijacking compared to third-party community actions.
- **Mitigating Factors Identified:**
  - *Lack of SHA Pinning:* The action is pinned to a mutable tag (@v1) instead of an immutable commit hash, which is technically a deviation from hardening best practices.
- **Actionable Remediation:** Pin the action to an immutable commit SHA (e.g., actions/setup-node@<sha>) if strict supply chain hardening policies require immutable references for all workflow actions.
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