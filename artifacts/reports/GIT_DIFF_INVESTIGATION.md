# Software Supply Chain Guardian: Repository & Change Investigation Report
**Target Repository:** `E:\Bosch\nodegoat`  
**Analysis Timestamp:** `2026-11-24T10:08:14.010265+00:00`  
**Commit Range Investigated:** `edd889c333` $\to$ `55948e996e`  
**Total Findings:** 19 (0 introduced in range, 19 pre-existing)  
**Correlated Multi-Vector Scenarios:** 1  
**AI Investigations Conducted:** 8  

---

## 1. Executive Summary
Software Supply Chain Guardian implements an evidence-driven, tool-using investigation pipeline designed to identify malicious, suspicious, and unauthorized software supply chain activities that conventional advisory databases (NVD, CVE, OSV) fail to detect. By analyzing Git commit diffs, manifest changes, lifecycle script commands, external package registries, and CI/CD pipelines, Guardian detects stealthy supply chain attacks and distinguishes them from benign engineering patterns.

## 2. Investigation Scope and Commit Range
- **Repository Path:** `E:\Bosch\nodegoat`
- **Baseline Commit:** `edd889c333845b68b114934bff19e591d44a4db9`
- **Head Commit:** `55948e996e61790d2da267093b14f6b1f3293bb4`
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
- **Rationale:** The package.json file explicitly pins the dependency 'grunt-env' to the floating version constraint 'latest'. Utilizing 'latest' or overly loose version constraints introduces significant software supply chain risks, including potential supply chain substitution attacks or breaking changes introduced automatically without code review.
- **Suspected Attack Scenario:** An attacker could compromise the upstream 'grunt-env' package registry entry and publish a malicious version under the 'latest' tag. Because the project's dependency configuration automatically resolves 'latest', any subsequent build or installation process would pull and execute the malicious package version.
- **Actionable Remediation:** Pin the 'grunt-env' dependency to a specific, immutable version number and enforce lockfile usage.
### Investigation: `SUSP-DOCKER-DF012-L14`
- **Verdict:** `CONFIRMED_ANOMALY` | **Confidence:** `HIGH`
- **Planner:** `llm:gemini:gemini-3.5-flash-lite` | **Steps Executed:** 1
- **Rationale:** Inspection of docker-compose.yml confirms that the 'mongo' service relies on image 'mongo:4.4', which is past its end-of-life and no longer supported with security patches. Utilizing outdated software versions increases the exposure to unpatched vulnerabilities and potential supply chain compromise.
- **Suspected Attack Scenario:** An attacker could exploit known unpatched vulnerabilities in MongoDB 4.4 to gain unauthorized access to the database container, potentially leading to data exfiltration or lateral movement within the application infrastructure.
- **Actionable Remediation:** Upgrade the MongoDB service image to a currently supported version (e.g., mongo:6.0 or mongo:7.0) and verify application compatibility.
### Investigation: `SRC-GIT-DEP-GRUNT-IF`
- **Verdict:** `CONFIRMED_ANOMALY` | **Confidence:** `HIGH`
- **Planner:** `deterministic` | **Steps Executed:** 1
- **Rationale:** Manifest inspection in 'package.json' confirmed dependency is sourced from a mutable Git branch head without an immutable SHA pin. Upstream branch updates will alter build contents without changing manifest version declarations.
- **Suspected Attack Scenario:** Upstream branch head mutation could alter package contents without manifest version changes.
- **Actionable Remediation:** Pin the Git dependency to an explicit 40-character commit SHA or consume from a verified registry.
### Investigation: `SCRIPT-DOCKER_LATEST-DOCKER-MONGO-L36`
- **Verdict:** `BENIGN_EXPLANATION` | **Confidence:** `HIGH`
- **Planner:** `llm:gemini:gemini-3.5-flash-lite` | **Steps Executed:** 1
- **Rationale:** The npm script uses 'mongo:latest' to run a local development instance of MongoDB via Docker, which is a common and standard pattern for local developer convenience and testing. While using the mutable 'latest' tag is a minor supply chain anti-pattern that can lead to reproducibility issues, it does not represent a supply chain attack or malicious payload in this context.
- **Mitigating Factors Identified:**
  - *Absence of Malicious Indicators:* The command targets the official MongoDB image ('mongo:latest') without any obfuscation, exfiltration vectors, or untrusted remote script downloads.
- **Actionable Remediation:** Pin the Docker image tag to a specific version (e.g., 'mongo:7.0') to ensure reproducibility and consistency across development environments.
### Investigation: `SUSP-TYPO-BCRYPT-NODEJS`
- **Verdict:** `BENIGN_EXPLANATION` | **Confidence:** `HIGH`
- **Planner:** `llm:gemini:gemini-3.5-flash-lite` | **Steps Executed:** 1
- **Rationale:** The package 'bcrypt-nodejs' is a well-known, albeit older, legacy wrapper package published on npm to provide pure-JavaScript fallback implementations for environments where native compilation of 'bcrypt' fails. While its name resembles 'bcrypt', its existence predates modern typosquatting waves and it serves a documented compatibility purpose rather than a malicious deception attempt.
- **Mitigating Factors Identified:**
  - *Name Similarity:* The edit distance and naming similarity alone do not indicate malicious squatting given the package's long history and known functionality.
- **Actionable Remediation:** Migrate dependency from 'bcrypt-nodejs' to the modern, actively maintained 'bcrypt' package.
### Investigation: `SUSP-CICD-GHA004-E2E_TEST-L1`
- **Verdict:** `CONFIRMED_ANOMALY` | **Confidence:** `HIGH`
- **Planner:** `llm:gemini:gemini-3.5-flash-lite` | **Steps Executed:** 1
- **Rationale:** The GitHub Actions workflow file '.github/workflows/e2e-test.yml' lacks an explicit 'permissions:' block at either the workflow or job level. Consequently, the workflow defaults to the repository's default GITHUB_TOKEN permissions, which are often overly permissive (typically read/write access across contents and other scopes) and violate the principle of least privilege.
- **Suspected Attack Scenario:** If a malicious or vulnerable dependency or untrusted code is executed within the e2e-test workflow, an attacker could abuse the overly broad default GITHUB_TOKEN permissions to modify repository contents, push unauthorized changes, or interact with GitHub API endpoints beyond what is strictly necessary for running end-to-end tests.
- **Actionable Remediation:** Add an explicit 'permissions' block at the top level of '.github/workflows/e2e-test.yml' adhering to the principle of least privilege (e.g., 'permissions: contents: read').
### Investigation: `SUSP-CICD-GHA001-E2E_TEST-L16`
- **Verdict:** `CONFIRMED_ANOMALY` | **Confidence:** `HIGH`
- **Planner:** `llm:gemini:gemini-3.5-flash-lite` | **Steps Executed:** 1
- **Rationale:** The workflow configuration at '.github/workflows/e2e-test.yml' uses a mutable tag reference ('@v2') for the official GitHub Action 'actions/checkout' rather than an immutable full-length commit SHA. While first-party actions from 'actions' are generally trustworthy, mutable tags can be updated or overwritten upstream, leading to potential supply chain risks if the tag points to a compromised or altered revision.
- **Suspected Attack Scenario:** An attacker with compromised access to the upstream repository or the ability to manipulate tags could force-push a malicious payload to the 'v2' tag of actions/checkout. Subsequent runs of the e2e-test workflow would automatically download and execute the compromised version in the runner environment.
- **Mitigating Factors Identified:**
  - *First-party Action:* The action is maintained by GitHub ('actions/checkout'), lowering the risk of malicious intent compared to arbitrary third-party actions.
- **Actionable Remediation:** Pin the 'actions/checkout' action to an immutable full-length commit SHA (e.g., uses: actions/checkout@8f4b7f84864484a7bf31766abe9204da3cbe65b3) to ensure deterministic and secure builds.
### Investigation: `SUSP-CICD-GHA001-E2E_TEST-L21`
- **Verdict:** `CONFIRMED_ANOMALY` | **Confidence:** `HIGH`
- **Planner:** `llm:gemini:gemini-3.5-flash-lite` | **Steps Executed:** 2
- **Rationale:** The workflow configuration at '.github/workflows/e2e-test.yml' utilizes the official GitHub Action 'actions/setup-node@v1' pinned only to a mutable major version tag ('@v1') rather than an immutable full-length commit SHA. While the action is first-party and trusted, relying on mutable tags exposes the pipeline to supply chain risks if the tag is ever overwritten or compromised upstream.
- **Suspected Attack Scenario:** An attacker with compromised access to the upstream official repository or ability to manipulate tags could retarget the 'v1' tag to point to a malicious commit, causing arbitrary code execution within the repository's CI/CD pipeline upon subsequent workflow runs.
- **Mitigating Factors Identified:**
  - *First-party Action:* The action is maintained by GitHub ('actions/'), which significantly lowers the likelihood of malicious intent compared to third-party actions.
- **Actionable Remediation:** Pin the GitHub Action 'actions/setup-node' to its immutable full-length commit SHA (e.g., actions/setup-node@<commit-sha>) to ensure reproducible and secure builds.
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