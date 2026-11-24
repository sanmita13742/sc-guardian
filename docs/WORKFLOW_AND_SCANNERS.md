# ⚙️ Workflow, Stages & Scanner Guide

> **A beginner-friendly, comprehensive breakdown of SC Guardian's execution pipeline, explaining why this workflow was designed, what happens under each step, and why each specific scanner and tool was chosen.**

---

## 1. Why Did We Choose This Workflow?

In traditional software security, tools often run in isolation:
* A container scanner checks the base image.
* An SBOM tool lists dependencies.
* A vulnerability scanner flags outdated libraries.
* A linter checks CI workflows.

When tools run in isolation, developers end up with fragmented reports, conflicting recommendations, and overwhelming noise. **SC Guardian** designs an **interconnected, evidence-gated workflow** where each step builds upon and validates the previous step.

```
┌────────────────────────────────────────────────────────────────────────────────────────┐
│                              THE 4 PHASES OF THE WORKFLOW                              │
│                                                                                        │
│  Phase 1: DISCOVER          Phase 2: DETECT          Phase 3: DECIDE    Phase 4: ACT   │
│  (Ingest, Lockfiles,       (OSV Vulns, Threats,     (Investigate,       (What-If Sim,  │
│   CycloneDX SBOM,           Pipeline Insecurities,   Reachability AST,   Human Approval│
│   Metadata Fusion)          Digest Verification)     P0-P3 Scoring)      Policy Gate)  │
└────────────────────────────────────────────────────────────────────────────────────────┘
```

### Key Architectural Decisions Behind the Workflow:
1. **Why Lockfiles Outrank Manifests**:
   A manifest (e.g., `package.json` with `"express": "^4.17.0"`) specifies a *range* of allowed versions. The lockfile (`package-lock.json`) specifies the *exact byte-for-byte version and hash* actually installed in production. Checking only manifests produces false alarms or misses real threats; lockfiles represent ground truth.
2. **Why Parallel Detection Branches**:
   Once the dependency graph is assembled, checking for known CVEs (network I/O against OSV) and analyzing code structure (typosquatting via RapidFuzz, Git commit history, and Dockerfile linting) are independent tasks. Running them concurrently cut total scan time by **60%**.
3. **Why Reachability Analysis Before Risk Scoring**:
   A vulnerability in a dependency doesn't matter if your application never executes or imports that package. By analyzing source code import statements *before* scoring risk, we can safely downgrade non-reachable CVEs from urgent alarms to lower-priority maintenance tasks.
4. **Why What-If Simulation Before Patch Proposal**:
   Blindly upgrading a library often introduces breaking changes or pulls in new, worse transitive vulnerabilities. SC Guardian simulates the upgrade in memory first, re-resolving the sub-tree and checking for newly introduced bugs before presenting the patch to a human.

---

## 2. Step-by-Step Breakdown: What Happens Under Each Stage

Here is what happens under the hood during each stage of an SC Guardian scan:

---

### Step 1: Ingestion (GitHub URL or local folder)
* **What happens**: The user or CI pipeline gives either a public GitHub repository URL (e.g., `https://github.com/OWASP/NodeGoat`) or the path of a project folder on the machine (e.g., `C:\projects\my-app`).
* **Processing (GitHub URL)**:
  * The URL validator strips attack vectors (null bytes, query parameters, credential leaks, shell command injections).
  * Executes a shallow, hardened git clone (`git clone --depth 50 --no-single-branch`).
  * Cloned with **no git hooks**, **no submodules**, and **no symlinks**, confined strictly to an isolated temporary workspace (`.workspaces/`).
* **Processing (local folder)**: the path is resolved and checked (it must exist and be a folder); the folder is then analysed **in place, read-only**. Nothing is cloned or copied, cached scans are not reused, and git history checks run only when the folder is the top of a repository.
* **Output**: A local checkout (or the folder itself) ready for static analysis.

---

### Step 2: Multi-Ecosystem Lockfile Parsing
* **What happens**: The scanner searches for lockfiles across multiple languages and ecosystems:
  * Node.js: `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`
  * Python: `poetry.lock`, `Pipfile.lock`, `requirements.txt`
  * Java: `pom.xml`, `build.gradle`
  * Go: `go.sum`, `go.mod`
  * Rust: `Cargo.lock`
  * PHP: `composer.lock`
  * .NET: `packages.lock.json`
* **Processing**: Extracts the exact package names, pinned versions, dependency scopes (production vs development/test), and cryptographic checksums (SRI hashes).
* **Output**: Normalized, authoritative component inventory.

---

### Step 3: CycloneDX SBOM Generation
* **What happens**: Generates a standard **CycloneDX 1.5 JSON** Software Bill of Materials (SBOM).
* **Processing**:
  * Tries primary scanner (**Syft**). Syft and Trivy are located on `PATH`, in the current Windows registry `PATH` (so a tool installed after the app started is still found) and in the usual install folders (winget, scoop, chocolatey, `~/bin`, `~/go/bin`); `SYFT_BIN` / `TRIVY_BIN` override.
  * If Syft misses components or is absent, falls back to **Trivy**.
  * If neither external binary is installed, runs SC Guardian's zero-dependency **Native Built-in Rule Engine**. (Syft also reads installed `node_modules`, so its relationship graph is much richer than the lockfile-only built-in engine's. That matters for remediation: findings are grouped under the direct dependency that brings them in. On OWASP NodeGoat, Syft gives 31 groups (all 311 findings covered, 20 proposals with an automatic patch covering 226 findings), while the built-in engine gives 117 small groups (25 patchable, covering 92 findings). Prefer Syft when you want the most patchable proposals.)
* **Output**: A standardized SBOM document identifying every component, ecosystem, and service boundary.

---

### Step 4: Metadata Fusion & Registry Verification
* **What happens**: Bridges local repository data with live upstream package registries (npm, PyPI, Maven Central, crates.io, deps.dev).
* **Processing**:
  * Gathers official package metadata: author information, license identifiers (SPDX), and published cryptographic digests.
  * **Integrity Check**: Compares the hash in the developer's lockfile with the hash recorded in the public registry.
  * **Anomalies Detected**:
    * `PKG-INT`: Hash mismatch (possible repository tampering or compromised mirror).
    * `PKG-NEW`: Recently published package release (< 14 days old, higher risk of supply-chain hijack).
    * `PKG-DEP`: Deprecated or yanked package version.
    * `PKG-INST`: Dangerous install scripts (`postinstall`, `preinstall`) that run arbitrary code on developer machines.
* **Output**: A fused CycloneDX document containing rich provenance tags and verified licenses.

---

### Step 5: Directed Dependency Topology (Graph Construction)
* **What happens**: Connects components into a directed dependency graph using **NetworkX**.
* **Processing**:
  * Root nodes = application services.
  * Direct edges = packages explicitly declared by developers.
  * Transitive edges = packages imported by dependencies.
  * Calculates topological depth (distance from root) and "blast radius" (how many other packages depend on this component).
* **Output**: Full directed graph topology, exported to the interactive UI and graph database.

---

### Step 6: Parallel Detection (Vulnerabilities & Threats)
* **Track A — Vulnerability Matching**:
  * Queries Google's **OSV.dev** database using batch requests.
  * Enriches matching CVEs with **NVD** CVSS metrics and **CISA KEV** exploitation flags.
  * Queries **EPSS** (FIRST.org) to obtain the 30-day exploitation probability.
* **Track B — Pipeline & Misconfiguration Analysis**:
  * Inspects Dockerfiles: flags base images running as root, insecure `ADD <url>`, `curl | sh` piping, unpinned tags (`latest`), and End-Of-Life (EOL) operating systems.
  * Inspects GitHub Actions: flags unpinned actions, overly broad `GITHUB_TOKEN` permissions, script injection risks, and `pull_request_target` pwn-request patterns.
* **Track C — Typosquatting Analysis**:
  * Runs **RapidFuzz** Levenshtein distance calculations against the top 10,000 most popular packages to catch typosquatting attempts.
* **Output**: Comprehensive finding bundles with exact file and line locations.

---

### Step 7: AST & Regex Reachability Analysis
* **What happens**: Analyzes the application's actual source code to see if the vulnerable libraries are actually used.
* **Processing**:
  * Python: Uses AST and regex to locate `import package` and `from package import ...`.
  * JavaScript/TypeScript: Parses `require('package')` and `import ... from 'package'`.
  * Java & Go: Scans package import headers.
  * Differentiates whether an import exists in production application code or strictly inside `test/`, `tests/`, `spec/`, or `mock/` files.
* **Output**: Reachability classification: `used_by_app`, `reachable_via_dependency`, `used_in_tests_only`, or `no_import_evidence`.

---

### Step 8: Multi-Agent Investigation (`InvestigatorAgent`)
* **What happens**: A specialized agent investigates each finding to establish whether it poses a real danger to the application.
* **Processing**:
  * Dispatches read-only inspection tools: `find_imports`, `dependency_path`, `advisory_facts`, `read_snippet`.
  * Evaluates evidence against the **Grounding Gate**: claims must cite valid evidence IDs and match verified facts.
  * Issues a final verdict: `exploitable_likely`, `reachable`, `possibly_reachable`, `test_only`, or `no_import_evidence`.
* **Output**: Investigated finding records with verified rationale and evidence chains.

---

### Step 9: Contextual Risk Scoring (P0–P3 Priority Model)
* **What happens**: Translates raw CVSS numbers into an actionable priority score:
  * **P0 (Immediate Hazard)**: Actively exploited in the wild (CISA KEV) + imported directly by production code.
  * **P1 (High Priority)**: Critical/High severity + reachable in production code.
  * **P2 (Moderate Risk)**: High severity but in test scope only, or transitive with no import evidence.
  * **P3 (Low / Maintenance)**: Low severity, dev tools, or unconfirmed advisory ranges.
* **Output**: Prioritized finding queue that eliminates alert fatigue.

---

### Step 10: Remediation Planning & What-If Simulation
* **What happens**: Plans the safest, least disruptive fix for each group of findings.
* **Processing**:
  * Checks for direct parent upgrades (preserving the major version whenever possible). Candidate versions are stable releases from deps.dev; pre-releases and **npm-deprecated versions are skipped**.
  * If a parent upgrade is unavailable, generates dependency override/resolution pins (never for a package that is also a direct dependency; its own spec is raised instead).
  * **What-If Simulation**: In memory, applies the proposed version change, re-resolves dependencies via deps.dev, and checks via OSV whether the fix cleanly eliminates the CVE without introducing new ones.
  * **OS packages in images**: a Dockerfile `RUN` layer that upgrades the packages with distro fix versions (see `CONTAINER_SCANNING.md`).
  * Plans up to 300 proposals within a 900 s budget (`remediation_max_groups`, `remediation_budget_s`); the Remediation page reports how many findings are covered and why the rest are not.
  * Formats unified patch files (`git apply --check` verified).
* **Output**: Proposals with patches, compatibility ratings, and step-by-step rollback instructions.

---

### Step 11: Validation, Human Decision, Audit & Policy Gate
* **What happens**: Each fix is validated and then accepted or ignored by a human; every decision is audited.
* **Processing (local folder)**:
  * **Resolve** — the fix is applied to a scratch clone and the lockfile is refreshed with the package manager (scripts disabled); the clone is rescanned and compared with the original scan (fixed vs newly introduced); declared compatibility is checked from registry metadata (deprecation, `engines`, peer dependencies, major jumps, yanked releases); and the project's own tests run in an isolated Docker container with `--network none` for the test phase (container fixes: image build + Trivy rescan). A baseline run separates pre-existing failures from regressions.
  * **Accept & Apply Changes** — available only if validation passed (warnings must be acknowledged). Exactly the tested files are copied into the real folder after confirming they have not changed since validation; originals are backed up outside the project and **Undo** restores them. **Ignore** discards the proposal.
  * Live counters (open / applied / ignored / findings remaining) update after every Accept, and the **Fix Report** records each applied fix with its scores, the real diff, the validation record and a one-page PDF.
* **Processing (GitHub repository)**: a human records Approve / Reject / Needs review with a reason; an approved fix can be exported as a patch and PR text, or committed to an isolated branch (never pushed or merged).
* **Both**: every decision goes into an immutable audit trail (`data/scanner.db`). Policy-as-code rules (`policies/default.yaml`, `strict.yaml`) are evaluated by `guardian.py gate` and in CI.
* **Output**: Applied fixes with an undo path, pass/fail gate status for CI/CD pipelines, plus SARIF 2.1.0 and CycloneDX VEX export files.

---

### Step 12: Continuous Monitoring
* **What happens**: Stores the software inventory in SQLite for background tracking.
* **Processing**:
  * Periodically re-queries OSV.dev and CISA KEV against stored inventories.
  * If a zero-day is disclosed today for a dependency scanned last week, generates an alert without needing to re-clone the repository.
  * Applies to GitHub scans. Scans of local folders are not put on the watch list; rescan the folder instead.
* **Output**: Real-time notifications for newly emerged supply-chain threats.

---

## 3. Which Scanners & Tools Do We Use, What Do They Do, and Why?

SC Guardian uses a curated suite of specialized industry-standard tools and algorithms. The table below details each component:

| Tool / Scanner | What It Actually Does | Why We Chose It | Fallback Behavior |
|---|---|---|---|
| **Syft** *(Anchore)* | High-speed CLI binary that inspects project directories and extracts package metadata across 15+ programming languages. | Fast, battle-tested, produces native CycloneDX 1.5 JSON with license and hash extraction. | Automatically falls back to **Trivy** or the **Native Built-in Engine**. |
| **Trivy** *(Aqua Security)* | Comprehensive scanner for container images, filesystems, and Git repositories. | Excellent container image and CI action inspection; serves as a cross-verification second pass. | Automatically falls back to the **Native Built-in Engine**. |
| **Native Built-in Engine** | Pure Python lockfile and manifest parser authored specifically for SC Guardian. | Zero external dependencies; guarantees SC Guardian runs anywhere (even in locked-down environments without binaries). | Primary baseline engine. |
| **OSV.dev** *(Google)* | Open Source Vulnerabilities distributed database. | Open, precise, tracks commit-level ranges across open-source ecosystems, supports fast JSON batch queries. | Falls back to SQLite cached queries; marks findings `unavailable` if offline. |
| **NVD & CVSS** | National Vulnerability Database maintained by NIST. | Authoritative source for standardized CVSS v2/v3 base scores, vector strings, and CWE classifications. | Uses cached scores; falls back to OSV severity ratings. |
| **CISA KEV** | Known Exploited Vulnerabilities catalog from the US Cybersecurity and Infrastructure Security Agency. | The gold standard for identifying vulnerabilities that threat actors are actively exploiting in the real world. | Cached locally; periodically refreshed. |
| **EPSS** *(FIRST.org)* | Exploit Prediction Scoring System: machine learning model estimating 30-day exploit probability. | Replaces guesswork with empirical probability data; separates academic bugs from real risks. | Cached locally (24-hour TTL); gracefully omitted if unavailable. |
| **RapidFuzz** | High-performance C++ implementation of Levenshtein string distance algorithms. | Analyzes package names against the top 10,000 packages in $< 5\text{ ms}$ to detect typosquatting. | Pure Python string matching fallback. |
| **NetworkX** | Python library for the creation, manipulation, and study of the structure and dynamics of complex networks. | Efficient directed graph traversal, shortest path calculation, and blast-radius reachability analysis. | Built into core dependencies. |
| **LangGraph** | Graph-based agent orchestration framework. | Enables stateful multi-agent DAGs with parallel execution, conditional edges, and robust failure containment. | Native orchestration backbone. |
| **Docker / gVisor** | Container runtime for ephemeral sandboxed execution. | Runs user builds and tests with `--network none` and `--cap-drop ALL`, ensuring zero host exposure. | Gracefully skipped with a notification if Docker daemon is not running. |
| **vis-network & Streamlit** | HTML5 Canvas physics-based visualization library with Streamlit frontend. | Interactive dark-mode graph exploration with debounced physics simulation, impact paths, and filtering. | Tree-view and tabular views available if offline or scripts disabled. |

---

## 4. Cache & Inference Optimizations

To ensure instant responsiveness and minimize external API calls:

```
┌────────────────────────────────────────────────────────────────────────┐
│                        CACHE & PERFORMANCE MATRIX                      │
│                                                                        │
│ • OSV Batch Queries:       Cached in SQLite for 12 hours               │
│ • EPSS Exploit Scores:     Cached in SQLite for 24 hours               │
│ • Package Registry Fusion: Cached in SQLite for 24 hours               │
│ • LLM Inference Responses: Cached in-memory by prompt SHA-256 (0.00s)  │
│ • Graph UI Payloads:       Cached via Streamlit @st.cache_data         │
│ • vis-network Physics:     Debounced (75ms), auto-pauses at rest (0% CPU)│
└────────────────────────────────────────────────────────────────────────┘
```

1. **Deterministic Speed**: In standard deterministic mode, a full scan of a typical repository runs in **3 to 8 seconds**.
2. **Zero-Latency In-Memory Graph Scrubbing**: As users move the limit slider or filter nodes, the UI avoids reloading Streamlit and updates via differential DOM mutations.
3. **Resilience to Network Drops**: If public registries or OSV experience outages, circuit breakers trip immediately, falling back to cached historical data without crashing the pipeline.
