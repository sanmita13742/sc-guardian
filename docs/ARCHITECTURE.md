# 🛡️ SC Guardian — System Architecture Guide

> **A human-friendly, comprehensive architectural guide to SC Guardian: an autonomous, evidence-gated software supply chain security platform.**

---

## 1. Executive Overview

Modern software development relies heavily on open-source dependencies, third-party container images, and CI/CD actions. While this accelerates shipping speed, it introduces severe supply-chain risks:
* **Transitive vulnerabilities** buried 5 levels deep in unseen sub-dependencies.
* **Malicious packages & typosquatting** that mimic popular libraries to steal credentials or inject backdoors.
* **Insecure pipelines & container configurations** (e.g., unpinned actions, `curl | sh`, root execution).
* **Alert fatigue**: legacy scanners produce hundreds of raw CVEs without telling developers whether the code actually reaches or executes the vulnerable function.

**SC Guardian** solves this by acting as an **agentic guardian** for your supply chain. It doesn't just list vulnerabilities; it maps dependency topology, tracks whether your application code actually imports the affected packages, correlates real-world threat intelligence (CISA KEV, EPSS), simulates fixes in memory before proposing them, and provides human-in-the-loop approvals.

### Core Philosophy
1. **Static Analysis by Default**: Repository code is **never** executed, built, or installed during scanning. Static analysis guarantees safety.
2. **Deterministic Grounding**: Every finding is backed by immutable, cited evidence (`evidence_id`). Hallucinations are mathematically impossible because claims are verified against hard facts before acceptance.
3. **No External Lock-In**: Works completely offline in deterministic mode without any LLM API key. If an LLM is enabled, it acts as an assistant whose outputs are strictly gate-checked.

---

## 2. High-Level System Architecture

The following diagram illustrates how requests flow through SC Guardian from initial URL ingestion to final policy reporting:

```
                  ┌──────────────────────────────────────────────┐
                  │          USER / CI/CD PIPELINE               │
                  │   Streamlit Web UI   │   CLI (guardian.py)   │
                  └──────────────────────┬───────────────────────┘
                                         │
                                         ▼
┌────────────────────────────────────────────────────────────────────────────────────────┐
│                        ORCHESTRATION LAYER (LangGraph DAG)                             │
│                                                                                        │
│  [Recon Agent] ──▶ [Lockfile Parser] ──▶ [SBOM Generator] ──▶ [Metadata Fusion]        │
│                                                                      │                 │
│                                                                      ▼                 │
│                                                            [Graph Builder]             │
│                                                                      │                 │
│                          ┌───────────────────────────────────────────┴──────────┐      │
│                          ▼                                                      ▼      │
│            [Vulnerability Correlator]                                [Threat Agent]    │
│            (OSV / NVD / KEV / EPSS)                                 (Typosquats / Risk)│
│                          │                                                      │      │
│                          └─────────────────────┬────────────────────────────────┘      │
│                                                ▼                                       │
│                                    [Investigator Agent]                                │
│                                (Import Reachability / Evidence)                        │
│                                                │                                       │
│                                                ▼                                       │
│                                      [Risk Scoring Engine]                             │
│                                       (P0 - P3 Prioritization)                         │
│                                                │                                       │
│                                                ▼                                       │
│                                       [Remediation Agent]                              │
│                                (What-If Simulation / Unified Patches)                  │
│                                                │                                       │
│                                                ▼                                       │
│                                     [Policy & Gatekeeper]                              │
│                                (SARIF / CycloneDX VEX / Audit)                         │
└────────────────────────────────────────┬───────────────────────────────────────────────┘
                                         │
                     ┌───────────────────┴───────────────────┐
                     ▼                                       ▼
        ┌─────────────────────────┐             ┌─────────────────────────┐
        │   SQLite Data Storage   │             │   Opt-In Docker Sandbox │
        │ • Cache (OSV/EPSS/NVD)  │             │ • Isolated test runner  │
        │ • Scans & Graph Tables  │             │ • --network none        │
        │ • Decisions & Audits    │             │ • --cap-drop ALL        │
        └─────────────────────────┘             └─────────────────────────┘
```

---

## 3. The 5 Architectural Layers

The codebase is organized into strict, unidirectional layers under `src/` (enforced by automated architectural auditing):

| Layer | Directory | Responsibilities |
|---|---|---|
| **1. Presentation & Interfaces** | `ui/`, `guardian.py` | Multi-page Streamlit dashboard (SBOM explorer, interactive dependency graph, vulnerability inspection, policy gate) and the command-line interface for CI/CD automation. |
| **2. Orchestration Layer** | `orchestration/` | Compiled LangGraph state machine. Manages execution order, concurrency, conditional branching, failure containment, and state persistence. |
| **3. Agent Layer** | `agents/` | Specialist autonomous agents: Supervisor, Recon, SBOM specialist, Graph analyst, Vulnerability specialist, Investigator, Threat analyst, Risk scorer, Remediation planner, and Memory keeper. |
| **4. Domain Logic Libraries** | `sbom/`, `graph/`, `vulnerability/`, `pipeline_analysis/`, `reachability/`, `remediation/`, `policy/`, `monitor/`, `sandbox/` | Core algorithmic engines: CycloneDX generators, NetworkX graph traversals, OSV batch matchers, AST import parsers, unified patch generators, and sandbox containers. |
| **5. Foundations & Infrastructure** | `evidence/`, `tools/`, `llm/`, `storage/`, `config/`, `core/` | Immutable evidence ledger, read-only tool registry, LLM client with inference cache, SQLite database, HTTP client with retries, and configuration loaders. |

---

## 4. The 12 Stages of Execution

When a scan begins, SC Guardian processes the target through 12 deterministic stages:

```
[1. Ingest] ──▶ [2. Lockfiles] ──▶ [3. SBOM] ──────────▶ [4. Fusion]
                                                              │
[8. Investigate] ◀── [7. Reachability] ◀── [6. Detect] ◀── [5. Graph]
      │
      ▼
[9. Risk Model] ──▶ [10. Remediate] ──▶ [11. Gate/Audit] ──▶ [12. Monitor]
```

### Stage 1: Safe Ingestion & Discovery (`ReconAgent`)
- Accepts a public GitHub URL.
- Validates the URL against strict security patterns (rejects command injections, private host redirects, credentials in URLs).
- Executes a safe, shallow clone (`--depth 50`, `--no-single-branch`, no git hooks, no submodules) into an isolated temporary workspace.
- Detects project languages, manifests (`package.json`, `pom.xml`, `requirements.txt`), Dockerfiles, and CI workflows.

### Stage 2: Authoritative Lockfile Parsing
- Parses lockfiles (`package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`, `poetry.lock`, `Pipfile.lock`, `go.sum`, `Cargo.lock`).
- **Core Principle**: Lockfiles outrank manifests because lockfiles represent the exact, pinned versions that run in production.

### Stage 3: SBOM Generation & Normalization (`SbomSpecialist`)
- Generates an industry-standard **CycloneDX 1.5 JSON** Software Bill of Materials.
- Employs a multi-tier fallback: **Syft** $\to$ **Trivy** $\to$ **Native Built-in Engine**.
- If external tools are not installed, the zero-dependency built-in engine guarantees a valid SBOM.
- Normalizes all scanner formats into a unified `Component` model with canonical package URLs (`purl`).

### Stage 4: Metadata Fusion & Integrity Verification
- Enriches components with authoritative data from public package registries (deps.dev, npm, PyPI, crates.io, Maven Central, Go checksum DB).
- **Digest Verification**: Compares the cryptographic SHA/SRI hash recorded in the developer's lockfile against the registry's published hash.
- Flags mismatches (`PKG-INT`), which can indicate compromised internal mirrors or tampered dependencies.

### Stage 5: Dependency Graph Construction (`GraphSpecialist`)
- Constructs a directed acyclic graph (DAG) using **NetworkX**.
- Edges follow the semantics: `Parent -> Child` (*"Parent depends on Child"*).
- Distinguishes **Direct Dependencies** (explicitly declared by developers) from **Transitive Dependencies** (sub-packages pulled in automatically).
- Calculates graph metrics: shortest distance from service roots, node degree, and blast radius.

### Stage 6: Dual-Track Detection (Vulnerabilities & Pipeline Threats)
- **Track A (Known Vulnerabilities)**: Queries Google's **OSV.dev** database using high-throughput batch requests. Enriches findings with CVSS metrics from **NVD** and active exploitation flags from **CISA KEV**.
- **Track B (Multi-CI Platform & Container Image Security)**:
  - *Multi-CI Platform Adapters*: Static, zero-code-execution security analysis across **GitHub Actions**, **GitLab CI/CD**, **Jenkins**, **CircleCI**, and **Azure Pipelines** via `src/pipeline_analysis/ci_adapters/`. Evaluates platform-specific security rules (unpinned actions/orbs/images, script injection, unpinned runner tokens, privileged DinD, and committed secrets).
  - *CI-to-Container Bridge*: Discovers container build directives (`docker build`, `kaniko`, `buildah`, `Docker@2`) in CI pipelines and links them to local Dockerfiles.
  - *Opt-In Trivy Container Image Scanner*: When enabled (`CONTAINER_SCAN_ENABLED=true`), scans container images using **Trivy** in an isolated, failure-resilient subprocess. Distinguishes OS-level packages (Debian/Alpine/RPM) from application runtime packages with layer provenance, unified under `asset_type: "container_image"`.
  - *Typosquatting Detection*: Uses **RapidFuzz** to compare package names against the top 10,000 most popular libraries to detect malicious lookalikes (e.g., `reqeusts` vs `requests`).

### Stage 7: AST & Regex Reachability Analysis
- Inspects the application's actual source code (`.py`, `.js`, `.ts`, `.java`, `.go`) using regex and AST import parsers.
- Classifies each dependency's usage and codebase influence:
  - `used_by_app`: The application directly imports the package.
    - *Heavy Usage*: Imported across $\ge 5$ files or $\ge 15\%$ of codebase (elevates Medium CVSS to High / P1).
    - *Moderate Usage*: Imported across $2-4$ files.
    - *Single Import*: Imported in $1$ file.
  - `reachable_via_dependency`: An imported direct dependency brings this transitive package in.
  - `used_in_tests_only`: The package is only referenced in test files or mock directories (capped at Medium).
  - `not_imported`: No code in the repository references this package (deprioritized; capped at Medium unless CISA KEV).

### Stage 8: Evidence-Gated Investigation (`InvestigatorAgent`)
- Investigates each vulnerability using bounded read-only tools (`find_imports`, `dependency_path`, `advisory_facts`, `read_snippet`).
- Emits a structured verdict: `exploitable_likely`, `reachable`, `possibly_reachable`, `test_only`, or `no_import_evidence`.
- Computes **Prioritization Shift**: Identifies when a vulnerability is *elevated* due to heavy codebase influence or *deprioritized* due to absence of runtime imports.
- **Never outputs "safe"**: Absence of evidence is not evidence of absence; dormant code can still be invoked dynamically.

### Stage 9: Contextual Risk Scoring (P0–P3 Priority Model)
- Moves beyond generic CVSS scores by incorporating execution context and codebase influence:
  - **P0 (Immediate Hazard)**: Known exploited in wild (CISA KEV) + imported by application code, or High risk with heavy production codebase blast radius.
  - **P1 (High Priority)**: Critical/High severity reachable in production code, or Medium severity with heavy production codebase influence ($\ge 5$ app files).
  - **P2 (Moderate Risk)**: Standard Medium severity, or deprioritized findings (Critical/High CVSS with no application imports or test-only scope).
  - **P3 (Informational / Low)**: Low severity, unconfirmed ranges, or unimported low-impact tooling.

### Stage 10: Remediation Planning, Reachability Impact & What-If Simulation (`RemediationAgent`)
- Finds the safest fix: direct parent bumps, minimal version increments, or override/resolution pins, ranked by **reachability-weighted urgency**.
- **Code Reachability Impact Analysis**: Evaluates how suggested version upgrades affect application imports, submodules, and call surfaces, outputting a reachability preservation score.
- **5-Tier Verification Matrix**:
  - *Tier 1*: Patch applicability check (`git apply --check`).
  - *Tier 2*: Lockfile coherence & update hint generation.
  - *Tier 3*: In-memory what-if dependency tree rescan (`OsvClient`).
  - *Tier 4*: Opt-in hardened Docker sandbox build & test execution (`--network none`, `--cap-drop ALL`).
  - *Tier 5*: Security regression gate (ensures zero new HIGH/CRITICAL CVEs introduced).

### Stage 11: Governed PR Delivery & Policy Gate
- **Interactive Remediation Agent Prompt**: Asks the user: *"Are you willing to commit these changes to the repository by creating a pull request?"*
- **Repository PR Template Conformance**: Automatically discovers `.github/pull_request_template.md` and populates its sections and checkboxes; falls back to a standardized enterprise security format if absent.
- **Governed Branch & Commit**: With user consent, safely creates an isolated branch (`remediation/fix-<pkg>-<version>`), stages the manifest patch, commits with a conventional commit message, and outputs GitHub CLI (`gh pr create`) dispatch commands.
- Evaluates policy-as-code (`policies/default.yaml`, `strict.yaml`) and exports **SARIF 2.1.0** and **CycloneDX VEX** reports.

### Stage 12: Continuous Monitoring & Memory
- Watches scanned inventories over time.
- Re-queries threat databases to alert developers when a previously clean dependency has a newly published zero-day or is added to CISA KEV.

---

## 5. The Agentic AI Layer

### Why Agentic AI instead of Traditional Static Scanners?
Traditional scanners act as simple search engines: they match strings in a lockfile against a database and dump a CSV of 500 CVEs on developers. This results in alert fatigue and ignored warnings.

SC Guardian uses **agentic workflow patterns**:
* **Autonomous Investigation**: When an agent detects a high-severity CVE, it doesn't stop. It dispatches tools to trace the import tree, inspect the source files, and test if the vulnerable function is actually reachable.
* **Specialist Division of Labor**: Different agents own distinct responsibilities (Graph Specialist, Threat Agent, Investigator, Remediation Planner), coordinated by a central Supervisor.
* **Self-Contained Error Resilience**: If one agent encounters a network timeout or unexpected file format, it isolates the failure, records an error limitation, and allows the remaining agents to complete their work.

### Dual-Execution Architecture: Deterministic Rules vs LLM

```
                     ┌────────────────────────────────┐
                     │    Finding Needs Assessment    │
                     └───────────────┬────────────────┘
                                     │
                 ┌───────────────────┴───────────────────┐
                 ▼                                       ▼
    ┌──────────────────────────┐            ┌──────────────────────────┐
    │ Deterministic Rule Engine│            │   LLM-Augmented Planner  │
    │  (Default - Always Runs) │            │     (Optional / Opt-in)  │
    │                          │            │                          │
    │ • Hardcoded rule matrix  │            │ • Multi-turn tool calling│
    │ • Exact evidence mapping │            │ • Natural language logic │
    │ • Zero API cost          │            │ • Requires LLM_API_KEY   │
    │ • 100% reproducible      │            │ • Groq / Gemini / Claude │
    └────────────┬─────────────┘            └────────────┬─────────────┘
                 │                                       │
                 │                                       ▼
                 │                          ┌──────────────────────────┐
                 │                          │   THE GROUNDING GATE     │
                 │                          │                          │
                 │                          │ • Validates evidence IDs │
                 │                          │ • Checks CVE consistency │
                 │                          │ • Blocks hallucinations  │
                 │                          └────────────┬─────────────┘
                 │                                       │
                 ▼                                       ▼
          ┌─────────────────────────────────────────────────────┐
          │                  VERIFIED VERDICT                   │
          │    Recorded with audit trail & evidence links       │
          └─────────────────────────────────────────────────────┘
```

1. **Deterministic Rule Engine (Default)**:
   - Always runs first.
   - Evaluates a rigorous decision table based on real evidence: import status, KEV status, EPSS probability, CVSS score, and dependency depth.
   - Guarantee: Works completely offline with 0 external API calls and 0 hallucination risk.

2. **LLM-Augmented Planner (Optional)**:
   - Enabled when `LLM_API_KEY` is present in `.env`.
   - The LLM can use read-only tools (`find_imports`, `advisory_facts`, `dependency_path`) in an interactive reasoning loop to investigate complex, ambiguous findings.

3. **The Grounding Gate (Anti-Hallucination Shield)**:
   - An LLM proposal is **never trusted blindly**. It must pass the strict `guard()` function:
     - Must cite valid, existing `evidence_id` tokens (e.g. `reachability:npm:minimist#d35595`).
     - Must not invent advisory IDs or reference CVEs not present in the finding.
     - Must not claim "no import evidence" if hard evidence shows the package is imported.
     - Must not claim "exploitable_likely" without CISA KEV or EPSS support.
   - Any LLM response that fails these tests is **instantly rejected**, logged in the audit trail, and replaced with the deterministic rule verdict.

---

## 6. Storage, Caching & Performance Architecture

SC Guardian is engineered for speed, low memory overhead, and resilience against API rate limits.

### Multi-Tier Caching Hierarchy

```
┌────────────────────────────────────────────────────────────────────────┐
│ 1. Streamlit In-Memory Cache (@st.cache_data)                          │
│    • Cached dependency graph JSON payloads                             │
│    • Cached database queries and recent scan lists                     │
├────────────────────────────────────────────────────────────────────────┤
│ 2. LLM Inference Response Cache (_INFERENCE_CACHE)                     │
│    • Thread-safe memory cache keyed by SHA-256(prompt + model)         │
│    • Instant 0.00s replay for repeated investigation prompts           │
├────────────────────────────────────────────────────────────────────────┤
│ 3. Persistent SQLite Cache Table (data/scanner.db)                     │
│    • OSV query batch results (TTL: 12 hours)                           │
│    • EPSS exploit probabilities (TTL: 24 hours)                        │
│    • Registry package metadata & digests (TTL: 24 hours)               │
│    • Automatic FIFO pruning (cleans records > 120 days or > 2M rows)   │
├────────────────────────────────────────────────────────────────────────┤
│ 4. Scan Result Cache                                                   │
│    • Skips re-scanning unchanged repositories if the same commit SHA   │
│      was scanned within 24 hours with identical options.               │
└────────────────────────────────────────────────────────────────────────┘
```

---

## 7. Security & Isolation Boundaries

Because SC Guardian analyzes potentially untrusted third-party repositories, it enforces military-grade boundaries:

1. **Subprocess Isolation**: Every internal tool execution uses `subprocess.run(shell=False)` with explicit argument lists and scrubbed environments. API keys and host environment secrets are never passed to child processes.
2. **Secret Redaction**: All outputs, logs, error messages, and LLM prompts are passed through regular expression filters (`redact()`) to strip out API keys, tokens, and private keys.
3. **Confined File Access**: Scanners are confined to the temporary workspace directory. Symlinks pointing outside the workspace and directory traversals (`../`) are blocked.
4. **Hardened Docker Sandbox (Opt-in)**:
   - When validating a remediation patch, Docker runs with:
     - `--network none` (test phase runs with all external networking severed).
     - `--cap-drop ALL` (drops all Linux root capabilities).
     - `--security-opt no-new-privileges` (prevents privilege escalation).
     - Memory limited to 2 GB, CPU limited to 2 cores, maximum 512 PIDs.

---

## 8. Summary Checklist

| Capability | SC Guardian Implementation |
|---|---|
| **Ecosystem Coverage** | npm, PyPI, Maven, Go, Cargo, Composer, NuGet, RubyGems, Docker, GitHub Actions |
| **SBOM Standard** | CycloneDX 1.5 JSON with full metadata fusion & digest verification |
| **Vulnerability Sources** | OSV.dev, NVD (CVSS v3/v2), CISA KEV, EPSS (FIRST.org) |
| **AI Architecture** | Multi-Agent LangGraph with Supervisor, Specialist Agents, and Grounding Gate |
| **Execution Safety** | Static analysis only; opt-in Docker sandbox with `--network none` |
| **Performance** | Multi-tier TTL caching, debounced vis-network physics, parallel OSV batching |
