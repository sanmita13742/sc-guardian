# Forensic Audit Report: Contextual Vulnerability Risk Scoring Engine

**Document:** `docs/audit/contextual-risk-scoring-v2-audit.md`  
**Status:** Complete Forensic Audit  
**Author:** SC Guardian Core Engineering  
**Target:** Implementation of Contextual Vulnerability Risk Scoring v2.0  
**Scope:** Risk engine, reachability analysis, production context detection, function-level impact evaluation, evidence management, and Streamlit presentation.

> **Status — implemented.** This audit preceded the contextual risk model that now runs in `src/risk_analysis/`; the current definition is in [`docs/RISK_SCORING.md`](../RISK_SCORING.md). The standalone *Risk & Explainability* page described below was later removed: per-finding risk details now live on **Vulnerability Findings → Risk breakdown**. Kept as design history.

---

## Executive Summary

This forensic audit evaluates SC Guardian's current vulnerability risk assessment pipeline in preparation for transitioning to the **Contextual Vulnerability Risk Scoring v2.0** model:

$$R = 0.15C + 0.20A + 0.35P + 0.30I$$

SC Guardian currently utilizes a deterministic, additive point-scoring system (Rules Version 2.1) combining CVSS severity, CISA KEV exploitation, dependency exposure, EPSS statistical probabilities, and coarse package-level import counts into a single aggregated score (0–100+).

While the existing system successfully separates raw advisory CVSS from repository-specific risk and provides transparent factor breakdowns, it exhibits critical architectural limitations:
1. **Ad-Hoc Additive Arithmetic:** CVSS, threat intelligence, and import counts are mixed additively rather than normalized across orthogonal dimensions.
2. **Coarse Reachability:** Reachability is package-level and import-level only. It does not map vulnerable symbols or functions to actual application call-sites.
3. **Absence of Production Context:** Production reachability is inferred solely through negative test-path filtering (`_is_test(rel) == False`), ignoring runtime entry points, Docker build artifacts, and CI deployment targets.
4. **Absence of Function-Level Impact Analysis:** The system does not analyze function criticality, data sensitivity, privilege boundaries, downstream impact, or exposure.
5. **Coupling of Threat Intelligence:** Active exploitation signals (CISA KEV, EPSS) are mixed directly into the base risk score rather than acting as independent prioritization and escalation dimensions.

---

## 1. Current Risk Scoring Implementation and Rules

### 1.1 Implementation Architecture
- **Primary Modules:**
  - `src/risk_analysis/risk_scorer.py`: Contains `score_vulnerability()`, `label_for()`, `_cap()`, and `priority_for()`.
  - `src/risk_analysis/risk_rules.py`: Defines `DEFAULT_RULES` (version `"2.1"`), containing raw points for severity, KEV, exposure, EPSS, and reachability tiers.
  - `src/risk_analysis/finding_correlator.py`: Orchestrates multi-finding aggregation across vulnerabilities, typosquatting candidates, and suspicious lockfile changes.

### 1.2 Scoring Logic & Weights
Currently, `score_vulnerability()` computes an unbounded additive point sum:
- **CVSS Severity Points:** CRITICAL: 55, HIGH: 40, MEDIUM: 22, LOW: 8, UNAVAILABLE: 12.
- **Threat Intelligence:**
  - CISA KEV presence: +30 points (+5 points for known ransomware campaigns).
  - EPSS probabilities: $\ge 0.5 \rightarrow +20$, $\ge 0.1 \rightarrow +10$, $\ge 0.01 \rightarrow +3$.
- **Dependency Topology:**
  - Direct dependency: +8 points; Direct inferred: +6 points; Transitive: 0 points.
  - Multiple application roots: +5 points.
  - No fixed version recorded: +5 points.
  - Development-only dependency: -10 points.
- **Reachability Modifiers:**
  - Heavy application usage ($\ge 5$ files or $\ge 15\%$ codebase): +35 points.
  - Moderate application usage (2–4 files): +20 points.
  - Single application import (1 file): +12 points.
  - Transitive via heavy root: +18 points; Transitive standard: +8 points.
  - Tests only: -10 points (with label capped at `MEDIUM`).
  - Not imported: -25 points (with label capped at `MEDIUM`).

### 1.3 Label Thresholds and Priority
- **Thresholds:** CRITICAL $\ge 70$, HIGH $\ge 45$, MEDIUM $\ge 25$, LOW $\ge 10$, otherwise INFORMATIONAL.
- **Priorities:**
  - **P0:** CRITICAL label OR (KEV + app import) OR (HIGH label + heavy production usage).
  - **P1:** HIGH label OR (MEDIUM label + heavy production usage).
  - **P2:** MEDIUM label OR deprioritized unimported/test-only findings.
  - **P3:** LOW or INFORMATIONAL.

### 1.4 Identified Flaws in Current Scoring
- **Dimension Entanglement:** The score conflates technical severity ($C$), exploit probability (EPSS), active exploitation (KEV), and code presence ($A$).
- **Unbounded Scaling:** Adding all modifiers can push raw points over 130 before thresholding.
- **Negative Penalties Masking Risk:** Subtracting 25 points for `not_imported` risks masking an intrinsically critical vulnerability as low without verifying true production unreachability.

---

## 2. Reachability Analysis Capabilities and Limitations

### 2.1 Current Capabilities (`src/reachability/scanners.py`)
- **Single-Pass Source Indexing:** `SourceIndex` indexes imports across 8 languages: Python (AST + regex fallback), JavaScript/TypeScript (regex), Java (regex), Go (AST/regex), Rust, PHP, C#, and Ruby.
- **Test vs. App Segregation:** Categorizes files into test code vs. application code using directory patterns (`/tests/`, `/__tests__/`, `/spec/`, `/cypress/`, `/fixtures/`) and filename patterns (`test_*.py`, `*_test.go`, `*.spec.ts`).
- **Density & Influence Metrics:** Calculates `app_files`, `test_files`, `import_ratio`, and assigns influence tiers:
  - `heavy`: $\ge 5$ app files or $\ge 15\%$ of codebase files.
  - `moderate`: 2–4 app files.
  - `light`: 1 app file.
  - `test_only`: 0 app files, $>0$ test files.
  - `not_imported`: 0 files.

### 2.2 Critical Limitations
- **Package-Level Only:** The scanner identifies that `requests` or `lodash` was imported, but has no knowledge of which specific function or class is invoked (`requests.get()` vs `requests.post()` vs `lodash.template()`).
- **No Vulnerable Symbol Cross-Referencing:** Advisories frequently identify affected functions/methods (e.g., `set_attribute`, `parse_xml`, `verify_token`), but the scanner does not extract or match these symbols against AST call nodes.
- **Dynamic Usage Ignored:** Dynamic imports, reflection, dependency injection containers, and CLI/entry-point invocations are marked as `not_imported`, risking false-negative unreachability claims.

---

## 3. Production Context Detection

### 3.1 Current Status
**Production context detection is currently non-existent.**
- The system currently treats any file where `_is_test(rel) == False` as "application/production" code.
- There is no distinction between:
  - Core production serving paths (HTTP endpoints, API routes, message queue consumers, background daemons).
  - Developer tooling, build scripts (`scripts/`, `tools/`, `tasks/`), documentation generators, and local benchmark suites.
  - Docker container entry points (`ENTRYPOINT`, `CMD` in Dockerfiles).
  - CI/CD deployment jobs (e.g., jobs targeting `production`, `release`, `deploy`, `k8s`).

### 3.2 Available Foundations in Codebase
- `src/pipeline_analysis/dockerfile.py`: Parses Dockerfiles, identifying base images, exposed ports, and commands.
- `src/pipeline_analysis/ci_adapters/`: Inspects CI definitions across GitHub Actions, GitLab CI, Jenkins, CircleCI, and Azure Pipelines, capturing triggers, environments, and deployment commands.
- `src/core/repository_inspector.py`: Identifies framework layouts (FastAPI, Flask, Django, Express, Spring, Go Gin/Chi).
- **Gap:** These components operate in isolation and do not feed production context signals into the risk scoring engine.

---

## 4. Function-Level Application Impact Analysis

### 4.1 Current Status
**Function-level impact analysis is completely absent.**
- Finding assessments do not evaluate the role of the vulnerable functionality within the host application.
- All dependencies imported in application files are weighted purely by file count, regardless of whether they execute in an authentication gateway, a database ORM, or a non-critical string utility.

### 4.2 Requirements for v2.0
The v2.0 engine requires computing Dimension $I$ (0–100):
$$I = 0.25F + 0.25S + 0.20B + 0.20D + 0.10X$$
- **$F$ (Function Responsibility & Criticality):** Security-critical (auth, crypto, access control) = 100; Core business/transactional = 75; Supporting business = 50; Auxiliary/utility = 25; Non-critical = 10.
- **$S$ (Data Sensitivity):** PII, credentials, financial, session tokens = 100; Internal business data = 60; Public/untrusted data = 30; No direct data handling = 10.
- **$B$ (Privilege Boundary):** Crosses network trust boundary (unauthenticated ingress) = 100; Crosses process/privilege boundary = 70; Within same execution context = 30; Local/isolated context = 10.
- **$D$ (Downstream Application Impact):** Application failure/RCE/takeover = 100; Subsystem failure/data corruption = 70; Degraded non-critical service = 35; Negligible impact = 10.
- **$X$ (Production Execution Exposure):** Continuously running (web server loop, event consumer) = 100; Frequently executed = 70; Intermittent / on-demand = 40; Rare / administrative = 20; Not executed in prod = 0.

---

## 5. Evidence Management and Explainability Pipeline

### 5.1 Current Evidence Flow
- `src/risk_analysis/evidence_collector.py`: Collects structured facts into bundles (advisory, component, dependency, repository).
- `src/risk_analysis/evidence_normalizer.py`: Flattens bundles into indexed `facts` (`F001`, `F002`) and text corpora for grounding.
- `src/explainability/explanation_engine.py`: Generates human-readable explanations via templates or validated LLM generation.
- `src/explainability/explanation_validator.py`: Enforces strict grounding rules (e.g., rejecting claims of unreachability if evidence says unknown).

### 5.2 Required Extensions for v2.0
- Evidence bundles must record the specific inputs, calculations, and intermediate values for all 4 dimensions:
  - Dimension $C$: raw CVSS score, vector, version, source.
  - Dimension $A$: reachable status, confidence, matched symbols/call sites, app file locations.
  - Dimension $P$: production indicator evidence (entry point, Docker container, CI deploy target).
  - Dimension $I$: sub-factor scores ($F, S, B, D, X$) and cited code/context justifications.
- Any incomplete or missing evidence must be logged explicitly as `missing_evidence: ["dimension_P: no production deployment manifests identified"]` rather than silently defaulting to 0.

---

## 6. Streamlit Presentation and User Interaction

### 6.1 Current Risk Page (`src/ui/pages/risk_page.py`)
- Renders top-level metrics for risk label distribution (CRITICAL, HIGH, MEDIUM, LOW, INFORMATIONAL).
- Renders influence metrics: Elevated by Code Influence, Deprioritized (No Imports), Heavy Application Usage.
- Provides search and filters by Risk Level, Finding Type, and Code Influence.
- In finding expanders:
  - Displays headline, score, confidence, and prioritization flags.
  - Displays impact, how entered, remediation notes.
  - Displays additive "Scoring Factors" table (factor name, points, detail).

### 6.2 Required Modifications for v2.0
- **Formula & Dimension Breakdown:** Replace the additive point table with a clear 4-factor contextual breakdown ($C, A, P, I$) showing normalized scores, weights, weighted contributions, and the final combined score.
- **Missing Evidence Badges:** Clearly display when a finding's score is provisional due to missing reachability or production evidence.
- **Sub-Factor Inspection for Dimension $I$:** Allow expanding Dimension $I$ to see the $F, S, B, D, X$ sub-factor breakdown with contextual rationale.
- **Threat Intelligence Separation:** Present CISA KEV and EPSS as separate escalation/threat indicators alongside the contextual risk score rather than blending them into the mathematical formula.

---

## 7. Gap Analysis & Architecture Mapping

| Dimension / Requirement | Current Implementation (v2.1) | Target Implementation (v2.0 Model) | Gap Severity | Action Required |
|---|---|---|---|---|
| **Mathematical Model** | Additive point accumulation ($S = \sum p_i$) | Linear combination: $R = 0.15C + 0.20A + 0.35P + 0.30I$ | **High** | Implement `ContextualRiskCalculator` with configurable weights and strict 0–100 normalization. |
| **CVSS Severity ($C$)** | Coarse categorical points (55, 40, 22, 8) | Direct normalization: $C = 10 \times \text{CVSS}$ | **Medium** | Map numeric CVSS to 0–100 scale; preserve vector and source. |
| **App Reachability ($A$)** | Package-level import count tiers (+35, +20, +12, -10, -25) | Normalized scale: Confirmed=100, Potentially=60, Unreachable=0, Unknown=Unassessed | **High** | Map import evidence and symbol matches to normalized $A$; flag unknowns. |
| **Production Context ($P$)** | Non-test flag (`not _is_test(path)`) | Multi-signal production mapping: Confirmed prod=100, Strong=70, Prod inclusion=40, Dev/Test=0 | **Critical** | Build `ProductionContextAnalyzer` integrating entry points, Dockerfile artifacts, and CI deploy jobs. |
| **Function-Level Impact ($I$)** | Absent | Weighted formula: $I = 0.25F + 0.25S + 0.20B + 0.20D + 0.10X$ | **Critical** | Build `FunctionImpactAnalyzer` evaluating responsibility, data sensitivity, privilege boundaries, and exposure. |
| **Missing Evidence Policy** | Unassessed reachability treated as 0 points | Missing dimensions preserved as Unknown; provisional scoring and explicit audit flagging | **High** | Implement strict missing-evidence handling; enforce "Unknown is not zero". |
| **Threat Intelligence** | Blended into additive risk score (+30 KEV, +20 EPSS) | Independent prioritization and escalation layer ($P0-P3$) | **Medium** | Decouple KEV/EPSS from 4-factor equation; maintain as priority escalation triggers. |
| **Streamlit UI** | Additive points table | Interactive 4-dimension breakdown + $F,S,B,D,X$ sub-factor viewer + missing evidence badges | **Medium** | Update `src/ui/pages/risk_page.py`. |

---

## 8. Conclusion and Audit Sign-Off

The forensic audit confirms that SC Guardian possesses strong foundational assets (AST import indexing, CI/Dockerfile parsing, multi-ecosystem SBOMs, and evidence-grounded explainability), but lacks the mathematical rigor, production contextualization, and function-level evaluation mandated by the Contextual Vulnerability Risk Scoring v2.0 specification.

The system is cleared to proceed to **Stage B: Implementation Plan**, detailing the engineering architecture, data structures, and phased delivery plan.
