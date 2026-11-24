# Engineering Implementation Plan: Contextual Vulnerability Risk Scoring v2.0

**Document:** `docs/implementation/contextual-risk-scoring-v2-plan.md`  
**Status:** Approved Implementation Architecture  
**Author:** SC Guardian Core Engineering  
**Version:** 2.0.0  
**Target:** Implementation across `src/risk_analysis/`, `src/reachability/`, and `src/ui/pages/risk_page.py`

> **Status — implemented.** The model described here is what runs today (rules version `2.2-contextual`); the current definition is in [`docs/RISK_SCORING.md`](../RISK_SCORING.md). Phase 6 (a separate *Risk & Explainability* page, `risk_page.py`) was later replaced by the **Risk breakdown** tab on *Vulnerability Findings*. Kept as design history.

---

## 1. Architectural Architecture & Core Formula

The target contextual risk engine evaluates vulnerabilities across four orthogonal dimensions:

$$R = w_C \cdot C + w_A \cdot A + w_P \cdot P + w_I \cdot I$$

Where default weights are:
- $w_C = 0.15$ (CVSS intrinsic technical severity, 15%)
- $w_A = 0.20$ (Application code reachability, 20%)
- $w_P = 0.35$ (Production execution reachability, 35%)
- $w_I = 0.30$ (Function-level application impact, 30%)
- **Constraint:** $\sum w_i = 1.0$ and all $C, A, P, I \in [0, 100]$.

### 1.1 Dimension Definitions & Value Domains

1. **$C$ — CVSS Severity (15%):**
   - $C = 10 \times \text{CVSS}$ (e.g. CVSS 8.6 becomes 86.0).
   - If numeric CVSS is unavailable, estimate from severity label (CRITICAL=90, HIGH=75, MEDIUM=50, LOW=25) and flag as estimated.
   - Original CVSS score, vector, and source must be preserved.

2. **$A$ — Application Code Reachability (20%):**
   - **Confirmed Reachable (100):** Vulnerable symbol or direct package imported in verified application code paths.
   - **Potentially Reachable (60):** Package imported, but specific vulnerable function invocation is unverified, or reachable transitively via an application root dependency.
   - **Unreachable with Evidence (0):** Rigorously verified that package is completely unimported and not dynamically loaded in application code.
   - **Unknown / Unassessed:** State preserved; missing-evidence policy triggered (never masked as 0).

3. **$P$ — Production Code Reachability (35%):**
   - **Confirmed Production Execution Path (100):** Imported in a validated production entry point (HTTP route, worker daemon, main service entry point) or packaged in a production container artifact.
   - **Strong Production Indicators (70):** Located in non-test application service directories, referenced in production Docker stages, or part of production CI build artifacts.
   - **Production Inclusion without Verified Execution (40):** Included in production dependency manifests (lockfiles) without direct entry point tracing.
   - **Dev / Test Only (0):** Exclusively confined to test suites, mock fixtures, or local development tooling.
   - **Unknown / Unassessed:** State preserved; missing-evidence policy triggered.

4. **$I$ — Function-Level Application Impact (30%):**
   $$I = 0.25F + 0.25S + 0.20B + 0.20D + 0.10X$$
   - **$F$ — Function Responsibility & Criticality (0–100):** Security-critical (auth, crypto, access control) = 100; Core transactional = 75; Supporting business = 50; Auxiliary/utility = 25; Non-critical = 10.
   - **$S$ — Sensitivity of Data Handled (0–100):** PII, secrets, credentials, payment tokens = 100; Internal business state = 60; Public/untrusted data = 30; No direct data = 10.
   - **$B$ — Privilege-Boundary Significance (0–100):** Crosses external network trust boundary (unauthenticated ingress) = 100; Crosses process/privilege boundary = 70; Within same execution context = 30; Isolated local = 10.
   - **$D$ — Downstream Application Impact (0–100):** Full application failure / RCE / system takeover = 100; Subsystem outage / data corruption = 70; Degraded non-critical service = 35; Negligible impact = 10.
   - **$X$ — Production Execution Exposure (0–100):** Continuously running (web server loop, event consumer) = 100; Frequently executed = 70; Intermittent / on-demand = 40; Rare / administrative = 20; Dev/test only = 0.

---

## 2. Missing-Evidence Policy & Incomplete Data Handling

When evidence is incomplete:
1. **Never substitute zero for unknown.** An unassessed reachability state does not mean the vulnerability is safe.
2. **Provisional Score Calculation:**
   $$\text{Available Weights } W = \sum_{k \in \text{Available}} w_k$$
   $$\text{Provisional Score } R_{\text{prov}} = \frac{1}{W} \sum_{k \in \text{Available}} w_k \cdot S_k$$
3. **Explicit Audit Metadata:**
   Every assessment record must contain:
   ```json
   {
     "is_provisional": true,
     "missing_dimensions": ["P", "I"],
     "missing_evidence_reasons": ["Production deployment context could not be identified from manifests"],
     "provisional_score": 68.5,
     "confidence_penalty": -20
   }
   ```
4. **Threat Intelligence Separation:**
   - Active exploitation in CISA KEV or high EPSS does **not** alter the mathematical 4-factor risk score.
   - Instead, it feeds the priority escalation engine:
     - **P0:** Contextual Risk $\ge 70$ OR (Active KEV + $A \ge 60$) OR (Contextual Risk $\ge 45$ + High Production Exposure $P \ge 70$).
     - **P1:** Contextual Risk $\ge 45$ OR (Contextual Risk $\ge 25$ + $P \ge 70$).
     - **P2:** Contextual Risk $\ge 25$ OR (Deprioritized high CVSS where $A=0$ or $P=0$).
     - **P3:** Contextual Risk $< 25$.

---

## 3. Phased Implementation Roadmap

### Phase 1: Contextual Scoring Foundation (`src/risk_analysis/contextual_scorer.py`)
- Define data structures for dimensions ($C, A, P, I$), sub-factors ($F, S, B, D, X$), and overall score.
- Implement `ContextualScorer` class with:
  - Configurable weights with runtime validation ($\sum w_i = 1.0$).
  - Strict input boundary clamping ($[0, 100]$).
  - Missing-evidence handler calculating provisional normalized scores.
  - Transparent calculation audit trails (recording raw values, normalized values, weights, and contributions).

### Phase 2: Application Reachability & Symbol Mapping (`src/reachability/`)
- Extend `src/reachability/scanners.py` to extract imported symbols (functions, classes, attributes) alongside package names.
- Implement `extract_vulnerable_symbols(advisory_text, advisory_id)` to parse known vulnerable functions from CVE/GHSA summaries.
- Implement `evaluate_app_reachability(package_name, ecosystem, symbols, source_index)` returning normalized $A \in [0, 100]$ and evidence details.

### Phase 3: Production Context Detection (`src/risk_analysis/production_context.py`)
- Create `ProductionContextAnalyzer` inspecting:
  - **Framework Entry Points:** FastAPI/Flask `@app.get/post`, Django `urls.py`, Express `app.use/get`, Spring `@RestController`, Go `http.HandleFunc`.
  - **Service Workers:** Celery tasks, Kafka/RabbitMQ consumers, background cron jobs.
  - **Container Packaging:** Dockerfile `ENTRYPOINT`, `CMD`, and multi-stage build copy targets.
  - **CI Deployment Signals:** CI jobs with `deploy`, `release`, `k8s`, `production` triggers.
- Return normalized $P \in [0, 100]$ with explicit production evidence chains.

### Phase 4: Function-Level Impact Evaluation (`src/risk_analysis/function_impact.py`)
- Create `FunctionImpactAnalyzer` assessing:
  - Code responsibility ($F$) from call site context and package taxonomy.
  - Data sensitivity ($S$) from variable names, parameter types, and module path patterns (auth, token, secret, cred, payment, user).
  - Privilege boundary ($B$) based on route exposure (public ingress vs internal helper).
  - Downstream impact ($D$) based on CWE classification (e.g. CWE-78/CWE-89/CWE-94 = 100, CWE-200 = 60, CWE-400 = 35).
  - Production exposure ($X$) correlating call sites with production entry points.
- Compute $I = 0.25F + 0.25S + 0.20B + 0.20D + 0.10X$.

### Phase 5: Risk Engine & Correlator Integration (`src/risk_analysis/risk_scorer.py`)
- Integrate `ContextualScorer`, `ProductionContextAnalyzer`, and `FunctionImpactAnalyzer` into `score_vulnerability()`.
- Maintain backward compatibility for pipeline and typosquatting findings while upgrading vulnerability assessment to v2.0.
- Update `correlate_findings()` in `src/risk_analysis/finding_correlator.py` to pass repository, source index, and CI/Docker context.

### Phase 6: Streamlit Risk & Explainability Page (`src/ui/pages/risk_page.py`)
- Display 4-factor metric cards ($C, A, P, I$) and the composite contextual risk score.
- Render interactive dimension breakdown tables displaying weights, raw scores, normalized scores, and contributions.
- Add expandable inspection for Dimension $I$ showing $F, S, B, D, X$ sub-factor details.
- Show "Provisional / Missing Evidence" warning badges with explicit explanations when evidence is incomplete.
- Highlight CISA KEV and EPSS as distinct threat intelligence signals outside the formula.

---

## 4. Verification and Validation Strategy

1. **Mathematical Invariant Tests:**
   - Weight normalization: Weights must sum to 1.0.
   - Value domain: All dimensional scores and the composite risk score must remain strictly within $[0, 100]$.
   - Unknown behavior: Missing evidence must trigger provisional status and must never default to 0.
   - Monotonicity: Increasing any dimension must monotonically increase or maintain the risk score.
2. **Benchmark Repository Scenarios:**
   - **Scenario 1 (High CVSS, Unused):** CVSS 9.8 in a dependency with $A=0$ (or unimported) resulting in deprioritized risk score and P2/P3 rating.
   - **Scenario 2 (Medium CVSS, Critical Production Auth):** CVSS 5.3 in an auth token parser with $A=100, P=100, I=90$ resulting in high contextual risk and P0/P1 escalation.
   - **Scenario 3 (Test-Only Dependency):** CVSS 8.5 in pytest/jest helper with $P=0$ resulting in low production risk.
   - **Scenario 4 (Incomplete Evidence):** Missing production context flags provisional assessment without masking risk.
