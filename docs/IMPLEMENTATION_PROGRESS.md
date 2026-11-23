# Implementation progress

What was built and **actually executed**. Branch `streamlit-app` (base `d2de3d02986fe6cd15cab7659417f8343cd79e07`); `main`/`origin/main` untouched; work committed progressively, no co-author trailers.

## Current layout

`nodegoat/` (demo target, separate) and `streamlit_app/` (the scanner). Test files were **removed at the owner's request**; they remain in Git history:
the last commit containing the 141-test suite is `d6a6c15` (`git show d6a6c15:streamlit_app/tests/...`, or `git checkout d6a6c15 -- streamlit_app/tests streamlit_app/pytest.ini` to restore them; they also need `pytest pytest-cov` installed).

## Delivered

| Area | Status |
|---|---|
| Safe ingestion: URL allow-list, shallow hook-less clone, size/time limits, cleanup | done |
| Static inspection: languages, ecosystems, frameworks, services, Docker/CI context | done |
| 7-ecosystem lockfile parsers; Syft CycloneDX; validation; quality assessment | done |
| NetworkX graph (bom-ref, per-root direct/transitive, provenance-labelled edges, cycles/dangling) | done |
| OSV matching with ecosystem-aware range validation; NVD; CISA KEV; SQLite cache | done |
| **Ground-truth verification**: second OSV route by PURL (`cross_verified`) + known-answer test (12/12, precision 1.0, recall 1.0 on live OSV) | done |
| **Source-package tracing**: each finding → lockfile record → graph path → direct dependency that introduces it; ranked "source packages" | done |
| Typosquatting and Git-history lockfile detectors | done |
| Deterministic risk rules, correlation, evidence-grounded explanations (templates; validated optional LLM) | done |
| **Multi-agent pipeline**: Supervisor + 8 specialist agents, 21 steps, weighted progress, decision trace, adaptive behaviours | done |
| Streamlit UI: live progress bar + activity log, SBOM viewer (raw CycloneDX), direct/transitive graph views, transitive severity alerts, Agent Activity page, reports | done |

## Verified (executed, results observed)

* Full pipeline on a **real GitHub clone of OWASP/NodeGoat** (`c5cb68a`, shallow): 62 s with warm cache; 1 229 packages, 311 confirmed findings (23 direct, 288 transitive), **311/311 independently reproduced** by the PURL route, 186 CRITICAL/HIGH transitive findings introduced by 29 direct dependencies (top: `cypress@3.3.1`, `grunt-retire@0.3.12`, `zaproxy@0.2.0`); workspace deleted afterwards.
* Multi-ecosystem monorepo fixture (npm + PyPI + Go) with a synthetic tampered-lockfile Git history: all detectors fired as expected (33 vulnerabilities, typosquat `reqeusts`, integrity-change + git-source lockfile findings).
* Known-answer test against live OSV: 12/12 (lodash, minimist, requests, flask, log4j-core, golang.org/x/text; patched versions not reported).
* UI: all 8 pages render for stored scans and for the empty state; the scan form (real URL → live progress → results) and invalid-URL rejection were driven through Streamlit's AppTest; the server was started and answered health checks.
* Before removal the suite was 141 tests (unit + integration + UI), all passing (one run had a transient GitHub "connection reset" in a clone test that passed on re-run), ~91 % line coverage.

## Bugs found by testing and fixed

Syft excluding npm dev dependencies (711 phantom "missing" packages) · duplicate findings for nested install paths · unrooted dependency cycles · Yarn Berry scoped names · empty diff excerpts ·
KEV/NVD reporting `ok` when never queried · `st.dataframe(height=None)` · offline typosquat matches labelled "high" · the application's *own* package being matched as a dependency (false-match risk and wrong "source package").

## Known limitations

* Public GitHub only; clone depth 50 → older baselines unavailable (reported as `insufficient_baseline`).
* Java: declared dependencies only (no transitive Maven resolution); Maven/Packagist/NuGet/RubyGems ordering approximated.
* OSV GIT-type ranges → `unknown`; CVSS v4 vectors kept but not scored locally.
* Reachability not assessed (always "unknown"); fix suggestions do not verify parent-version compatibility.
* Typosquatting: small curated reference list; registry checks for npm/PyPI only.
* Docker/CI files recorded only. Cytoscape needs CDN access in the browser and its canvas was **not visually inspected** here.
* Agents are rule-based; the optional LLM path (top-15 explanations) was only exercised with a mocked model.
* NVD without an API key: 20 CVEs per scan (the rest reported as `skipped_over_cap`).
* Developed/tested on Windows 11 only. The shared `.venv` lives at the repository root (git-ignored).
