# Implementation progress

This file records what was **actually built and executed**. Everything marked "verified" was run; anything not run is listed under limitations.

Branch `streamlit-app` (base commit `d2de3d02986fe6cd15cab7659417f8343cd79e07`). `main` / `origin/main` untouched (`8c64d3c`). Work was committed progressively on this branch only.

## Environment (Phase 0) — verified

* Python 3.11.9 in `.venv/` (Python 3.15 was avoided for wheel compatibility). Dependencies pinned in `requirements-lock.txt` (ranges in `requirements.txt`).
* Syft 1.57.2 installed user-level (`~/bin/syft`) via the official installer; `scripts/verify_environment.py` scans a test directory, generates CycloneDX JSON (spec 1.7) and parses/validates it → all required checks pass.
* Syft directory scans on Windows need a native path (a Unix `/tmp` path from Git Bash is not resolved by the Windows binary) — the runner always passes resolved absolute paths.

## Phases

| Phase | Deliverable | Status | Evidence |
|---|---|---|---|
| 1 | URL validator, safe clone, inspector (languages/ecosystems/frameworks/services/Docker/CI) | done | `tests/unit/test_core.py`; real clone test; UI form test |
| 2 | Syft runner, CycloneDX validation, 7-ecosystem lockfile parsers, quality analyzer, registry enricher | done | `test_sbom.py`, `test_lockfile_parsers.py`, real Syft tests |
| 3 | NetworkX graph, validation, per-root tracing, impact, JSON/Cytoscape export | done | `test_graph.py` (incl. real Syft graph for the monorepo) |
| 4 | OSV batch + advisories, version matcher, CVSS v3, NVD, KEV, correlator, remediation | done | `test_version_matcher.py`, `test_vulnerability.py`, live OSV integration |
| 5 | Typosquatting + modified-lockfile detectors | done | `test_suspicious.py` (real temporary Git repos) |
| 6 | Evidence, deterministic risk, correlation, grounded explanations | done | `test_risk_explain.py` |
| — | SQLite storage + cache, orchestrator, exports, reports | done | integration tests |
| — | Streamlit dashboard (7 pages), Cytoscape graph | done (see limitation on visual check) | AppTest smoke tests + form submission test + server start |

## Bugs found by tests and fixed (regression tests exist)

* Syft excludes npm dev dependencies by default → 711 "lockfile packages missing from SBOM" on NodeGoat. Now run with `javascript.include-dev-dependencies=true`; lockfile↔SBOM mismatch is 0.
* Duplicate findings for the same package installed at several `node_modules` paths → merged per (package@version, service) with all paths kept.
* 30 components unreachable from any root (dependency cycles without recorded entry) → entry components attached with flagged `inferred-no-parent` edges.
* Yarn Berry dependency names kept a stray quote on scoped packages.
* Diff excerpts were empty when only an integrity line changed → hunk-aware excerpts.
* KEV/NVD reported `ok` when never queried → `not_queried`.
* `st.dataframe(height=None)` rejected by Streamlit 1.67 (caught by AppTest).
* Offline typosquat matches on legitimate packages (`object.assign`, `safer-buffer`, `through`) were labelled "high" → uncorroborated strength capped at "low"; packages added to the reference list.

## Test results

Final run on Windows 11, Python 3.11.9, Syft 1.57.2, live network (OSV, NVD, CISA KEV, GitHub):

| Suite | Tests | Result |
|---|---|---|
| Unit (`tests/unit`, offline, mocked APIs, real temporary Git repos) | 0 | all passed |
| Integration + UI (`tests/integration`: real Syft, live OSV/KEV/GitHub, AppTest pages, UI form submission) | 0 | all passed |
| **Total** | **139** | **139 passed, 0 failed, 0 skipped** (7 min 33 s on a cold cache) |

Line coverage over the application packages: **91 %** (3 763 statements). Lowest: `reporting/sbom_exporter.py` 44 % (only the enrichment-overlay helper is partly exercised),
`sbom/syft_runner.py` 78 %, `sbom/package_extractors/others.py` 79 % (Gradle/csproj edge paths), `suspicious_changes/popular_packages.py` 79 %.
Critical logic is higher: `version_matcher` 91 %, `vulnerability_correlator` 95 %, `graph_builder` 99 %, `risk_scorer` 98 %, `url_validator` 100 %.

Commands: `python -m pytest tests/unit` · `python -m pytest tests/integration` · `python scripts/verify_environment.py`.

## Integration runs (recorded)

| Target | Revision | SBOM | Graph | OSV | Findings | Sample dependency path |
|---|---|---|---|---|---|---|
| `nodegoat/` (vendored OWASP NodeGoat) | enclosing repo HEAD (subdirectory scan) | Syft, valid, 1230 components | 1231 nodes / 4865 edges, 4 cycle groups handled | ok | 311 vulnerability findings (21 direct, 290 transitive) | `nodegoat (service) → selenium-webdriver@2.53.3 → adm-zip@0.4.4` |
| `tests/fixtures/monorepo` + synthetic 2-commit Git history | exact commit SHA | Syft, valid, 15 components | 3 service roots, no cross-service edges | ok | 33 vulnerabilities, 1 typosquat (`reqeusts`≈`requests`), 2 lockfile findings (integrity change on `lodash`, git-sourced `left-pad-ng`) | `frontend (service) → mkdirp@0.5.1 → minimist@0.0.8` (transitive) |
| Real clone of `github.com/OWASP/NodeGoat` @ `c5cb68a` (via script and via the UI form) | `c5cb68a7084e4ae7dcc60e6a98768720a81841e8` (branch `master`, shallow) | Syft, 1230 components | as above | ok; NVD 20 CVEs enriched (cap), KEV catalog 1790 entries, 0 KEV hits | 311 vulnerabilities; 5 commits compared with parents, no lockfile changes | same |

Synthetic fixtures are clearly named (`reqeusts` is a deliberate typo-like name; the tampered lockfile is created by the test). No vulnerability was invented: all vulnerability findings come from live OSV responses.

## Acceptance criteria

All criteria in the master prompt were exercised; see the evidence in the table above and in `tests/`. Items with caveats:

* **LLM explanations**: implemented and verified with a mocked LLM (invented IDs/CVSS/claims are rejected per section; failures fall back to templates). **Not exercised against the live Anthropic API** (no key available). The deterministic path is the default and fully tested.
* **Dashboard**: all pages render without exceptions for real stored scans and for the empty state (AppTest), the form submission workflow and invalid-URL rejection work, and the server starts and serves. The Cytoscape canvas needs a real browser and CDN access; its rendering was **not visually inspected** in this environment.
* **NVD**: verified live (20 CVEs enriched, 33 findings updated). Without an API key only 20 CVEs per scan are requested (documented, reported as `skipped_over_cap`).

## Known limitations

* Public GitHub only; clone depth 50 means older commits/baselines may be unavailable (reported as `insufficient_baseline`, never guessed).
* Java: Syft/pom parsing yields declared dependencies; transitive Maven resolution is not performed, so Java graphs are shallow. Maven version ordering approximates `ComparableVersion` (sublists flattened). Packagist/NuGet/RubyGems use a loose numeric ordering.
* OSV `GIT` ranges cannot be evaluated → `unknown` (never counted as confirmed). CVSS v4 vectors are kept but not scored locally (NVD may provide a score).
* Reachability is not assessed (always "unknown"); fixes are advisory-recommended versions, parent compatibility is explicitly *not verified*.
* Typosquatting reference lists are small curated lists (~60–130 names for npm/PyPI, fewer elsewhere); registry corroboration exists for npm and PyPI only. Typosquat "established package" suppression relies on live registry data.
* Lockfile direct/transitive flags need the sibling manifest for npm v1, yarn, poetry, composer; pnpm v9 snapshot handling and Yarn Berry are basic.
* Docker/compose files and CI/CD pipelines are only detected and recorded; images are never built or scanned.
* Syft's dev-dependency inclusion is only configured for JavaScript; other ecosystems use Syft defaults.
* Tested on Windows 11 only. Syft-dependent tests skip when Syft is absent; live tests skip when the network is unreachable.
* NodeGoat is intentionally vulnerable and ships a sample `artifacts/cert/server.key` (pre-existing, not part of the scanner).

## Remaining blockers

None for the delivered scope. Optional integrations not exercised: live LLM explanations, NVD with an API key.
