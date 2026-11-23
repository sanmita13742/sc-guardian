# SC Guardian — Repository Supply Chain Security Scanner

A repository-centric **software supply-chain security scanner** delivered as a **Streamlit** app.
Given a public GitHub URL it clones the repository (safely, statically), detects languages / frameworks /
ecosystems, generates and quality-checks a CycloneDX SBOM, builds a dependency graph, correlates components
with known vulnerabilities, detects suspicious supply-chain changes, and presents evidence-backed findings.

This README is the project context and implementation blueprint. It is **not** a recreation of Snyk; it targets
two hackathon requirements:

- **A. Detect Vulnerabilities**
- **B. Detect Suspicious Changes** (MVP detectors: **typosquatting** and **modified lockfile**)

Guiding principle: *automate inventory generation, validate it, correlate it with vulnerability intelligence,
inspect suspicious dependency changes, and give explainable, evidence-backed findings.* Reliability, evidence and
accurate relationships matter more than a long list of half-working detectors.

---

## 1. Hackathon requirements

### A. Detect vulnerabilities

| Requirement | Expected functionality |
|---|---|
| Correlate components with known vulnerabilities | Match SBOM components against vulnerability databases |
| Capture CVE | Record CVE ids when available |
| Capture severity | LOW / MEDIUM / HIGH / CRITICAL |
| Capture available fixes | Fixed versions / remediation |
| Trace vulnerable transitive dependencies | Show path back to the source/root component |

Finding fields: vulnerability id, package, installed version, severity, CVSS (if available), fixed version (if
available), direct/transitive, dependency path (root → intermediate → vulnerable component).
(CVE-2024-1234 / CVSS 9.8 in the hackathon text are illustrative only.)

Rules:
1. Match on package identity + ecosystem + version, never name alone.
2. Use PURLs where available.
3. Validate affected ranges with ecosystem-appropriate version semantics (no lexicographic comparison).
4. Never report unknown / insufficiently identified packages as confirmed vulnerable.
5. Keep vulnerability source and retrieval timestamps.
6. A vulnerability may lack CVE / severity / fix — represent that honestly, never invent values.
7. Support direct and transitive findings; preserve all relevant dependency paths for shared components.

### B. Detect suspicious changes

**Detector 1 — Typosquatting.** Extract package names from manifests/lockfiles, normalise per ecosystem, compare to
popular packages in the same ecosystem (edit distance, e.g. RapidFuzz), add registry metadata as supporting signals.
Output: suspicious package, similar known package, similarity score, evidence. Similarity is *suspicious*, not
*malicious*.

**Detector 2 — Modified lockfile.** Compare a selected commit with its parent (or a chosen baseline) using Git
history and ecosystem-aware lockfile parsing. Detect added / removed / changed packages, version, resolved-source and
integrity-hash changes, and lockfile changes with no matching manifest change. Output: commit SHA, file, package,
previous/new value, change type, diff evidence and *why it is suspicious*. A lockfile change is not inherently
malicious; if history/baseline is unavailable, report the limitation instead of inventing a result.

Out of scope for the MVP: unsafe install scripts, untrusted images, CI/CD analysis.

---

## 2. Pipeline

```text
GitHub URL -> clone (isolated) -> inspect -> language/framework detection -> manifest/lockfile discovery
  -> Syft CycloneDX SBOM -> SBOM quality assessment -> NetworkX dependency graph
      -> vulnerability detection (OSV + NVD [+ CISA KEV])   \
      -> suspicious-change detection (typosquat, lockfile)   > unified risk correlation -> Streamlit dashboard -> reports
```

Users never generate an SBOM manually. Repository code is **never executed**.

## 3. Ingestion and generic detection

- Public GitHub URLs only (MVP). Validate URL, block local paths and non-HTTPS/GitHub schemes, clone into an
  isolated temp workspace with size/time limits, record URL, branch and exact commit SHA, clean up afterwards.
- Languages from extensions **plus** manifests/lockfiles/config (py, js/jsx, ts/tsx, java, go, rs, cs, php, rb …).
- Ecosystems/frameworks from `package.json`, `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`, `pyproject.toml`,
  `requirements.txt`, `poetry.lock`, `uv.lock`, `pom.xml`, `build.gradle`, `Cargo.toml/.lock`, `go.mod/.sum`,
  `composer.json`, `.csproj`.
- Monorepos supported: multiple frameworks/services per repo, no single-framework forcing.

## 4. SBOM

- **Syft** (https://oss.anchore.com/docs/) → **CycloneDX JSON**, invoked via a controlled subprocess (no shell):
  `syft dir:<repo> -o cyclonedx-json=<out>`. Capture exit status, stdout/stderr, duration, tool version, output path.
  A successful Syft run never implies a complete SBOM.
- Source/build SBOM and runtime/image SBOM are different scopes and are kept separate. Image scanning is optional.
- **Quality assessment** (own module) using lockfiles, Syft output and optional image scan: lockfile-only vs
  Syft-only packages, missing versions / PURLs / licences / suppliers / relationships, duplicates, unresolved
  identities. Compare only within the same ecosystem and scope (OS packages absent from a lockfile are not a defect).
- **Enrichment** from npm / PyPI / Maven Central only when verifiable; record the source of every enriched field;
  keep original Syft evidence; never invent metadata.
- Emit an internal quality report (inventory status, relationship status, metadata status, unresolved count,
  missing-metadata counts); never mark an SBOM complete just because a file was produced.

## 5. Dependency graph (NetworkX)

- Directed graph, edge = **parent → child** (parent depends on child); nodes keyed by CycloneDX `bom-ref`.
- Parse components, metadata root, `dependencies`; validate dangling refs; detect duplicate refs / namespace
  collisions when combining SBOMs; keep framework/service provenance; handle shared deps, cycles, malformed data.
- No artificial frontend↔backend edges; monorepos keep separate roots/scopes.
- Direct vs transitive classification; targeted traversal for paths to vulnerable nodes (no unrestricted
  all-simple-paths enumeration on large graphs); keep multiple paths.
- Visualisation: Cytoscape.js (or a Streamlit-compatible component). Never render thousands of nodes at once —
  provide overview, per-service subgraphs, direct-dependency exploration, vulnerability-focused subgraphs.

## 6. Vulnerability engine

- **OSV.dev** primary: `POST https://api.osv.dev/v1/querybatch`, then fetch full records for ranges, severity,
  fixed events. **NVD** for CVE/CVSS enrichment. **CISA KEV** optional prioritisation.
- Normalised finding model: finding_id, component_ref, package, ecosystem, installed_version, purl,
  vulnerability_ids, severity, cvss_score/vector (nullable), affected_status
  (`confirmed_affected` | `not_affected` | `unknown`), fixed_versions, dependency_type, root_component,
  dependency_paths, sources, remediation, scan_timestamp.
- For transitive findings do not blindly recommend bumping the first parent; derive an upgrade path from real
  constraints and advisory data.

## 7. Risk correlation, dashboard, reports

Unified correlator normalises vulnerability, typosquatting and lockfile findings, associates them to components,
dedupes, preserves evidence/provenance, and does **not** force anomalies into CVSS.

Dashboard sections: Repository Overview · SBOM Overview · Vulnerabilities (filter by severity, ecosystem, package,
direct/transitive, id) · Dependency Graph · Suspicious Changes (typosquatting + modified lockfiles) · Reports.
Downloads: CycloneDX SBOM, graph JSON, vulnerability JSON, suspicious-change JSON, consolidated report.

## 8. Stack

Streamlit · Python · GitPython or controlled `git` subprocess · custom inspector · Syft · CycloneDX JSON ·
registry APIs (npm/PyPI/Maven) · OSV.dev · NVD · NetworkX · RapidFuzz · Cytoscape.js · SQLite · pytest.
Avoid unnecessary dependencies; keep modules small with clear interfaces.

## 9. Target structure (adapt to the repo)

```text
app.py
core/            repository_manager, repository_inspector, framework_detector, scan_orchestrator
sbom/            syft_generator, lockfile_analyzer, metadata_enricher, sbom_validator, quality_analyzer
graph/           graph_builder, dependency_tracer, graph_exporter
vulnerability/   osv_client, nvd_client, vulnerability_matcher, severity_analyzer, remediation_engine
suspicious_changes/  typosquatting_detector, lockfile_change_detector
reporting/       risk_correlator, report_generator, export_manager
storage/         database, models
tests/   generated/   requirements.txt   README.md
```

## 10. Security requirements (untrusted repositories)

Validate/restrict URLs (GitHub only); no local paths or odd schemes; isolated temp workspaces; size and clone-time
limits; never run repo scripts; never run `npm/pip/poetry install`; never build Dockerfiles from untrusted repos
outside an isolated environment; no shell interpolation for Git/Syft; API timeouts and retries; handle offline mode;
no secrets in logs/commits; safe cleanup; malformed SBOMs/lockfiles must not crash the app.

## 11. Milestones

| M | Deliverable |
|---|---|
| M1 | Streamlit UI + repository ingestion |
| M2 | Generic language/framework detection |
| M3 | Automated Syft SBOM generation |
| M4 | Lockfile analysis + SBOM quality assessment |
| M5 | NetworkX dependency graph |
| M6 | OSV/NVD vulnerability correlation |
| M7 | Direct/transitive tracing |
| M8 | Typosquatting detector |
| M9 | Modified-lockfile detector |
| M10 | Unified dashboard + reporting |
| M11 | Integration tests + reliability |

Test each module before integrating it.

## 12. Acceptance criteria (summary)

- **Repo analysis:** public repos clone; SHA recorded; multi-language/monorepo detection; unsupported ecosystems reported.
- **SBOM:** valid CycloneDX from Syft; components/PURLs parsed; lockfile-vs-Syft comparison; missing metadata/relationships reported; completeness never assumed.
- **Graph:** valid `bom-ref` nodes; real edges; direct/transitive distinguishable; multi-path tracing; malformed refs safe.
- **Vulnerabilities:** OSV (+ NVD) working; IDs, severity, CVSS, fixed versions captured when present; accurate range matching; paths shown; unknowns not reported as confirmed.
- **Suspicious changes:** evidence-backed typosquat findings; lockfile detector uses real Git history; reasons given; normal updates not auto-flagged.
- **Dashboard:** repo info, SBOM summary, filterable findings, graph, suspicious changes, downloads.
- **Engineering:** unit tests per detector, end-to-end integration tests, API failures don't crash a scan, no secrets committed, no repo code executed, existing functionality preserved.

## 13. Scope boundaries

In MVP: generic ingestion, language/framework detection, SBOM + quality assessment, graph, vulnerability
correlation (CVE, severity, fixes), transitive tracing, the two detectors, dashboard, reporting.
Future: private-repo auth, install-script and image-trust detection, container OS vuln analysis, CI/CD analysis,
runtime monitoring, reputation intelligence, continuous monitoring, reachability, VEX.

---

## 14. Current repository state (as of branch `streamlit-app`)

Branch `streamlit-app` was created from base commit `d2de3d02986fe6cd15cab7659417f8343cd79e07`.

| Path | Content |
|---|---|
| `nodegoat/` | OWASP NodeGoat (intentionally vulnerable Node.js app) — **test target**, not scanner code. Contains its own `README.md`; leave untouched. |
| `artifacts/{sbom,scans,reports,graphs}/` | Placeholder output dirs (`.gitkeep`); generated outputs are git-ignored. |
| `.gitignore` | Python/Node/IDE ignores + artifact-output rules. |

The base commit has **no scanner source code**. An earlier FastAPI + React implementation (Milestones 1–6, NodeGoat
only) exists on `main` / `origin/main` (commit `b2d80b8`) but is *not* part of this branch's base.

## 15. Implementation plan

Phase 0 — Prerequisites: install Syft; Python deps (`streamlit`, `rapidfuzz`, `GitPython` or subprocess git,
`requests`, `packaging`, `pytest`, `networkx`, `pydantic`; optionally `univers`/`semantic_version` for version ranges,
`streamlit-cytoscapejs`-style component or a small custom HTML component). Optional NVD API key via env var.

Phase 1 (M1–M2) — `core/`: URL validator, shallow clone in temp dir with limits and SHA capture, inspector
(extension + manifest evidence), framework/ecosystem detector, Streamlit shell with progress and status.
Phase 2 (M3–M4) — `sbom/`: Syft subprocess wrapper, CycloneDX validator, lockfile parsers (npm first, then PyPI,
Go, Maven, Cargo), quality analyzer, optional enricher.
Phase 3 (M5, M7) — `graph/`: bom-ref graph builder, root/scope handling, targeted path tracer, JSON exporter.
Phase 4 (M6) — `vulnerability/`: OSV batch + record fetch (cached in SQLite), ecosystem-aware version matching,
NVD enrichment, KEV flag, remediation engine.
Phase 5 (M8–M9) — `suspicious_changes/`: popular-package lists + RapidFuzz detector; Git-diff lockfile detector.
Phase 6 (M10–M11) — `reporting/` correlator + exports, full dashboard, integration tests against NodeGoat and one
Python/monorepo sample, reliability (timeouts, offline mode, malformed input).

### Reuse candidates from `main` (to port, not depend on)

`backend/app/sbom/sbom_generator.py` (Syft subprocess wrapper), `sbom_parser.py` (CycloneDX validation),
`discovery/dependency_extractor.py` + `manifest_parser.py` (npm lockfile v1/v2 parsing), `graph/dependency_graph.py`
(NetworkX builder), `models/schemas.py` (pydantic models), and `backend/tests/*`. They are npm/NodeGoat-specific and
must be generalised (multi-ecosystem, bom-ref-keyed, no hardcoded filenames) before reuse.

### Risks

- Syft is not installed locally; Windows path handling and subprocess quoting need care.
- Python 3.15 is very new; verify Streamlit/RapidFuzz wheels (fall back to Python 3.11 venv if needed).
- Ecosystem-specific version semantics (npm semver, PEP 440, Maven) are the main correctness risk for matching.
- OSV/NVD rate limits and offline operation; mitigate with caching, retries and graceful degradation.
- Large monorepos and graph rendering size; mitigate with scoped subgraphs and node caps.

## 16. Git workflow rules (current phase)

Work stays **uncommitted** on `streamlit-app` until explicitly authorised: no commits, pushes, merges, rebases,
resets or branch deletions, and no changes to unrelated files.
