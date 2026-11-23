# SC Guardian — agentic repository supply-chain security scanner

Paste a **public GitHub URL**; a team of agents clones it safely, finds its manifests and lockfiles, generates a CycloneDX SBOM
(**Syft**, **Trivy** or the built-in **rule engine**), builds the dependency graph, checks every component against **OSV.dev** (the ground truth)
with NVD/CISA-KEV enrichment, traces each vulnerable package back to the *direct dependency that introduces it*, runs two suspicious-change
detectors (typosquatting, modified lockfiles), scores risk with transparent rules and explains every finding from evidence — all inside the
Streamlit app, with a live progress bar.

> Static analysis only: repository code is never executed, nothing is installed or built. **No findings ≠ safe** — every result lists its coverage and limitations.

## Run

The environment is self-contained in `.venv` (Python 3.11 recommended). One command creates it on first use and starts the app:

```bash
run.bat            # Windows (double-click works too)
./run.sh           # Linux / macOS / Git Bash
```

or manually:

```bash
python -m venv .venv
.venv\Scripts\python -m pip install -r requirements.txt        # Linux/macOS: .venv/bin/python
.venv\Scripts\python scripts/verify_environment.py             # Python deps, Git, scanners, network sources
.venv\Scripts\python -m streamlit run app.py                   # http://localhost:8501
```

Always start with `python -m streamlit` (or `run.bat`), not the bare `streamlit` command: with Anaconda installed, bare `streamlit` can resolve to
Anaconda's copy, which lacks this app's packages (the app detects this and shows the fix). After updating the code, stop the running Streamlit server
(Ctrl+C) and start it again.

### SBOM scanners

| Scanner | Needed? | Install |
|---|---|---|
| **Syft** | optional | `scripts/install_syft.sh`, `winget install Anchore.Syft`, `brew install syft`; set `SYFT_BIN` if not on PATH |
| **Trivy** | optional | `winget install AquaSecurity.Trivy`, `brew install trivy`, or a release from github.com/aquasecurity/trivy; set `TRIVY_BIN` if not on PATH |
| **Built-in rule engine** | always available | nothing to install |

The scan form's *SBOM scanner* option defaults to **Auto**: Syft → Trivy → built-in rule engine, falling through on failure, so every scan with dependency
evidence ends with a real CycloneDX file you can open on the **SBOM Explorer → SBOM file** tab. The rule engine (`sbom/builtin_generator.py`, rules R1–R6) builds the
document from the scanner's own lockfile/manifest parsers; because it reads the same lockfiles used for cross-checking, the app labels that comparison as not independent.
Trivy runs with `--scanners license`, so no vulnerability database download is needed (vulnerabilities come from OSV).

### Complete SBOM metadata (metadata fusion)
After the scanner runs, the SBOM Agent **fuses** lockfile, scanner and registry metadata with per-field provenance and writes a *fused* CycloneDX file (licences, hashes, supplier, scope, links, install-script and deprecation flags, `sc-guardian:provenance:*`). Lockfile digests are **verified against the registry** (npm, PyPI, crates.io, Packagist, RubyGems, Go checksum DB) and mismatches raise an alert. For services without a lockfile (`pom.xml`, `build.gradle`, pinned `requirements.txt`) the transitive packages are resolved through deps.dev and labelled `registry-resolved`. Measured: NodeGoat 99% metadata completeness. Details: `docs/ARCHITECTURE.md` section 4b. Disable registry look-ups with the scan option *Fill missing metadata from registries*.

### Configuration
Copy `scanner.example.toml` to `scanner.toml` for tuning (timeouts, cache limits, scan reuse window, tool paths). Precedence: environment `SCANNER_<NAME>` > `.env` > `scanner.toml` > defaults; values are validated and secrets are environment-only. The **Settings & Health** page shows every effective value and its source, tool versions, database health, cache statistics and disk usage.

Accepted repository addresses: `https://github.com/owner/repo`, `.git` and trailing-slash forms, `github.com/owner/repo`, `git@github.com:owner/repo.git`,
and browser URLs such as `https://github.com/owner/repo/tree/<branch>` (the branch is taken from the URL). Only public repositories can be cloned.

Run the audit any time with `.venv\Scripts\python scriptsudit_check.py` (add `--with-scanners` to compare Syft/Trivy/rule engine, `--offline` to skip network checks).

Optional environment variables (see `.env.example`): `NVD_API_KEY` (higher NVD limits), `ANTHROPIC_API_KEY` (LLM-phrased explanations), `SYFT_BIN`, `TRIVY_BIN`. Nothing is required.

## The agent pipeline

The agents are nodes of a **LangGraph** state graph (`orchestration/pipeline.py`): a conditional edge runs a second SBOM scanner when the first misses lockfile packages, and the Threat and Vulnerability branches run in parallel. Full design: `docs/ARCHITECTURE.md`.

Everything runs automatically from one button; the **live progress bar** shows overall percentage, current step, a per-agent checklist and a streaming log of what each agent observes
and decides. The same trace is kept on the **Agent Activity** page.

| Agent | Steps it owns | What it does autonomously |
|---|---|---|
| **Supervisor** | validate URL · plan · clean up | Validates input, builds the analysis plan from what Recon found, observes every result and adapts: falls back to the next SBOM scanner, retries OSV once, limits/prioritises NVD lookups, escalates correlated detections, reuses a stored scan for an identical commit, deletes the workspace. |
| **Recon Agent** | clone · discover · classify | Shallow, hook-less, submodule-less clone into an isolated workspace; finds manifests, lockfiles, Dockerfiles, CI files; detects languages, frameworks, monorepo services. |
| **SBOM Agent** | lockfiles · sbom_generate · validate · quality | Parses 7 ecosystems' lockfiles independently, selects the scanner (Syft / Trivy / rule engine) → CycloneDX, validates it, compares lockfile ↔ SBOM ↔ relationships and reports gaps (never "complete"). |
| **Graph Agent** | graph | NetworkX digraph keyed by `bom-ref`, one root per service, direct/transitive **per root**, cycles/dangling refs handled. |
| **Vulnerability Agent** | osv · enrich · trace | OSV batch query + full advisories, **local range re-validation with ecosystem rules**, NVD CVSS, CISA KEV, then traces every finding to its path and **source package**. |
| **Verification Agent** | verify | Re-queries every PURL via a second OSV route and marks each finding *cross-verified*; disagreements are listed. |
| **Threat Agent** | typosquat · lockfile history | Name-similarity vs popular packages (registry-corroborated); real Git-history lockfile diffs (integrity/source/version anomalies). |
| **Memory Agent** | memory | Compares with the repository's previous scans (new / persisting / fixed / reappeared), keeps analyst decisions (accepted risk, false positive) with reason and expiry. |
| **Risk Agent** | risk · explain | Deterministic rule engine (CVSS severity ≠ project risk), cross-detector correlation, evidence-grounded explanations (templates; optional validated LLM). |
| **Analyst Agent** | summary · export | Executive summary, prioritised "update this source package" actions, JSON/Markdown/HTML reports, SQLite persistence. |

Honest scope of "agentic": agents are autonomous, tool-using, stateful components with a supervisor that plans, observes and adapts. Their reasoning is **rule-based and
deterministic**; an LLM is used only to phrase explanations (Risk Agent, top-15 findings) when `ANTHROPIC_API_KEY` is set, and each section is validated against the evidence
before it is shown — otherwise the template text is used.

## How vulnerabilities are found and checked against ground truth

1. **Identify** each component exactly: ecosystem + name + version + PURL (SBOM and lockfiles). The application's own package is excluded.
2. **Ask the database**: OSV.dev (GitHub Advisories, PyPA, RustSec, Go vuln DB, NVD CVE records, …) via `querybatch`, then fetch full advisory records.
3. **Re-validate locally**: affected ranges are evaluated with the ecosystem's own version rules (PEP 440, semver, Maven ordering, …). Out-of-range advisories are dropped; ranges that cannot be evaluated become *unknown* — never "confirmed".
4. **Enrich**: NVD CVSS (vector/score), CISA KEV (known exploited). Missing CVE/CVSS/fix stays `n/a`.
5. **Cross-verify**: every PURL is queried again by a second OSV route; a finding is ✅ only if both routes return it.
6. **Known-answer test** (Vulnerability page → *Ground truth*): 6 documented CVEs (lodash, minimist, requests, flask, log4j-core, golang.org/x/text) must be detected and their patched versions must not be — reports precision/recall.

## Where things are shown

| Page | Contents |
|---|---|
| Repository Scan | URL form, SBOM-scanner choice, **live agent progress**, repository overview, analyst summary, where the clone was stored, coverage/limitations |
| SBOM Explorer | components table with licence/scope/integrity/provenance, **Metadata tab** (coverage before/after fusion, digest verification, conflicts), quality, scanner attempts & validation, **the actual CycloneDX file** (full file with line numbers, header / components / dependencies views), download |
| Dependency Graph | **Dependency tree** (top-down / bottom-up, depth statistics), **Direct-only**, **transitive-only**, vulnerability-path, service and neighbourhood views (Cytoscape); **severity alert banner**; **Transitive alerts** with *source (direct) package*; **Source packages** ranking; package tracer |
| Vulnerability Findings | filters, details, **7-step evidence chain**, ground-truth panel |
| Suspicious Changes | typosquatting evidence; lockfile changes with commit, baseline, diff, reasons |
| Risk & Explainability | risk overview, per-root exposure, factor tables, grounded explanations |
| Agent Activity | per-agent steps/timings, every decision with its reason, full timeline, plan, workspace |
| Reports | CycloneDX SBOM, graph JSON, vulnerability JSON, suspicious-change JSON, consolidated JSON, Markdown/HTML report |

### Where is the cloned repository stored?
In an isolated, git-ignored temp workspace `.workspaces/<scan-id>/repo`. It is only read statically and **deleted when the scan ends**. Tick *Keep clone workspace* to inspect it afterwards.
Generated artifacts (SBOM, reports, graph JSON) go to `artifacts/`, results and caches to `data/scanner.db`.

## Layout

```
app.py                 Streamlit entry point
orchestration/         LangGraph pipeline (nodes, routing, parallel branches, checkpoints) + Supervisor helpers
agents/                runtime (steps, progress, decision trace) + specialist agents + memory agent
core/                  URL validation, safe Git, repository inspection, HTTP client, Supervisor (scan_orchestrator)
sbom/                  scanner engine, per-scanner adapters (normalisation), merge, CycloneDX validation, lockfile parsers, quality analyzer
graph/                 graph builder/validator, per-root tracer, impact, export
vulnerability/         OSV/NVD/KEV clients, version matcher, CVSS, correlator, remediation, verification (ground truth)
suspicious_changes/    typosquatting + lockfile-change detectors
risk_analysis/ explainability/ reporting/ storage/ ui/ config/
docs/                  architecture, risk scoring, implementation progress, original spec
scripts/               verify_environment.py, audit_check.py (architecture + behaviour audit), Syft install helpers
```

## Security

HTTPS GitHub URL allow-list; no shell (argument lists only); depth-limited clone, no submodules, hooks disabled, symlinks off, timeouts and size limit; repository files are read only
(size-capped, symlinks skipped, path-checked); API failures are reported as `unavailable`/`stale_cache`, never as "0 vulnerabilities"; secrets only via environment variables.

## Limitations

Public GitHub only · shallow history (depth 50) limits lockfile baselines · Maven/Packagist/NuGet/RubyGems ordering is approximate · OSV GIT-type ranges and CVSS v4 vectors cannot be evaluated locally ·
reachability of vulnerable code is not assessed · typosquatting uses a small curated list and registry checks only for npm/PyPI · Docker/CI files are recorded, not analysed ·
the built-in rule engine only inventories packages declared in parsed lockfiles/manifests · the Cytoscape canvas loads from a CDN · LLM explanations were validated with a mocked model only ·
developed and tested on Windows. Details: `docs/IMPLEMENTATION_PROGRESS.md`.
