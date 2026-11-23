# SC Guardian — Repository Supply Chain Security Scanner

SC Guardian takes a **public GitHub repository URL** and produces an evidence-backed picture of its software supply chain:
a validated CycloneDX SBOM, a directed dependency graph, known vulnerabilities (with CVE, severity, CVSS, fixed versions and the
dependency path back to each application root), and two *suspicious-change* detectors (typosquatting and modified lockfiles) —
all presented in a Streamlit dashboard with downloadable reports.

> The scanner performs **static analysis only**. It never executes repository code, install scripts or builds.
> **A scan with no findings does not prove a repository is safe** — every result lists its coverage and limitations.

The original hackathon specification is kept in [docs/PROJECT_SPEC.md](docs/PROJECT_SPEC.md).
Implementation status and test evidence: [docs/IMPLEMENTATION_PROGRESS.md](docs/IMPLEMENTATION_PROGRESS.md).
Architecture: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) · Risk rules: [docs/RISK_SCORING.md](docs/RISK_SCORING.md).

## What it does

| Stage | Behaviour |
|---|---|
| Ingest | Validates a `https://github.com/<owner>/<repo>` URL (no local paths, credentials, other hosts), shallow-clones into an isolated temp workspace (no submodules, no hooks, size/time limits), records URL, branch and **exact commit SHA**, cleans up afterwards. |
| Inspect | Languages (extensions), ecosystems/frameworks (manifests, lockfiles, config), monorepo services, Dockerfiles/compose/CI files (recorded as context only). |
| SBOM | Syft → **CycloneDX JSON**, validated (profile schema + `bom-ref` integrity). The original file is preserved byte-for-byte; enrichment is a separate overlay with per-field provenance. |
| Quality | Compares manifests/lockfiles ↔ Syft components ↔ SBOM relationships *within the same ecosystem and service scope*; reports missing versions/PURLs/licenses/suppliers/relationships, duplicates, unresolved identities. Never says "complete". |
| Graph | NetworkX digraph keyed by `bom-ref`, edge = parent → child, one synthetic root per service, edge provenance (`sbom`, `lockfile`, `lockfile-direct`, `inferred-*`), cycle/dangling/duplicate handling, **direct/transitive per root**, bounded multi-path tracing. |
| Vulnerabilities | OSV.dev batch query + full advisories, local **ecosystem-aware range validation**, NVD CVSS enrichment (optional key), CISA KEV flag, SQLite cache, retry/backoff, explicit "source unavailable" states. |
| Typosquatting | RapidFuzz/Damerau-Levenshtein vs curated popular packages in the *same ecosystem*, registry corroboration (npm/PyPI), established packages suppressed, evidence strength + caveats. |
| Lockfile changes | Real Git history: parses the lockfile at the commit and its parent (or an explicit baseline) and classifies each change as `normal_update`, `unexplained_change`, `potentially_suspicious` or `insufficient_baseline`, with commit info, previous/new values and diff excerpt. |
| Risk | Transparent additive rule engine (labels CRITICAL…INFORMATIONAL) kept separate from CVSS severity; every label lists its factors and unknowns. |
| Explain | Evidence bundles + deterministic explanation templates. An optional LLM may rephrase them only if each section validates against the evidence (IDs, numbers, labels, certainty claims); otherwise the template is used. |
| Report | Dashboard + downloads: CycloneDX SBOM, graph JSON, vulnerability JSON, suspicious-change JSON, consolidated JSON, Markdown/HTML report. |

### Supported ecosystems

| Ecosystem | Lockfile / manifest parsers | Vulnerability matching |
|---|---|---|
| npm / JavaScript / TypeScript | package-lock.json (v1–v3), npm-shrinkwrap.json, yarn.lock (v1, basic berry), pnpm-lock.yaml | semver |
| Python | requirements*.txt, poetry.lock, uv.lock, Pipfile.lock, pyproject.toml (direct names) | PEP 440 |
| Java | pom.xml (declared + properties + dependencyManagement), build.gradle(.kts), gradle.lockfile | Maven ordering (approximated) |
| Go | go.mod, go.sum | semver |
| Rust | Cargo.lock | semver |
| PHP | composer.lock | loose numeric ordering |
| .NET | packages.lock.json, *.csproj | loose numeric ordering |

Other ecosystems Syft discovers (OS packages, GitHub Actions, …) appear in the SBOM but are reported as *not queried* for vulnerabilities. Ruby (`Gemfile`) is detected but has no lockfile parser — this is reported, not hidden.

## Install

Requirements: Python 3.10+ (developed and tested on **3.11** on Windows 11), Git, and [Syft](https://oss.anchore.com/docs/installation/syft/).

```bash
# 1. virtual environment (Python 3.11 recommended)
python -m venv .venv
.venv/Scripts/activate          # Windows (PowerShell: .venv\Scripts\Activate.ps1);  Linux/macOS: source .venv/bin/activate
pip install -r requirements.txt  # or: pip install -r requirements-lock.txt   (exact versions used in development)

# 2. Syft (user-level install, no admin rights)
scripts/install_syft.sh          # Git Bash / Linux / macOS     (Windows alt: powershell scripts/install_syft.ps1)
#    or: winget install Anchore.Syft   |   brew install syft
#    If syft is not on PATH, set SYFT_BIN in .env.

# 3. verify the whole toolchain (Python deps, Git, Syft scan + CycloneDX parse, network sources)
python scripts/verify_environment.py
```

### Configuration (all optional)

Copy `.env.example` to `.env`. **No key is required** for the scanner to work.

| Variable | Purpose |
|---|---|
| `NVD_API_KEY` | Raises the NVD rate limit (default cap without key: 20 CVEs per scan, ~6.5 s apart). |
| `ANTHROPIC_API_KEY`, `EXPLAIN_LLM_MODEL` | Enables validated LLM-phrased explanations (templates are used otherwise). |
| `SYFT_BIN` | Path to the Syft executable. |
| `SCANNER_DATA_DIR`, `SCANNER_WORKSPACE_DIR` | SQLite/cache location and temp clone location. |

## Run

```bash
streamlit run app.py          # then open http://localhost:8501
```

Pages: **Repository Scan** → **SBOM Explorer** → **Dependency Graph** → **Vulnerability Findings** → **Suspicious Changes** → **Risk & Explainability** → **Reports**. Previous scans are stored in SQLite (`data/scanner.db`) and can be reloaded; scanning the same commit again reuses the stored result unless you untick *Reuse cached scan*.

Generated artifacts (git-ignored): `artifacts/sbom/` (original CycloneDX), `artifacts/scans/` (JSON exports), `artifacts/graphs/`, `artifacts/reports/` (Markdown/HTML).

## Test

```bash
python -m pytest tests/unit                    # fast, offline, deterministic (mocked OSV/NVD/KEV)
python -m pytest tests/integration             # real Syft, live OSV/KEV/GitHub; ~10 min on a cold cache
python -m pytest -m "not network"              # everything that needs no internet
python -m pytest --cov=core --cov=sbom --cov=graph --cov=vulnerability --cov=suspicious_changes --cov=risk_analysis --cov=explainability --cov=reporting
```

Integration tests use the vendored `nodegoat/` directory, a multi-ecosystem monorepo fixture (`tests/fixtures/monorepo`) turned into a real Git repository with a deliberately suspicious second commit, and a real shallow clone of `OWASP/NodeGoat`. Live tests skip themselves when the network is unreachable. Each integration run appends a record (fixture, revision, SBOM/graph/OSV status, findings, sample paths) to `artifacts/scans/integration-test-records.json`.

## Security considerations

* URL allow-list (GitHub HTTPS only); branch/tag names validated; no shell — every subprocess uses an argument list.
* Clone: depth-limited, `--no-recurse-submodules`, hooks disabled, `core.symlinks=false`, `GIT_TERMINAL_PROMPT=0`, timeout and repository-size limit, workspace always removed.
* Repository files are only *read*: size-capped, symlinks skipped, path-traversal checked. Nothing is installed, built or executed; Dockerfiles are never built.
* Malformed SBOMs/lockfiles/API payloads are recorded as errors and never abort a scan; API failures are reported (`unavailable`, `stale_cache`), never converted into "0 vulnerabilities".
* Secrets only via environment variables; `.env` is git-ignored; API keys are never logged or sent anywhere except their own service.
* No finding is invented: missing CVE/CVSS/fix stays `n/a`; unknown applicability is `unknown`, not "affected".

## Limitations (honest list)

See [docs/IMPLEMENTATION_PROGRESS.md](docs/IMPLEMENTATION_PROGRESS.md#known-limitations) for the full list. Highlights: public GitHub only; shallow history (depth 50) limits baseline availability; version semantics for Maven/Packagist/NuGet/RubyGems are approximations; OSV `GIT` ranges and CVSS v4 vectors cannot be evaluated locally; typosquatting uses a small curated reference list and registry checks only for npm/PyPI; reachability of vulnerable code is **not** assessed (treated as unknown); Docker images and CI/CD pipelines are recorded but not analysed; Cytoscape.js is loaded from a CDN so the graph canvas needs browser internet access.

## Future extensions

Container-image SBOM and OS-package vulnerability analysis · Dockerfile and CI/CD pipeline security analysis · unsafe install-script detection · untrusted-image detection · more suspicious-dependency detectors · private-repository authentication · additional ecosystems and advisory providers · reachability analysis · VEX output. The module boundaries (`sbom/package_extractors`, `vulnerability/*_client.py`, `suspicious_changes/*`) are the intended extension points; none of these extensions is implemented yet.
