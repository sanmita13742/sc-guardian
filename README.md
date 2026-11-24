# SC Guardian — agentic software supply-chain security

Give it a **public GitHub URL** or the **path of a project folder on your machine**. A team of agents (LangGraph) reads it safely, builds a **fused CycloneDX SBOM** (Syft → Trivy → built-in rule engine, enriched from lockfiles and registries),
analyses Dockerfiles / compose / CI workflows (and, opt-in, the container images themselves), matches components against **OSV** (with NVD, CISA KEV and EPSS), **investigates** each finding with read-only tools (reachability evidence, dependency path),
scores risk with transparent rules, and proposes **validated remediations**. For a local folder, every fix is first applied to a **clone**, rescanned, checked for compatibility and tested; only then can you **Accept** it into your real files (with backup and Undo) — and the **Fix Report** gives a one-page PDF per fix.

> Static analysis only: repository code is never executed, installed or built — the exceptions are the project's own tests and image builds, which run only inside an isolated Docker sandbox during validation. **No findings ≠ safe** — every result lists its coverage and limitations.
> Fully deterministic by default. An LLM is optional: set `LLM_API_KEY` (Groq / Gemini / Anthropic / OpenAI-compatible) in `.env` and tick *Optional LLM reasoning*; every AI statement must pass an evidence-grounding gate (see [docs/RESPONSIBLE_AI.md](docs/RESPONSIBLE_AI.md)).

## Run
```bash
python -m venv .venv
.venv\Scripts\activate            # Windows   (Linux / macOS: source .venv/bin/activate)
pip install -r requirements.txt
python -m streamlit run app.py    # http://localhost:8501
```
Use `python -m streamlit` (not bare `streamlit`) so the venv's packages are used. Syft, Trivy and Docker are optional; nothing else is required.
Install them if you want them: `winget install Anchore.Syft AquaSecurity.Trivy` (Windows), `brew install syft trivy` (macOS), or see the Syft and Trivy release pages; without them the built-in rule engine produces the SBOM (Syft is recommended: its richer dependency graph groups findings under direct dependencies, which gives noticeably more patchable remediation proposals).
Syft and Trivy are found on `PATH`, in the Windows registry `PATH` (so a tool installed after your terminal or the app started is still found), and in the usual install folders (winget, scoop, chocolatey, `~/bin`, `~/go/bin`); override with `SYFT_BIN` / `TRIVY_BIN`.
Configuration precedence: environment `SCANNER_<NAME>` > `.env` > `scanner.toml` (optional) > defaults; see `.env.example`. Secrets only via the environment.

## Scanning a project
* **GitHub URL** — `https://github.com/<owner>/<repo>` (public, HTTPS). Cloned shallow into an isolated workspace.
* **Local folder** — paste a path (`C:\projects\my-app`, `/home/me/app`, `~/app`, `file:///…`). The folder is scanned in place, read-only; nothing is copied or cloned. Cached scans are not reused for local folders.

## Pages
| Page | What it shows |
|---|---|
| Repository Scan | URL or folder path, options (scanner, LLM, investigator, remediation), live agent progress |
| SBOM Explorer | components (packages only; CI actions and images are listed under Pipeline & Containers), metadata completeness, digest verification, the actual CycloneDX file |
| Dependency Graph | dark, interactive vis-network explorer: node size = importance, green production / orange dev / blue root, search, filters (Direct / Production / All), limit slider, layouts, Pause Physics; click = impact analysis, double-click = focus. Plus dependency tree (top-down / bottom-up), transitive alerts and package tracer |
| Vulnerability Findings | findings table and per-finding **Overview / Risk breakdown / Investigation / References** tabs; verdicts (reachable / possibly reachable / test-only / no import evidence), evidence chain, ground-truth test |
| Pipeline & Containers | Dockerfile, compose and CI findings (GitHub Actions, GitLab, Jenkins, CircleCI, Azure) plus opt-in image scan results |
| Suspicious Changes | typosquatting, lockfile history, package risk (install scripts, deprecation, digest mismatch) |
| Remediation | one proposal per source package (language packages) or per Dockerfile (OS packages). **GitHub scans:** measured effect, patch, rollback, approval, optional PR branch. **Local folders:** **Resolve** (clone → apply → rescan → compatibility → tests) → **Accept & Apply Changes** / **Ignore** → **Undo**; live counters (open / applied / ignored / findings remaining) |
| Fix Report | every applied fix with CVSS and contextual scores, files changed (real diff), validation record, and a **one-page PDF per fix** (or all in one file) |
| Monitoring | watch list; re-checks stored inventories for newly disclosed advisories (GitHub scans) |
| Agent Activity · Reports · Architecture · Settings & Health | decision trace, MD/HTML/JSON/SARIF/VEX exports, agent-workflow graph + safety notes, effective config and tool status |

## How remediation works
1. **Plan** — for each group of findings the planner finds the smallest safe change: a parent upgrade verified against OSV on the registry-resolved dependency tree (deprecated versions are skipped), otherwise a pin, otherwise a mitigation. OS packages in images get a Dockerfile `RUN` layer using the distro's own fix versions. Up to 300 proposals are planned within a 900 s budget (`remediation_max_groups`, `remediation_budget_s` in Settings).
2. **Resolve** (local folders) — the fix is applied to a scratch clone; the lockfile is refreshed with the package manager (scripts off); the clone is rescanned; declared compatibility is checked from registry metadata (deprecation, `engines`, peer dependencies, major jumps, yanked releases); the project's own tests run in the Docker sandbox when available (images are built and rescanned with Trivy). A fix is blocked if it fixes nothing, introduces High/Critical findings, cannot refresh its lockfile, is incompatible, or breaks tests that pass without it.
3. **Accept / Ignore** — Accept writes exactly the tested files into your folder after checking they are unchanged since validation; originals are backed up under `~/.sc-guardian/local-changes/` (override with `SC_GUARDIAN_HOME`) and **Undo** restores them. Warnings (for example tests could not confirm compatibility) must be acknowledged first.
4. **Rescan** the folder to confirm the findings are gone; the **Fix Report** keeps the record.

## CLI and CI
```bash
python guardian.py scan <url-or-folder>            # scan from the terminal
python guardian.py gate latest --policy default    # policy gate, exit code 1 when it fails
python guardian.py monitor                         # cron / Actions friendly
python guardian.py scans | report                  # list stored scans / export a report
```
Policy-as-code lives in `policies/` (`default.yaml`, `strict.yaml`) and is evaluated by the CLI gate and in CI. `.github/workflows/guardian.yml` is a ready-to-copy example.

## Documentation & deep dives
* 🏛️ **[System Architecture](docs/ARCHITECTURE.md)** — layers, the 12 execution stages, multi-agent system, grounding gate, security boundaries.
* ⚙️ **[Workflow, Stages & Scanners](docs/WORKFLOW_AND_SCANNERS.md)** — what happens in each step and why each scanner (Syft, Trivy, built-in, OSV, NVD, KEV, EPSS, RapidFuzz) is used.
* 🎯 **[Risk Scoring](docs/RISK_SCORING.md)** — the four-factor contextual model, missing-evidence handling, priorities P0–P3.
* 🐳 **[Container Scanning & OS-package remediation](docs/CONTAINER_SCANNING.md)** — image scanning, distro-aware fixes, build-and-rescan validation.
* 🔁 **[Multi-CI Guide](docs/MULTI_CI_GUIDE.md)** — GitHub Actions, GitLab, Jenkins, CircleCI, Azure Pipelines rules.
* 🤖 **[Responsible AI](docs/RESPONSIBLE_AI.md)** — evidence citation, grounding gate, human approvals, what runs on your machine.
* 🚀 **[Demo script](docs/DEMO_SCRIPT.md)** — guided walkthrough with OWASP NodeGoat.
* 📐 Design history: [`docs/audit/`](docs/audit/contextual-risk-scoring-v2-audit.md) and [`docs/implementation/`](docs/implementation/contextual-risk-scoring-v2-plan.md) (the audit and plan behind the contextual risk model).

## Layout
```
app.py            Streamlit entry point            guardian.py   CLI (scan / gate / monitor / scans / report)
src/              all application code (added to sys.path by the entry points)
  orchestration/ agents/       LangGraph pipeline · specialist agents (runtime, investigator, remediation, memory)
  sbom/ graph/                 scanners + tool discovery + metadata fusion · dependency graph, tree view, exports
  vulnerability/ reachability/ intel/ tools/ evidence/   matching and evidence-gated investigation
  pipeline_analysis/ containers/   Dockerfile, compose and multi-CI rules · image discovery and Trivy image scanning
  remediation/                 planner, patchers, compatibility checks, container plans, clone validation (local_trial), apply/undo
  sandbox/                     opt-in Docker sandbox for project tests
  policy/ monitor/ reporting/ risk_analysis/ explainability/   (reporting also holds counts.py and the Fix Report PDF)
  core/ config/ storage/ llm/ ecosystems/ suspicious_changes/ ui/
policies/         sample policy-as-code (default, strict)
docs/             architecture, workflow, risk, container, multi-CI, responsible-AI, demo, audit/, implementation/
tests/            validation fixtures and checks
.env.example  requirements.txt  .github/workflows/guardian.yml
data/ artifacts/ .workspaces/   runtime output (git-ignored)
```

## Security and limitations
HTTPS GitHub allow-list for URLs; no shell (argument lists only); shallow, hook-less, submodule-less, symlink-less clone with size limits; read-only file access; subprocesses get a scrubbed environment (no API keys);
credentials found in repos are reported by rule and location, never by value.
**Nothing is pushed or merged automatically.** Local folders are only written when you press *Accept* on a fix that passed validation on a clone; the exact files are backed up first and can be restored with *Undo*.
Registry lookups (OSV, deps.dev, npm, PyPI, and the optional NVD/KEV/EPSS feeds) send package names and versions only.

Limits: reachability is package-level import evidence, not a call graph · registry simulation covers npm, PyPI, Maven, Go, Cargo and NuGet (others get findings and notes, not patches) · lockfile refresh needs the ecosystem's package manager installed (npm, pnpm, yarn, go, cargo, composer, poetry, uv); otherwise the page tells you the command to run ·
the Docker sandbox needs a running Docker daemon, and container fixes need Docker and Trivy to be verified · EOL / deprecated-action tables are dated static data · Maven/Packagist/NuGet/RubyGems version ordering is approximate ·
the dependency graph loads vis-network from a CDN (offline: use the tree/tables) · the LLM path is tested with scripted providers only · developed and tested on Windows. Details: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).
