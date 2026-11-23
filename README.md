# SC Guardian — agentic software supply-chain security

Paste a **public GitHub URL**. A team of agents (LangGraph) clones it safely, builds a **fused CycloneDX SBOM** (Syft → Trivy → built-in rule engine, enriched from lockfiles and registries),
analyses Dockerfiles / compose / CI workflows, matches components against **OSV** (with NVD, CISA KEV and EPSS), **investigates** each finding with read-only tools (reachability evidence, dependency path),
scores risk with transparent rules, and proposes **verified remediations** you approve before any patch can be exported. Policy gate, SARIF/VEX reports and continuous monitoring are included.

> Static analysis only: repository code is never executed, installed or built (the one exception is the opt-in, approved Docker sandbox). **No findings ≠ safe** — every result lists its coverage and limitations.
> Fully deterministic by default. An LLM is optional: set `LLM_API_KEY` (Groq / Gemini / Anthropic / OpenAI-compatible) in `.env` and tick *Optional LLM reasoning*; every AI statement must pass an evidence-grounding gate (see `docs/RESPONSIBLE_AI.md`).

## Run
```bash
scriptsun.bat    # Windows
scripts/run.sh     # Linux / macOS / Git Bash
```
or manually: `python -m venv .venv`, install `requirements.txt`, `python scripts/verify_environment.py`, then `python -m streamlit run app.py` (http://localhost:8501).
Use `python -m streamlit` (not bare `streamlit`) so the venv's packages are used. Syft and Trivy are optional (`SYFT_BIN` / `TRIVY_BIN`); nothing else is required.
Configuration precedence: environment `SCANNER_<NAME>` > `.env` > `scanner.toml` > defaults (`scanner.example.toml`, `.env.example`); secrets only via environment.

## Pages
| Page | What it shows |
|---|---|
| Repository Scan | URL form, options (scanner, LLM, investigator, remediation), live agent progress |
| SBOM Explorer | components, metadata completeness, digest verification, the actual CycloneDX file |
| **Dependency Graph** | dark, interactive vis-network explorer: node size = importance, green production / orange dev / blue root, search, filters (Direct / Production / Shared hubs / All), limit slider, layouts, Pause Physics; click = impact analysis (red path to root), double-click = focus. Plus dependency tree (top-down / bottom-up), alerts and package tracer |
| Vulnerability Findings | verdicts (reachable / possibly reachable / test-only / no import evidence), evidence chain, ground-truth test |
| Pipeline & Containers | Dockerfile, compose, GitHub Actions and generic CI findings (EOL images, unpinned actions, token permissions, ...) |
| Suspicious Changes | typosquatting, lockfile history, package risk (install scripts, deprecation, digest mismatch) |
| Risk & Explainability | priority P0-P3, confidence, factor tables |
| Remediation | proposal per source package with measured effect (fixed / remaining / new), SBOM diff, patch, rollback, approval + audit trail, optional Docker sandbox |
| Policy & Gate | YAML policy-as-code (`policies/default.yaml`, `strict.yaml`) with waivers |
| Monitoring | watch list; re-checks stored inventories for newly disclosed advisories |
| Agent Activity · Reports · Architecture · Settings & Health | decision trace, MD/HTML/JSON/SARIF/VEX exports, agent-workflow graph + safety notes, effective config and tool status |

## CLI and CI
```bash
python guardian.py scan <url>                      # scan from the terminal
python guardian.py gate latest --policy default    # exit code 1 when the policy fails
python guardian.py monitor                         # cron / Actions friendly
```
`.github/workflows/guardian.yml` is a ready-to-copy example. Audit everything with `python scripts/audit_check.py` (`--offline`, `--with-scanners`).

## Documentation & Deep Dives
* 🏛️ **[System Architecture Guide](docs/ARCHITECTURE.md)**: Layered architecture, 12 execution stages, multi-agent AI system, grounding gate, and security boundaries.
* ⚙️ **[Workflow, Stages & Scanner Guide](docs/WORKFLOW_AND_SCANNERS.md)**: Detailed rationale on why this workflow was chosen, what happens under each step, and why each specific scanner (Syft, Trivy, Built-in, OSV, NVD, KEV, EPSS, RapidFuzz) is used.
* 🤖 **[Responsible AI & Anti-Hallucination Shield](docs/RESPONSIBLE_AI.md)**: Evidence citation requirements, grounding gate enforcement, and human-in-the-loop approvals.
* 🎯 **[Risk Prioritization Model (P0–P3)](docs/RISK_SCORING.md)**: Context-aware risk scoring rules, reachability weighting, and factor breakdown.
* 🚀 **[Interactive Demo Script](docs/DEMO_SCRIPT.md)**: Guided walkthrough using OWASP NodeGoat and vulnerable sample targets.

## Layout
```
app.py            Streamlit entry point            guardian.py   CLI (scan / gate / monitor / report)
src/              all application code (added to sys.path by the entry points)
  orchestration/ agents/       LangGraph pipeline · specialist agents (runtime, investigator, remediation, memory)
  sbom/ graph/                 scanners + metadata fusion · dependency graph, tree view, exports
  vulnerability/ reachability/ intel/ tools/ evidence/   matching and evidence-gated investigation
  pipeline_analysis/           Dockerfile, compose and CI rules
  remediation/ sandbox/        planner, patchers, what-if validation, opt-in Docker sandbox
  policy/ monitor/ reporting/ risk_analysis/ explainability/
  core/ config/ storage/ llm/ ecosystems/ suspicious_changes/ ui/
policies/         sample policy-as-code (default, strict)
docs/             ARCHITECTURE, RESPONSIBLE_AI, RISK_SCORING, DEMO_SCRIPT
scripts/          run.bat / run.sh launchers, audit_check.py, ui_smoke_test.py, verify_environment.py
.env.example  scanner.example.toml  requirements.txt  .github/workflows/guardian.yml
data/ artifacts/ .workspaces/   runtime output (git-ignored)
```

## Security and limitations
HTTPS GitHub allow-list; no shell (argument lists only); shallow, hook-less, submodule-less, symlink-less clone with size limits; read-only file access; subprocesses get a scrubbed environment (no API keys);
credentials found in repos are reported by rule and location, never by value; nothing is applied, pushed or merged automatically.

Limits: public GitHub only · reachability is package-level import evidence, not a call graph · the registry resolver resolves each direct dependency on its own ·
EOL / deprecated-action tables are dated static data · Maven/Packagist/NuGet/RubyGems ordering is approximate · the dependency graph and workflow graph load vis-network from a CDN (offline: use the tree/tables) ·
the LLM path is tested with scripted providers only · the Docker sandbox needs a running Docker daemon · developed and tested on Windows. Details: `docs/ARCHITECTURE.md`.
