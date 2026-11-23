# SC Guardian — architecture

Static analysis of a public GitHub repository's software supply chain. **Nothing from the repository is ever executed, installed or built.**
Verified by `scripts/audit_check.py` (see "Invariants").

## 1. Layers (dependencies point downwards only; enforced by the audit script)

```
ui/              Streamlit pages and components (reads results, writes only analyst decisions)
orchestration/   LangGraph state graph: order, branching, parallelism, failure containment, checkpoints
agents/          Recon · SBOM · Graph · Vulnerability · Verification · Threat · Risk · Memory · Analyst  (+ Supervisor in orchestration/supervisor.py)
domain libs      sbom/  graph/  vulnerability/  suspicious_changes/  risk_analysis/  explainability/  reporting/
core/ storage/   URL validation, safe Git, HTTP, subprocess env, settings, SQLite (scans, memory, graph, cache)
```

`core/scan_orchestrator.py` is the public entry point (`run_scan`, `scan_local_directory`): validate URL → reuse check → safe clone → hand over to `orchestration`.

## 2. Pipeline (LangGraph, `orchestration/pipeline.py`)

```
discover → classify → plan → lockfiles → sbom_generate → sbom_validate → sbom_quality ─(incomplete & 2nd scanner?)→ sbom_second_pass ─┐
                                                                                      └──────────────────────────────────────────────┴→ graph
graph ─┬→ vulnerability → verification ─┐
       └→ typosquat → lockfile_history ─┴→ risk → explain → memory → assemble → summary → export → finalize
```

* Agents are **deterministic and rule-based**. The graph decides order/branching/parallelism; an LLM is used only to phrase explanations (optional, validated against evidence).
* **Thin state**: LangGraph state = scan id + trail. Heavy objects (components, NetworkX graph, results) live in an in-process `ScanState`, keeping checkpoints small.
* **Failure containment**: each node is wrapped. An exception becomes a recorded step error; a node whose required step failed is skipped with a limitation; `assemble` always emits a full-schema result so no page or report breaks.
* **Parallel branches**: Threat and Vulnerability run concurrently (`Runtime` is lock-protected). The graph runs in a worker thread and events are queued to the *calling* thread, so Streamlit callbacks stay on the script thread.
* **Checkpoints** (`data/checkpoints.db`, `SqliteSaver`) record the executed trail for audit. They are *not* used to resume a half-finished scan (restoring heavy state is not implemented, deliberately).
* `Runtime` (agents/runtime.py) is the event model behind the live progress bar, per-agent checklist and the decision trace stored with every result.

## 3. SBOM scanner policy — when to use which

| Situation | Decision |
|---|---|
| Always | Lockfile parsers (`sbom/package_extractors`) run first: independent evidence, direct/transitive flags, edges. They are never replaced by an SBOM tool. |
| `auto` (default) | Syft → Trivy → built-in rule engine; the first that succeeds is the primary. Raw output is stored byte-for-byte. |
| Primary SBOM misses lockfile packages (`quality = incomplete`) and the *other* external scanner is installed | Supervisor runs it as a **second pass** and merges by identity (`sbom/merge.py`); the decision is logged; three files are viewable (primary raw, second raw, merged). |
| Explicit choice (`syft` / `trivy` / `builtin`) | That scanner first, always falling back to the rule engine. No second pass (the user chose). |
| No scanner installed | Built-in rule engine (rules R1–R6, `sbom/builtin_generator.py`); the lockfile-vs-SBOM comparison is then labelled *not independent*. |
| Manifest-only repos / containers / binaries | Syft is preferred by the `auto` order (broader catalogers). Unpinned ranges cannot be vulnerability-matched and are reported as such. |

Trivy runs with `--scanners license --offline-scan` (no vulnerability DB; vulnerabilities come from OSV). Syft runs with remote lookups disabled. Neither receives the scanner's secrets (`core/safe_env.py`).

## 4. Normalisation — one boundary, one schema

`sbom/adapters/{syft,trivy,builtin}.py` are the only code that knows a tool's dialect:
`canonicalize(raw) → document`, `locations(component)`, `found_by(component)`. `normalize_components(doc, …, tool)` turns the canonical document into `Component` models carrying `sources`.
Identity key = `(ecosystem, normalised name, version, service_dir)`. Everything downstream (graph, OSV, detectors, reports) consumes only canonical models. Raw files are for viewing/download only and are never rewritten.

## 5. Dependency graph

* Library: **NetworkX `DiGraph`**, edge *parent → child* ("parent depends on child"), nodes keyed by canonical bom-ref, one synthetic root per service (monorepos).
* Built **once**, after normalisation + quality, **before** any vulnerability work (`graph/graph_builder.py`).
* Edge provenance, in precedence order: `sbom` > `lockfile:<file>` > `lockfile-direct` > `inferred-no-parent` (flagged, not proven).
* Direct/transitive is always **per root** (`classify_all`, one BFS per root); paths come from bounded Yen enumeration on the target's ancestor sub-graph (`dependency_tracer`), so large graphs never explode.
* Persisted to `graph_nodes` / `graph_edges` / `graph_meta` (content hash). `graph/graph_diff.py` compares graphs by *identity* (not bom-ref), powering "Changes since the previous scan".

## 6. Vulnerability data

OSV.dev is the ground truth (`querybatch` by name/ecosystem/version, then full advisories). Affected ranges are **re-validated locally** with ecosystem rules (PEP 440, semver, Maven, …); undecidable ranges become *unknown*, never "confirmed". NVD adds CVSS, CISA KEV adds known-exploited. Every finding is **cross-verified** by an independent PURL query. A known-answer test (6 CVEs, 12 cases) runs in the audit script. A source outage is reported as `unavailable`, never as "0 vulnerabilities". NVD's rate limit is shared process-wide (`core/safe_env.LIMITER`).

## 7. Agentic memory (SQLite, `storage/memory.py`, `agents/memory_agent.py`)

| Table | Purpose |
|---|---|
| `finding_state` | per repo + stable finding fingerprint (not `VULN-001`): first/last seen, status → *new / persisting / fixed / reappeared* diff on every scan |
| `decisions` | analyst decisions (accepted risk, false positive, suppress) with required reason and optional expiry; the latest decision wins; findings stay visible and flagged; scores are not altered |
| `package_seen` | how many scans/repositories a package appeared in (context for typosquat triage) |

No vector store: recall is exact and auditable.

## 8. Storage and freshness

SQLite (`data/scanner.db`, `PRAGMA user_version` migrations; refuses a database newer than the code): `scans`, `findings`, `graph_*`, memory tables, TTL `cache`.
A stored scan of the same commit is **reused only if** it is younger than `scan_cache_ttl_s` (24 h), was produced by the same `SCANNER_VERSION` and `RULES_VERSION` with the same options fingerprint, and its SBOM file still exists — otherwise the repo is rescanned (new advisories may exist).
Retention keeps the newest `keep_scans_per_repo` scans (rows, graph rows and artifacts); orphaned clone workspaces older than an hour are swept at the start of the next scan; cleanup retries on Windows file locks and reports honestly if it could not delete.

## 9. Security model

HTTPS GitHub URL allow-list (clone URL rebuilt from owner/name; query/fragment never reach Git); argument-list subprocesses with `shell=False`; **allow-listed subprocess environment** (no API keys); shallow, hook-less, submodule-less, symlink-less clone with size/time limits; read-only, size-capped, path-checked file access; secrets only via environment variables; persistence failures are reported, never swallowed.

## 10. Invariants checked by `scripts/audit_check.py`

layering (imports point down) · every `subprocess` call has explicit `env` and `shell=False` · API keys never reach subprocess env · every runtime step has a graph node · graph has parallel branches + conditional edge · Syft/Trivy/rule-engine parity on a monorepo fixture · failure injection leaves a full-schema result · memory diff/decisions/expiry · graph diff identity · retention · freshness rules · URL attack cases · adapter purity · OSV known-answer test.

## 11. Known limits

Public GitHub only · shallow history (depth 50) limits lockfile baselines · rule-engine inventory covers only lockfile/manifest ecosystems that have parsers (npm/yarn/pnpm, pip/poetry/uv/Pipfile, Go, Cargo, Composer, NuGet, Maven, Gradle) · Maven/Packagist/NuGet/RubyGems ordering is approximate · CVSS v4 and OSV GIT ranges are not evaluated locally · reachability is not assessed · checkpoints are for audit, not resume · the Streamlit script thread still waits for the scan (a click during a scan reruns the page; the worker thread finishes, saves and cleans up on its own) · CycloneDX validation is a structural profile, not the full official schema.
