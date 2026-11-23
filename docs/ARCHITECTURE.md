# SC Guardian — architecture

An agentic guardian for the software supply chain: it **discovers** what a repository is built from (packages, container images, CI/CD actions), **detects** known and suspicious risks, **analyses and prioritises** them with evidence, **recommends and validates** safe fixes, and **reports** with an audit trail.
Everything is static analysis: repository code is never executed, installed or built (the only exception is the opt-in Docker sandbox, §10). The agent workflow graph is generated from the compiled LangGraph and shown interactively on the in-app *Architecture* page.

## 1. Layers (dependencies point downwards only; enforced by `scripts/audit_check.py`)

```
ui/ · guardian.py   Streamlit pages and the CLI (gate / scan / monitor / report)
orchestration/      LangGraph state graph: order, branching, parallelism, failure containment, checkpoints
agents/             Recon · Pipeline · SBOM · Graph · Vulnerability · Verification · Investigator · Threat · Risk · Remediation · Validator · Memory · Analyst (+ Supervisor)
domain libraries    sbom/ graph/ vulnerability/ suspicious_changes/ pipeline_analysis/ reachability/ remediation/ policy/ monitor/ sandbox/ risk_analysis/ explainability/ reporting/ intel/
foundations         evidence/ tools/ llm/ ecosystems/ core/ storage/ config/
```

## 2. The agent pipeline (`orchestration/pipeline.py`)

```
discover → classify → plan → lockfiles → sbom_generate → sbom_validate → pipeline (Docker/CI) → sbom_quality ─(incomplete? 2nd scanner)→ sbom_metadata (fusion) → graph
graph ─┬→ vulnerability → verification → investigator ─┐
       └→ typosquat → lockfile_history → package_risk ─┴→ risk → explain → remediate → validate_fix → memory → assemble → summary → export → finalize
```

* Agents are **deterministic and rule-based**; the graph decides order, branching and parallelism (Threat and Vulnerability branches run concurrently).
* **Failure containment:** a node never raises into the graph; an exception becomes a recorded step error, dependents are skipped with a limitation, and `assemble` always emits a full-schema result.
* **Thin state:** LangGraph state = scan id + trail; heavy objects live in an in-process `ScanState`. SQLite checkpoints record the trail for audit (they are not used to resume a half-finished scan).
* The Supervisor plans from what Recon found and records every observation/decision (`agent_trace`), streamed to the live progress bar.

## 3. The evidence-gated agent loop (what makes the agents agents)

* **Evidence store** (`evidence/`): every fact is an `Evidence` record with a readable id (`reachability:npm:minimist#d35595`, `epss:CVE-…`, `workflow:PIPE-004#…`, `what-if:REM-003#…`). Persisted in the scan result.
* **Tool registry** (`tools/`): typed, **read-only** tools (`advisory_facts`, `dependency_path`, `find_imports`, `package_meta`, `epss`, `read_snippet`). Unknown tools/arguments are rejected; a tool never raises into an agent.
* **Investigator Agent**: for every finding runs a bounded tool plan and issues a **verdict** (`exploitable_likely · reachable · possibly_reachable · test_only · no_import_evidence · needs_review` — never "safe"), a **confidence** with its basis, and the **evidence ids** it used.
  *Deterministic planner* (default, always runs) + *optional LLM planner* (only with `LLM_API_KEY`): the model may call the same read-only tools and propose a verdict + rationale. A **grounding gate** accepts it only if it cites existing evidence ids, mentions only advisory ids present in the finding, and does not contradict hard evidence (e.g. "no import" while an import exists; "likely exploitable" without KEV/EPSS/CVSS support). Rejections are kept and shown; AI-assisted conclusions are labelled.
* **What-if simulator** (Remediation/Validator): a proposed change is applied to the inventory in memory, the dependency tree is re-resolved (deps.dev) and advisories are re-matched with the production range validation → measured *fixed / remaining / newly introduced*, instead of guessed risk reduction.

## 4. Discover — SBOM, normalisation, fusion, resolution

* **Scanner policy:** lockfile parsers always run (independent evidence). `auto` = Syft → Trivy → built-in rule engine; if the primary SBOM misses lockfile packages and the other scanner is installed, the Supervisor runs it as a second pass and merges by identity. Explicit choices fall back to the rule engine.
* **Normalisation boundary** (`sbom/adapters/`): one adapter per scanner → one canonical document/`Component` model (identity = ecosystem, normalised name, version, service). Raw files stay byte-for-byte viewable.
* **Metadata fusion** (`sbom/fusion/`): lockfile (exact pin) > manifest > registry > scanner, with per-field provenance and conflicts; registries (deps.dev, npm, PyPI, crates.io, Maven Central, Packagist, RubyGems, Go checksum DB) fill gaps; **lockfile digests are verified against registry digests** (verified / mismatch / unverifiable / absent). Output: a fused CycloneDX file with licences (SPDX), hashes, scope, links and `sc-guardian:provenance:*` properties. NodeGoat: 99% completeness.
* **Registry resolver:** manifest-only services (`pom.xml`, `build.gradle`, pinned `requirements.txt`) get their transitive packages from deps.dev, labelled `registry-resolved` (each direct dependency resolved on its own; real version mediation may differ).
* **Pipeline Agent** (`pipeline_analysis/`): Dockerfile (multi-stage), docker-compose, GitHub Actions, and generic GitLab/Jenkins/CircleCI/Azure rules — unpinned/`latest`/EOL/community base images, root user, `ADD <url>`, `curl|sh`, baked secrets, privileged/docker.sock, mutable action refs, pwn-request (`pull_request_target` + PR checkout), script injection, over-broad token permissions, self-hosted runners on PRs, outdated action majors, committed credentials (value never stored). Images and actions become SBOM components (`pkg:docker`, `pkg:github`). Every finding has a rule id, file:line, evidence id and a fix.
* **Ecosystem plugin registry** (`ecosystems/registry.py`): the capability matrix (lockfile/manifest parsing, registry metadata, resolution, OSV, reachability, patching, pipeline rules) per ecosystem is declared in one place and rendered in the app; Python/npm/Docker/CI are first-class, Maven/Go/Cargo/Composer/NuGet/RubyGems are covered through the same interfaces.

## 5. Detect

* **Vulnerabilities:** OSV (ground truth) via batch query + full advisories; affected ranges **re-validated locally** with ecosystem rules; NVD (CVSS) and CISA KEV enrichment; every finding **cross-verified** through a second OSV route (PURL). Known-answer test (12 cases) in the audit.
* **Threat Agent:** typosquatting (similarity + registry corroboration), Git-history lockfile changes, and **package risk** (`PKG-INT` digest mismatch, `PKG-INST` install script without provenance, `PKG-NEW` very new release, `PKG-DEP` deprecated/yanked, `PKG-CONF` dependency-confusion candidate) plus provenance-attestation *presence* (not cryptographically verified).

## 6. Analyse and prioritise (risk model v2, `risk_analysis/`, rules version 2.0)

Additive, documented, versioned rules: CVSS, KEV, **EPSS** (estimate, small nudge), **reachability** (+20 imported by the app, +8 via an imported parent, −5 tests only, −15 no import; honest label "package-level import evidence, not a call graph"), exposure, scope, fix availability. Each assessment carries a **label**, a **P0–P3 priority**, a **confidence** (with basis) and the full factor table. KEV + application import always escalates to P0. On NodeGoat the 311 raw findings become 6 P0 / 25 P1 with 17 reachable and 166 with no import evidence.

## 7. Recommend and validate (`remediation/`, `agents/remediation_agent.py`)

* **Remediation Agent:** per source-package group chooses upgrade / pin / remove / mitigate / block / escalate. **Parent-upgrade search** walks newer versions of the direct dependency (same major first), resolves each tree and re-matches advisories; falls back to a verified pin of the vulnerable child; with no fix it recommends mitigate/block/escalate (never an invented version). Generates real **unified diffs** for npm (`package.json`/overrides/resolutions), pip (requirements/pyproject), Maven (version or `dependencyManagement`), Go, Cargo, Composer, NuGet — each verified with `git apply --check`. Compatibility signals (semver change), lockfile refresh command and rollback steps included.
* **Validator Agent:** static what-if → fixed / remaining / newly introduced (advisories already present elsewhere are not counted as introduced), before/after SBOM diff of the affected sub-tree, patch applicability. Build/tests are reported as *not run* unless the sandbox ran.
* **Human approval:** Approve / Reject / Needs review with a required reason, stored in `approvals` + `audit_log`; only approved remediations can export the patch and PR description. Nothing is applied, pushed or merged.

## 8. Report, policy, monitoring

* **Guardian report** (`reporting/`): Markdown/HTML/JSON plus **SARIF 2.1.0** and **CycloneDX VEX**. Sections: executive summary, prioritised findings with evidence ids, pipeline findings, package signals, recommended actions with validation, policy gate, responsible-AI disclosure, remaining/accepted risk, audit trail, coverage and limitations. VEX never states `not_affected` from absence of an import (stays `in_triage`); only an explicit analyst decision can.
* **Policy-as-code** (`policy/`, `policies/*.yaml`): declarative rules over findings and components → pass/fail gate with the violating evidence; analyst decisions and time-boxed exceptions waive (never hide). Same engine in the UI and in `guardian.py` (exit code 1 blocks a pipeline); illustrative Rego export; sample `.github/workflows/guardian.yml`.
* **Continuous monitoring** (`monitor/`): watch list + `monitor_events`; re-queries OSV (cache bypassed), KEV and EPSS for the *stored* inventories and alerts once per new advisory, newly exploited CVE, or EPSS rise.

## 9. Memory, storage, configuration

* **Memory** (SQLite): finding history (new/persisting/fixed/reappeared), analyst decisions with reason+expiry, approvals, audit log, packages-seen, graph tables (queryable/diffable).
* **Freshness:** a stored scan of the same commit is reused only if younger than the TTL, same scanner/rules/options and its SBOM still exists. Cache has per-namespace stats and bounded size/age.
* **Configuration:** `SCANNER_<NAME>` env > `.env` > `scanner.toml` > defaults, type/range validated, secrets env-only, effective values and sources on the *Settings & Health* page. Optional LLM: `LLM_API_KEY` (+ `LLM_PROVIDER`, `LLM_MODEL`, `LLM_BASE_URL`).

## 10. Security model

HTTPS GitHub allow-list (clone URL rebuilt from owner/name); argument-list subprocesses with `shell=False` and an **allow-listed environment** (no API keys); shallow, hook-less, submodule-less, symlink-less clone with size/time limits; read-only, size-capped, path-confined file access; secret-shaped strings redacted from findings, snippets and LLM prompts; persistence failures reported, never swallowed.
**Sandbox (opt-in, `sandbox/runner.py`):** after approval and a separate explicit confirmation, a throw-away re-clone at the scanned commit gets the patch applied and the repository's own build/tests run in Docker — `--cap-drop ALL`, `no-new-privileges`, CPU/memory/PID limits, no host environment, tests with `--network none`, baseline run to attribute failures. Skipped with a reason when Docker is not running.

## 11. Invariants checked by `scripts/audit_check.py` (76 checks)

layering · every `subprocess` call has explicit `env`/`shell=False` · API keys never reach subprocesses · every runtime step has a graph node · Syft/Trivy/rule-engine parity · failure injection leaves a full-schema result · memory/decisions/expiry · fusion precedence, digest verdicts, outage handling · pipeline rules (positive and negative fixtures, credential values never stored) · reachability per language · deterministic investigator verdicts, tool-registry rejection, **grounding gate** accept/reject cases, LLM tool loop with a scripted provider, **zero LLM calls without a key** · patches for 7 ecosystems pass `git apply --check` · what-if semantics · approval requires a reason and is audited · policy parsing/waivers/expiry/strict-vs-default · SARIF/VEX shape and conservative mapping · monitor alert + dedup · sandbox recipe detection and graceful skip · OSV known-answer test.

## 12. Known limits

Public GitHub only · shallow history (depth 50) · reachability is package-level import evidence (no call graph; dynamic imports/config-driven use are invisible) · registry-resolved transitive packages may differ from the project's real resolution · Maven/Packagist/NuGet/RubyGems ordering approximate · CVSS v4 and OSV GIT ranges not evaluated locally · provenance is presence only (no Sigstore/cosign verification) · EOL tables are dated snapshots · the LLM path was validated with a scripted provider (no live key available during development) · sandbox not exercised without a running Docker daemon · checkpoints are for audit, not resume.
