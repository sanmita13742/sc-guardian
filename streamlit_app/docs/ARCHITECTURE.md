# Architecture

## Agent layer (v2)

`core/scan_orchestrator.py` is the **Supervisor**. It validates the URL, owns the isolated workspace, runs the specialist agents in `agents/specialists.py`
(Recon, SBOM, Graph, Vulnerability, Verification, Threat, Risk, Analyst) and adapts to what they observe. `agents/runtime.py` provides the shared
`Runtime`: a 21-step catalogue with weighted progress, step lifecycle (`begin/progress/done/skip/fail`), failure isolation (a failed step is recorded and
independent steps continue) and an append-only trace of `observation`, `decision` and `warning` events that is streamed to the UI (live progress bar) and
stored in the scan result (`agent_trace`, `agents`, `plan`). Agent reasoning is rule-based; the optional LLM is confined to explanation text and validated.

Adaptive behaviours implemented: lockfile-derived fallback inventory when Syft fails; one OSV retry (cache keeps successful packages); NVD prioritisation under the
public rate limit; reuse of a stored scan for an identical commit; escalation of correlated detections; LLM only for the top-N risks with per-section validation.

Verification layer: `vulnerability/verification.py` re-queries every PURL by a second OSV route (`cross_verified`) and provides a known-answer test (precision/recall).
Source-package tracing: each finding records the direct dependency that introduces it (`source_packages`), the lockfile record, and per-root paths; the Analyst Agent ranks source packages.


```text
app.py (Streamlit)  ──►  ui/pages/*  ──►  core/scan_orchestrator.run_scan()
                                              │
   validate URL ─► git clone (isolated) ─► inspect ─► lockfile parsers ─► Syft ─► CycloneDX validate/normalize
        │                                                                              │
        │                                              quality analyzer ◄──────────────┤
        │                                              graph builder/validator ◄────────┘
        │                                                    │
        │      ┌──────────────── OSV (batch+advisories) ◄────┤ version_matcher (ecosystem semantics)
        │      │   NVD / CISA KEV enrichment                 │
        │      ▼                                             ▼
        │  vulnerability findings (+graph paths, remediation)   typosquatting detector (RapidFuzz + registry)
        │      │                                             lockfile change detector (Git history)
        │      └───────────────► evidence collector ► finding correlator ► risk scorer (rules) ► explanation engine
        │                                                                       │
        └────────────────────────────────────────────  SQLite (scans, findings, caches) + artifacts/ + reports/
```

## Modules

| Package | Responsibility |
|---|---|
| `config/` | Settings (env-driven, limits) and static tables. |
| `core/` | URL validation, safe Git wrapper, repository inspection, models, HTTP client (retry/backoff), **scan orchestrator** (stage isolation: a stage failure is recorded and independent stages continue). |
| `sbom/` | Syft runner, CycloneDX validation + normalization, per-ecosystem lockfile parsers (`package_extractors/`), quality analyzer, registry metadata enricher. |
| `graph/` | Graph builder (provenance-labelled edges), validator, per-root tracer (lazy bounded path enumeration), impact analysis, JSON/Cytoscape export. |
| `vulnerability/` | OSV/NVD/KEV clients, version matcher, CVSS v3 calculator, correlator, remediation engine. |
| `suspicious_changes/` | Typosquatting and lockfile-change detectors and their models. |
| `risk_analysis/` | Evidence collection/normalization, deterministic rules, scorer, cross-finding correlation. |
| `explainability/` | Evidence formatter, deterministic templates, optional LLM writer, grounding validator. |
| `reporting/` | JSON exports, Markdown/HTML report, SBOM artifact handling. |
| `storage/` | SQLite database (scans, findings) and TTL cache. |
| `ui/` | Streamlit pages, shared components, Cytoscape embed. UI contains no analysis logic. |

## Key design decisions

* **bom-ref nodes, per-root classification.** Direct/transitive is a property of a (component, root) pair; a package can be direct for one service and transitive for another and both are shown.
* **Edge provenance.** Syft's CycloneDX `dependencies` are authoritative. Lockfile `requires` are added only where the SBOM has no children for that parent. Root→package edges come from lockfile/manifest "direct" flags; packages with no recorded parent get a *flagged inferred* root edge (reported as "direct (inferred)"); unrooted cycle entry points are attached the same way.
* **Syft scope.** Syft is run with `javascript.include-dev-dependencies=true` so the SBOM matches the build-oriented lockfile inventory; dev-only status is kept (from the lockfile) and discounted in risk, not hidden. The setting is recorded on every scan.
* **No silent zeros.** Source states (`ok`, `partial`, `stale_cache`, `unavailable`, `not_queried`, `disabled`) travel with the results and appear in limitations.
* **Findings merge, not multiply.** Advisories sharing an id/alias collapse into one finding; duplicate SBOM records of the same package@version in a service (nested install paths) collapse into one finding that unions their dependency paths.
* **Extensibility.** New ecosystem = a parser in `sbom/package_extractors` + a comparator in `version_matcher.ECOSYSTEM_CMP` + a PURL/OSV mapping in `config/constants.py`. New intelligence provider = a client returning the normalized advisory shape. New detector = a module producing findings with `finding_id`, `evidence` and a scorer in `risk_scorer`.
