# Guardian backend

FastAPI service for secure GitHub URL validation, isolated bounded-history clones, lockfile-only CycloneDX generation, official validation, canonical dependency-graph reconciliation, OSV v2 scanning, historical dependency-change analysis, static CI/container inspection, evidence correlation, and JSON/Markdown/HTML reporting.

The cloned repository is treated as untrusted data. The service never runs `npm install`, lifecycle scripts, application code, or tests from it. `npx` downloads only the pinned analyzer package into npm's managed cache.

Configuration: `GUARDIAN_WORKSPACE`, `GUARDIAN_MAX_JOBS`, `GUARDIAN_CLONE_TIMEOUT`, `GUARDIAN_TOOL_TIMEOUT`, `GUARDIAN_HISTORY_DEPTH`, `GUARDIAN_HISTORY_COMMITS`, `CYCLONEDX_CLI_PATH`, `OSV_SCANNER_PATH`, `CYCLONEDX_NPM_VERSION`, and (for a preinstalled executable) `CYCLONEDX_NPM_COMMAND`.
