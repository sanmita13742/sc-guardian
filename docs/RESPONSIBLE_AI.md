# Responsible AI & security note

## Where AI is (and is not) used
| Capability | How it works | AI? |
|---|---|---|
| Inventory, SBOM, graph, vulnerability matching, version ranges, KEV/EPSS lookups | parsers, registries, OSV, local range evaluation | **No** |
| Risk score, priority (P0–P3), confidence | additive documented rules (`risk_analysis/risk_rules.py`, version 2.0) | **No** |
| Pipeline/container findings, package signals, policy gate, what-if simulation, patches | rule engines and registry data | **No** |
| Investigation verdict (default) | deterministic planner over read-only tools | **No** |
| Investigation reasoning, explanation phrasing (optional) | LLM proposes, grounding gate disposes | **Yes — only if `LLM_API_KEY` is set and "Optional LLM reasoning" is ticked** |

With no key the product is fully functional and makes **zero** LLM calls (asserted by the audit script).

## How hallucination is controlled
1. **Only evidence can be cited.** Every fact (advisory data, import locations, EPSS, dependency path, registry digest, what-if result) is an evidence record with an id. The model sees evidence summaries, not the repository.
2. **Read-only tools.** The model may call six tools; unknown tools/arguments are rejected; `read_snippet` only reads files already cited as import evidence, ≤ 11 lines, secrets redacted.
3. **Grounding gate** (`agents/investigator.py::guard`): a proposal is rejected if it cites a non-existent evidence id, mentions an advisory id that is not part of the finding, uses a verdict outside the allowed set, claims reachability without import evidence, claims "no import"/"test only" when an import exists, claims "likely exploitable" without KEV/EPSS/CVSS support, or makes any claim when the affected range is unconfirmed.
4. **Fail safe.** Rejection, timeout or provider error keeps the deterministic verdict; the rejection reason is shown. AI-assisted conclusions are labelled ("AI-assisted, grounded"); verified evidence vs inference is distinguished (`verified` flag on evidence).
5. **Conservative language.** Verdicts never say "safe"; reachability is "package-level import evidence, not a call graph"; VEX never auto-asserts `not_affected`; EPSS is shown as an estimate.

## Human approval points
* Every remediation needs **Approve / Reject / Needs review with a reason** before a patch or PR description can be exported.
* The optional Docker sandbox (the only place repository commands run) needs approval **and** a separate confirmation checkbox.
* Nothing is applied, pushed, merged, deployed or released automatically. All decisions go to `audit_log`.

## Source code, credentials and secrets
* Repository code is only read. Cloning is shallow, hook-less, submodule-less and symlink-less; files are size-capped and path-confined.
* What may leave the machine, **only if an LLM key is configured**: package names/versions, advisory facts, evidence summaries and ≤ 11-line import snippets — to the provider you configured. Secret-shaped strings (Groq/Gemini/Anthropic/OpenAI/GitHub/AWS/Slack tokens, private keys) are redacted from every prompt. Each call is logged (size + SHA-256 prefix, never content) and listed in the report's disclosure section.
* Credentials found in repositories are reported by rule and location; **the value is never stored or displayed**.
* Subprocesses (git, Syft, Trivy, Docker) run with an allow-listed environment: API keys are never passed. Secrets are accepted from the environment only, never from `scanner.toml`.
* Out of scope by design: scanning production systems, publishing packages, using real credentials, auto-merging/deploying.

## Known limitations of the AI path
Validated with a scripted provider and mocked failures; no live provider key was available during development. Quality of AI rationales depends on the provider; the gate limits harm but cannot make a weak rationale insightful.
