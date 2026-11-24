# Responsible AI & security note

## Where AI is (and is not) used
| Capability | How it works | AI? |
|---|---|---|
| Inventory, SBOM, graph, vulnerability matching, version ranges, KEV/EPSS lookups | parsers, registries, OSV, local range evaluation | **No** |
| Risk score, priority (P0–P3), confidence | documented four-factor rules (`risk_analysis/`, rules version 2.2-contextual; see `RISK_SCORING.md`) | **No** |
| Pipeline/container findings, package signals, policy gate, what-if simulation, patches, compatibility checks, clone validation, OS-package fix versions | rule engines, registry metadata and the distro's own advisory data | **No** |
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
* **GitHub scans:** every remediation needs **Approve / Reject / Needs review with a reason** before a patch or PR description can be exported or a branch created.
* **Local folders:** a fix can only be written to your files after you press **Resolve** (it is applied to a *clone*, rescanned, checked and tested there) and then **Accept & Apply Changes**. Accept is disabled unless validation passed, and any validation warning must be acknowledged first. Accept copies exactly the files that were tested, after confirming your originals have not changed since; they are backed up first and **Undo** restores them. **Ignore** discards the proposal.
* **Project tests** (language projects) run inside an isolated Docker container during validation (`--cap-drop ALL`, no new privileges, resource limits; dependencies installed with network access, tests run with `--network none`); the Resolve step has a checkbox to turn this off. **Container fixes** are validated with a plain `docker build` of the patched Dockerfile in the clone followed by a Trivy scan of the built image. A build runs the Dockerfile's own `RUN` steps with network access, as any build does, and the temporary image is removed afterwards. These are the only places a project's own commands run.
* Nothing is pushed, merged, deployed or released automatically. All decisions go to the audit log.

## Source code, credentials and secrets
* Repository code is only read. Cloning is shallow, hook-less, submodule-less and symlink-less; files are size-capped and path-confined.
* Registry and advisory lookups (OSV, deps.dev, npm, PyPI, and the optional NVD, CISA KEV and EPSS feeds) send **package names and versions only**, whether or not an LLM is configured. Compatibility checks fetch the registry metadata of the proposed version.
* What may leave the machine, **only if an LLM key is configured**: package names/versions, advisory facts, evidence summaries and ≤ 11-line import snippets — to the provider you configured. Secret-shaped strings (Groq/Gemini/Anthropic/OpenAI/GitHub/AWS/Slack tokens, private keys) are redacted from every prompt. Each call is logged (size + SHA-256 prefix, never content) and listed in the report's disclosure section.
* Credentials found in repositories are reported by rule and location; **the value is never stored or displayed**.
* Subprocesses (git, Syft, Trivy, Docker) run with an allow-listed environment: API keys are never passed. Secrets are accepted from the environment only, never from `scanner.toml`.
* During clone validation the ecosystem's package manager (npm, pnpm, yarn, go, cargo, composer, poetry, uv) refreshes the lockfile **inside the scratch clone** with install scripts disabled; it resolves from the public registry and never touches your folder until you Accept.
* Local-folder scans read the folder in place and never write to it. Backups and undo records are stored outside the project (`~/.sc-guardian/local-changes/`), so scanners never see them.
* Out of scope by design: scanning production systems, publishing packages, using real credentials, auto-merging/deploying.

## Known limitations of the AI path
Validated with a scripted provider and mocked failures; no live provider key was available during development. Quality of AI rationales depends on the provider; the gate limits harm but cannot make a weak rationale insightful.
