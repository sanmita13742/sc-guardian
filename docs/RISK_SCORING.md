# Risk scoring

Risk is produced by a **deterministic, rule-based engine** (`src/risk_analysis/`). No LLM participates in scores, labels, priorities or factors.
Rules version: **2.2-contextual** (`RULES_VERSION` in `risk_rules.py`). Every assessment stores its factor list, the unknowns and the thresholds in effect, so a label can always be reproduced.

Two things are kept apart everywhere in the product:

* **CVSS severity** — a property of the *advisory* (how bad the vulnerability is in general).
* **Contextual risk** — a property of *this finding in this project*: the advisory's severity combined with whether and how the code uses the package.

The findings table, the header and the Dependency Graph's alert banner show CVSS severity; the *Risk*, *Score* and *Priority* columns, and each finding's **Risk breakdown** tab, show contextual risk. They are expected to differ (a CVSS-Critical advisory in a package nothing imports is not an urgent risk).

## Vulnerability findings: the four-factor model

```
R = 0.15·C + 0.20·A + 0.35·P + 0.30·I        (each factor 0–100, result 0–100)
```

| Factor | Weight | What it measures | How it is derived |
|---|---|---|---|
| **C** Advisory severity | 15 % | How severe the vulnerability is | `10 × CVSS` when a numeric score exists; otherwise estimated from the severity label (Critical 90, High 75, Medium 50, Low 25, unknown 40, flagged as an estimate) |
| **A** Application reachability | 20 % | Does application code import or call the package? | Static import / symbol evidence (`reachability/app_reachability.py`): confirmed reachable, potentially reachable, transitively reachable, test-only, unreachable, unknown |
| **P** Production reachability | 35 % | Does it ship and run in production? | Entry points, routes, Dockerfile/deployment context (`risk_analysis/production_context.py`): confirmed production path, shipped but not traced, test-only, not shipped |
| **I** Function impact | 30 % | How much damage the code that uses it could do | Sub-factors F (function criticality 25 %), S (data sensitivity 25 %), B (privilege boundary 20 %), D (downstream impact 20 %), X (production exposure 10 %) (`risk_analysis/function_impact.py`) |

### Missing evidence is not zero
If a factor cannot be assessed it is marked *unknown* and the score is **re-normalised over the factors that are known**; the result is flagged **provisional** and the missing evidence is listed. If nothing at all is known the baseline is 50. Unknown is never silently treated as safe.

### Labels
`score ≥ 70` CRITICAL · `≥ 45` HIGH · `≥ 25` MEDIUM · `≥ 10` LOW · otherwise INFORMATIONAL.

### Priority (P0–P3), with threat intelligence kept separate
Threat intelligence (CISA KEV, EPSS) does **not** change the score; it escalates the operational priority:

| Priority | When |
|---|---|
| **P0** immediate | score ≥ 70, **or** active CISA KEV with confirmed application reachability, **or** score ≥ 45 with a confirmed production path |
| **P1** this sprint | score ≥ 45, **or** score ≥ 25 with a confirmed production path, **or** any active CISA KEV |
| **P2** scheduled | score ≥ 25 |
| **P3** monitor | everything else |
| *Deprioritised* | verified **test-only** or **unimported** with no active KEV: capped at **P2** (P3 if the label is already low) |

EPSS ≥ 20 % is recorded as an escalation reason. KEV and EPSS are statistical or exploitation evidence, not proof about your code.

### Confidence
Each finding gets a confidence level from independent signals: cross-verified by a second OSV query route, affected range validated locally, reachability known, numeric CVSS present. It is shown on the Investigation tab. Findings whose affected range could not be confirmed locally are listed with that unknown.

## Non-vulnerability findings
Pipeline, typosquatting and lockfile findings are scored by a simple additive rule set (they have no CVSS or reachability):

* **Pipeline findings (Dockerfile, compose, CI):** severity points CRITICAL 75, HIGH 50, MEDIUM 28, LOW 12, INFO 4; −8 when the evidence is heuristic; +5 for an unpinned third-party action.
* **Typosquatting:** evidence strength (high 45 / medium 30 / low 15) + exposure (direct +5) + correlations (added in lockfile history +10, also vulnerable +5). Strength comes from similarity plus registry signals (very young package, very few downloads, name not found); established packages (> 1 year and ≥ 20 000 monthly downloads) are suppressed; without registry corroboration strength is capped at *low*. **Label cap: HIGH** — name similarity is a signal, never proof.
* **Lockfile changes:** classification points (`potentially_suspicious` 30, `unexplained_change` 12, `normal_update` 0, `insufficient_baseline` 0) + evidence bonus (high +20, medium +8) + correlations (+10 if the package is also vulnerable or a typosquat candidate). **Label cap: HIGH** — a lockfile change never proves compromise.

Signals that make a change `potentially_suspicious`: integrity hash changed for the *same* version, integrity hash removed, source/registry host changed, a dependency newly resolved from a git/URL/path source. `unexplained_change`: a direct dependency changed with no manifest change in the same directory, a downgrade not mentioned by a manifest diff, a new package with no changed parent, a deleted lockfile. Everything consistent with a manifest edit or a dependency cascade is `normal_update` and is not reported.

## How counts are reported
The numbers on every page and in every report come from one place (`reporting/counts.py`):

* **Findings** = vulnerability findings, confirmed + unconfirmed. **By CVSS severity** and **by contextual risk / priority** are separate breakdowns of the same findings.
* The contextual-risk and priority breakdowns count **vulnerability findings only**; pipeline and package-risk assessments are counted separately so the totals add up.
* **Components** = software packages (files, container images and CI actions are excluded and listed on Pipeline & Containers).
* **Remediation** counts findings fixed or covered **once**, even when several proposals touch the same finding.

## Overriding
Pass a JSON file to `ScanOptions(rules_path=...)`; keys are deep-merged over `DEFAULT_RULES` (weights, thresholds, per-source points). The defaults are never mutated.
