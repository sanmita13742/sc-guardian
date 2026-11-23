# Risk scoring

Risk labels are produced by a **deterministic, additive rule engine** (`risk_analysis/risk_rules.py`, `risk_scorer.py`).
No LLM participates in scores, labels or factors. Rules version: **2.0** (adds reachability, EPSS, pipeline findings, confidence and P0-P3 priority). Every assessment stores the factor list, the
unknowns and the thresholds that were in effect, so a label can always be reproduced.

CVSS severity (a property of the advisory) and *risk* (a property of this finding in this repository) are shown separately.

## Labels

`score >= 70` CRITICAL · `>= 45` HIGH · `>= 25` MEDIUM · `>= 10` LOW · otherwise INFORMATIONAL.

## Vulnerability findings

| Factor | Points | Notes |
|---|---|---|
| CVSS severity | CRITICAL 55, HIGH 40, MEDIUM 22, LOW 8, **unavailable 12** | Missing severity is neutral — neither low nor critical. |
| CISA KEV | +30 (+5 if known ransomware use) | Exploitation evidence, not CVSS. Absence says nothing. |
| Exposure | direct +8, direct (inferred) +6, **transitive 0**, unknown 0 | Transitive is *not* discounted. Direct is *not* automatically critical. |
| Multiple roots | +5 | Affects ≥ 2 application roots/services. |
| No fixed version recorded | +5 | Does not by itself make a finding critical. |
| Development-only dependency | −10 | Lockfile marks it dev-only; build/CI exposure remains. |
| Correlated lockfile change | +5 | Same package also changed suspiciously in Git history. |
| EPSS (exploit probability estimate) | ≥0.5 +20, ≥0.1 +10, ≥0.01 +3 | Only nudges the score; it is a statistical estimate, not proof. |
| Reachability (package-level import evidence, not a call graph) | imported by the app +20, reached via a dependency +8, tests only −5, no import found −15, unknown 0 | Verdict comes from the Investigator with cited evidence ids. |
| Applicability unconfirmed | label capped at **MEDIUM** | OSV returned the advisory but the range could not be validated locally. |

## Pipeline findings (Dockerfile, compose, CI)

Severity points CRITICAL 75, HIGH 50, MEDIUM 28, LOW 12, INFO 4; −8 when the evidence is heuristic rather than directly visible; +5 for an unpinned third-party action.

## Confidence and priority

Every finding also gets a **confidence** (cross-verified, range-validated, reachability known, CVSS present) and a **priority P0-P3** (P0 = reachable/exploited and critical). The factor table on *Risk & Explainability* shows each contribution.

Example: a transitive CVSS-CRITICAL finding without KEV scores 55 → **HIGH**; with KEV 85 → **CRITICAL**; a direct LOW finding stays **LOW**.

## Typosquatting

Evidence strength (high 45 / medium 30 / low 15) + exposure (direct +5) + correlations (added in lockfile history +10, also vulnerable +5).
Strength comes from similarity techniques plus registry signals (very young package, very few downloads, name not found); established
packages (> 1 year and ≥ 20 000 monthly downloads) are suppressed. Without registry corroboration strength is capped at *low*.
**Label cap: HIGH** — name similarity is a signal, never proof.

## Lockfile changes

Classification points (`potentially_suspicious` 30, `unexplained_change` 12, `normal_update` 0, `insufficient_baseline` 0) + evidence strength bonus
(high +20, medium +8) + correlations (+10 if the package is vulnerable or a typosquat candidate). **Label cap: HIGH** — a lockfile change never proves compromise.

Signals that make a change `potentially_suspicious`: integrity hash changed for the *same* version, integrity hash removed, source/registry host changed,
a dependency newly resolved from a git/URL/path source. `unexplained_change`: a direct dependency changed with no manifest change in the same directory,
a downgrade not mentioned by a manifest diff, a new package with no changed parent, a deleted lockfile. Everything consistent with a manifest edit or a dependency
cascade is `normal_update` and is not reported as a finding.

## Overriding

Pass a JSON file to `ScanOptions(rules_path=...)`; keys are deep-merged over the defaults (see `DEFAULT_RULES`). The defaults are never mutated.
