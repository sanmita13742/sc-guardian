"""Pure verdict rules. Every verdict carries the checks and human-readable reasons that produced it.

verified_fixed   install ok, tests pass (or failures pre-existed), all targeted findings gone, nothing new at >= the worst fixed severity
fixed_untested   as above, but tests could not be run (no recipe / no Docker): the inventory evidence holds, the behaviour is unproven
partial          some targeted findings are gone, some remain
no_effect        no targeted finding is gone
regressed        the patch broke install/tests, or introduced a finding at >= the worst severity it fixed
inconclusive     the validation could not produce the evidence needed (patch did not apply, rescan failed, ...)
"""
from __future__ import annotations

from typing import Optional

from validation.comparison import severity_rank
from validation.contracts import Comparison, SandboxOutcome, Verdict


def decide(cmp: Optional[Comparison], sandbox: SandboxOutcome, rescan_ok: bool) -> tuple[Verdict, list[str], dict[str, Optional[bool]]]:
    reasons: list[str] = []
    checks: dict[str, Optional[bool]] = {"install_ok": sandbox.install_ok, "tests_ok": sandbox.tests_ok, "rescan_ok": rescan_ok,
                                         "target_versions_present": None, "all_targeted_fixed": None, "no_new_findings_at_or_above": None}
    if sandbox.status == "error" and sandbox.install_ok is None:
        return "inconclusive", [f"Sandbox error before install: {sandbox.reason}"], checks
    if not rescan_ok or cmp is None:
        return "inconclusive", ["The patched tree could not be rescanned, so there is no after-state evidence."], checks

    checks["target_versions_present"] = cmp.target_versions_present
    fixed, remaining = len(cmp.targeted_fixed), len(cmp.targeted_remaining)
    checks["all_targeted_fixed"] = remaining == 0 and fixed > 0
    worst_fixed = max((severity_rank(f.severity) for f in cmp.targeted_fixed), default=0)
    worse_new = [f for f in cmp.newly_introduced if severity_rank(f.severity) >= max(worst_fixed, 1)]
    checks["no_new_findings_at_or_above"] = not worse_new

    if sandbox.install_ok is False:
        return "regressed", ["Dependency installation failed with the patch applied."], checks
    if sandbox.tests_ok is False:
        return "regressed", ["Tests fail with the patch but pass on the unpatched baseline."], checks
    if worse_new:
        return "regressed", [f"{len(worse_new)} newly introduced finding(s) at or above the worst fixed severity: "
                             + ", ".join(f"{f.advisory} ({f.package} {f.version}, {f.severity})" for f in worse_new[:5])], checks

    if cmp.target_versions_present is False:
        reasons.append("Planned versions not observed in the rescanned inventory: " + ", ".join(cmp.missing_target_versions[:5]))
    if fixed == 0:
        return "no_effect", reasons + [f"None of the {remaining} targeted finding(s) disappeared."], checks
    if remaining:
        return "partial", reasons + [f"{fixed} targeted finding(s) fixed, {remaining} remain."], checks

    reasons.append(f"All {fixed} targeted finding(s) are gone after the rescan.")
    if cmp.newly_introduced:
        reasons.append(f"{len(cmp.newly_introduced)} lower-severity finding(s) newly introduced; review them.")
    if sandbox.tests_ok is True:
        return "verified_fixed", reasons + ["Install and tests pass in the sandbox."], checks
    return "fixed_untested", reasons + [f"Tests were not run: {sandbox.reason or sandbox.attribution or 'no result'}."], checks
