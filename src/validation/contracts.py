"""Typed contracts for fix validation.

``ApprovedRemediation.from_item`` is the *only* place that knows the shape of a remediation item produced by the remediation engine.
When that engine changes its output (e.g. a new ``remediation_plan.json``), update this adapter and nothing else.
"""
from __future__ import annotations

from typing import Any, Literal, Optional

from pydantic import BaseModel, ConfigDict, Field

Verdict = Literal["verified_fixed", "fixed_untested", "partial", "no_effect", "regressed", "inconclusive"]
SandboxStatus = Literal["passed", "failed", "error", "skipped"]


class DependencyChange(BaseModel):
    model_config = ConfigDict(extra="ignore")
    package: str
    from_version: Optional[str] = Field(default=None, alias="from")
    to_version: Optional[str] = Field(default=None, alias="to")
    kind: Optional[str] = None  # bump | pin


class ApprovedRemediation(BaseModel):
    """The minimum a validator needs from a remediation proposal (agreed with the remediation engine owner)."""

    model_config = ConfigDict(extra="ignore")
    id: str
    fingerprint: str
    ecosystem: str
    service: str = "."
    source_package: str = ""
    finding_ids: list[str] = Field(default_factory=list)
    action: str = ""
    patch_path: Optional[str] = None
    patch_diff: Optional[str] = None
    changes: list[DependencyChange] = Field(default_factory=list)
    priority: Optional[str] = None
    risk_label: Optional[str] = None
    predicted: Optional[dict[str, Any]] = None  # the static what-if result, if the scan produced one

    @classmethod
    def from_item(cls, item: dict[str, Any]) -> "ApprovedRemediation":
        patch = item.get("patch") or {}
        return cls(id=item["id"], fingerprint=item["fingerprint"], ecosystem=item.get("ecosystem") or (item.get("target") or {}).get("ecosystem") or "",
                   service=item.get("service") or ".", source_package=item.get("source_package") or "", finding_ids=list(item.get("finding_ids") or []),
                   action=item.get("action") or "", patch_path=patch.get("path"), patch_diff=patch.get("diff"),
                   changes=[DependencyChange.model_validate(c) for c in item.get("changes") or []], priority=item.get("priority"),
                   risk_label=item.get("risk_label"), predicted=item.get("what_if"))


class PhaseRun(BaseModel):
    model_config = ConfigDict(extra="ignore")
    phase: str  # install | test
    exit_code: Optional[int] = None
    seconds: float = 0.0
    log_tail: str = ""


class SandboxOutcome(BaseModel):
    status: SandboxStatus
    reason: Optional[str] = None
    recipe: Optional[dict[str, Any]] = None
    runs: list[PhaseRun] = Field(default_factory=list)
    baseline: Optional[dict[str, Any]] = None  # unpatched re-run when the patched tests fail
    attribution: Optional[str] = None
    docker_version: Optional[str] = None
    isolation: Optional[str] = None

    @property
    def install_ok(self) -> Optional[bool]:
        r = next((x for x in self.runs if x.phase == "install"), None)
        return None if r is None else r.exit_code == 0

    @property
    def tests_ok(self) -> Optional[bool]:
        """True = passed, False = the patch broke tests, None = not run / inconclusive / failure pre-existed."""
        if self.status == "passed":
            return True
        if self.status == "failed":
            return None if (self.baseline or {}).get("status") == "failed" else False
        return None


class FindingRef(BaseModel):
    key: str
    advisory: str
    package: str
    version: Optional[str] = None
    service: str = "."
    severity: Optional[str] = None
    risk_label: Optional[str] = None
    priority: Optional[str] = None


class ComponentChange(BaseModel):
    key: str
    before: list[str] = Field(default_factory=list)
    after: list[str] = Field(default_factory=list)


class Comparison(BaseModel):
    before_scan_id: Optional[str] = None
    after_scan_id: Optional[str] = None
    components_added: list[ComponentChange] = Field(default_factory=list)
    components_removed: list[ComponentChange] = Field(default_factory=list)
    components_changed: list[ComponentChange] = Field(default_factory=list)
    targeted_fixed: list[FindingRef] = Field(default_factory=list)
    targeted_remaining: list[FindingRef] = Field(default_factory=list)
    newly_introduced: list[FindingRef] = Field(default_factory=list)
    other_resolved: list[FindingRef] = Field(default_factory=list)
    target_versions_present: Optional[bool] = None  # every planned change is visible in the rescanned inventory
    missing_target_versions: list[str] = Field(default_factory=list)
    risk_before: dict[str, int] = Field(default_factory=dict)  # label -> count
    risk_after: dict[str, int] = Field(default_factory=dict)
    suspicious_before: int = 0
    suspicious_after: int = 0
    predicted_vs_observed: Optional[dict[str, Any]] = None


class FinalAssessment(BaseModel):
    remediation_id: str
    fingerprint: str
    scan_id: str
    verdict: Verdict
    reasons: list[str] = Field(default_factory=list)
    checks: dict[str, Optional[bool]] = Field(default_factory=dict)
    limitations: list[str] = Field(default_factory=list)
    provenance_ref: Optional[str] = None  # path of the provenance statement
    created_at: str
    approved_by: Optional[str] = None
