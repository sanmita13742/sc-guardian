"""Models for suspicious-change findings (typosquatting, lockfile changes)."""
from __future__ import annotations

from typing import Any, Optional

from pydantic import BaseModel, Field


class TyposquatFinding(BaseModel):
    finding_id: str = ""
    kind: str = "typosquatting"
    classification: str = "suspicious_name_similarity"  # never "malicious": similarity is a signal, not proof
    package_name: str
    ecosystem: str
    versions: list[str] = Field(default_factory=list)
    component_refs: list[str] = Field(default_factory=list)
    similar_to: str
    similarity_score: float  # 0-100
    edit_distance: int
    techniques: list[str] = Field(default_factory=list)
    reference_source: str = ""
    evidence: list[str] = Field(default_factory=list)
    registry: dict[str, Any] = Field(default_factory=dict)
    evidence_strength: str = "low"  # low | medium | high
    evidence_points: int = 0
    why_flagged: str = ""
    caveats: list[str] = Field(default_factory=list)
    dependency_type: str = "unknown"
    roots: list[str] = Field(default_factory=list)
    services: list[str] = Field(default_factory=list)
    severity: Optional[str] = None  # unused for anomalies (no CVSS); kept for storage symmetry
    scan_timestamp: str = ""


class LockfileChange(BaseModel):
    finding_id: str = ""
    kind: str = "lockfile_change"
    commit: str
    baseline: str
    baseline_mode: str  # parent | explicit
    commit_info: dict[str, str] = Field(default_factory=dict)
    file: str
    ecosystem: str
    package_name: str
    change_type: str  # added | removed | version_changed | integrity_changed | integrity_removed | source_changed | lockfile_removed | lockfile_added | unparseable
    previous: dict[str, Any] = Field(default_factory=dict)
    new: dict[str, Any] = Field(default_factory=dict)
    manifest_changed: bool = False
    manifest_files_changed: list[str] = Field(default_factory=list)
    classification: str = "normal_update"  # normal_update | unexplained_change | potentially_suspicious | insufficient_baseline
    signals: list[str] = Field(default_factory=list)
    reasons: list[str] = Field(default_factory=list)
    evidence_strength: str = "low"
    diff_excerpt: list[str] = Field(default_factory=list)
    component_ref: Optional[str] = None
    severity: Optional[str] = None
    scan_timestamp: str = ""
