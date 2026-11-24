"""Container asset discovery and vulnerability scanning models."""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from typing import Any, Literal, Optional


@dataclass
class DiscoveredContainerAsset:
    """Represents a container image or build specification discovered in a repo."""
    asset_id: str
    source_type: Literal["dockerfile", "compose", "ci_pipeline", "prebuilt_image"]
    source_file: str
    image_tag: Optional[str] = None
    base_image: Optional[str] = None
    base_image_tag: Optional[str] = None
    base_image_digest: Optional[str] = None
    context_dir: Optional[str] = None
    stage_names: list[str] = field(default_factory=list)
    associated_ci_jobs: list[str] = field(default_factory=list)
    scan_status: Literal["pending", "scanned", "skipped", "failed"] = "pending"
    scan_error: Optional[str] = None

    @staticmethod
    def generate_id(source_file: str, image_tag: Optional[str], base_image: Optional[str]) -> str:
        key = f"{source_file}:{image_tag or ''}:{base_image or ''}"
        return hashlib.sha256(key.encode("utf-8")).hexdigest()[:12]


@dataclass
class ContainerScanFinding:
    """Normalized vulnerability finding inside a container image."""
    finding_id: str
    vuln_id: str
    package_name: str
    installed_version: str
    fixed_version: Optional[str] = None
    severity: Literal["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "UNKNOWN"] = "UNKNOWN"
    cvss_score: Optional[float] = None
    package_type: Literal["os_pkg", "lang_pkg"] = "os_pkg"
    os_distribution: Optional[str] = None
    target: str = ""
    layer_diff_id: Optional[str] = None
    title: str = ""
    description: str = ""
    references: list[str] = field(default_factory=list)
    image_tag: str = ""
    source_file: str = ""
    extra: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "vuln_id": self.vuln_id,
            "package_name": self.package_name,
            "installed_version": self.installed_version,
            "fixed_version": self.fixed_version,
            "severity": self.severity,
            "cvss_score": self.cvss_score,
            "package_type": self.package_type,
            "os_distribution": self.os_distribution,
            "target": self.target,
            "layer_diff_id": self.layer_diff_id,
            "title": self.title,
            "description": self.description,
            "references": self.references,
            "image_tag": self.image_tag,
            "source_file": self.source_file,
            "asset_type": "container_image",
            "extra": self.extra,
        }
