"""Shared normalized data models."""
from __future__ import annotations

from typing import Any, Optional

from pydantic import BaseModel, Field


class RepoInfo(BaseModel):
    scan_id: str
    url: str
    name: str
    owner: str = ""
    ref: Optional[str] = None  # requested branch/tag
    branch: Optional[str] = None  # resolved branch name
    commit_sha: str
    scan_timestamp: str
    local_path: str = ""
    shallow: bool = False
    source: str = "github"  # github | local


class ManifestFile(BaseModel):
    path: str  # repo-relative, posix
    name: str
    kind: str  # manifest | lockfile
    ecosystem: str
    service_dir: str  # repo-relative dir ("." for root)


class FrameworkHit(BaseModel):
    name: str
    ecosystem: str
    service_dir: str
    evidence: str


class InspectionResult(BaseModel):
    languages: dict[str, dict[str, int]] = Field(default_factory=dict)  # lang -> {files, bytes}
    frameworks: list[FrameworkHit] = Field(default_factory=list)
    ecosystems: list[str] = Field(default_factory=list)
    manifests: list[ManifestFile] = Field(default_factory=list)
    services: list[dict[str, Any]] = Field(default_factory=list)  # {dir, ecosystems, manifests, frameworks}
    dockerfiles: list[str] = Field(default_factory=list)
    container_files: list[str] = Field(default_factory=list)
    ci_files: list[str] = Field(default_factory=list)
    unsupported: list[str] = Field(default_factory=list)  # evidence of ecosystems without parser support
    total_files: int = 0
    truncated: bool = False
    limitations: list[str] = Field(default_factory=list)


class LockDependency(BaseModel):
    """A dependency record extracted from a manifest/lockfile (independent of Syft)."""

    name: str
    version: Optional[str] = None
    ecosystem: str
    purl: Optional[str] = None
    direct: Optional[bool] = None  # None = not determinable from this file
    dev: Optional[bool] = None
    requires: list[str] = Field(default_factory=list)  # names of dependencies (when the file records edges)
    lockfile: str  # repo-relative path
    service_dir: str = "."
    record: Optional[str] = None  # location in file (e.g. "packages[node_modules/x]")
    integrity: Optional[str] = None
    resolved: Optional[str] = None  # source URL / registry
    source_type: Optional[str] = None  # registry | git | url | path | unknown
    # native metadata the lockfile itself records (never guessed): license, scope flags, install scripts, deprecation, homepage, authors, time ...
    license: Optional[str] = None
    meta: dict[str, Any] = Field(default_factory=dict)
    derived: bool = False  # True: not read from a file of the repository but resolved by the registry resolver (see sbom/fusion/resolver.py)


class Component(BaseModel):
    """Normalized CycloneDX component."""

    bom_ref: str
    name: str
    version: Optional[str] = None
    group: Optional[str] = None
    type: str = "library"
    purl: Optional[str] = None
    ecosystem: Optional[str] = None  # OSV-style ecosystem; None for unsupported
    purl_type: Optional[str] = None
    licenses: list[str] = Field(default_factory=list)
    supplier: Optional[str] = None
    cpe: Optional[str] = None
    hashes: list[dict[str, str]] = Field(default_factory=list)
    locations: list[str] = Field(default_factory=list)  # repo-relative paths
    service_dir: Optional[str] = None
    found_by: Optional[str] = None
    sources: list[str] = Field(default_factory=list)  # which inventories saw it: syft | trivy | builtin | lockfile
    # ---- fused metadata (sbom/fusion): every value knows where it came from
    scope: Optional[str] = None  # required | optional | dev
    description: Optional[str] = None
    external_refs: list[dict[str, str]] = Field(default_factory=list)  # {type, url, source}
    published_at: Optional[str] = None
    deprecated: Optional[bool] = None
    install_script: Optional[bool] = None  # package runs code at install time (npm hasInstallScript)
    direct_declared: Optional[bool] = None
    source_type: Optional[str] = None  # registry | git | url | path
    resolved_url: Optional[str] = None
    provenance: dict[str, dict[str, Any]] = Field(default_factory=dict)  # field -> {source, confidence, evidence, conflicts[]}
    integrity: dict[str, Any] = Field(default_factory=dict)  # {status: verified|mismatch|unverifiable|absent, algorithm, lockfile, registry}
    resolution: str = "scanner"  # scanner | lockfile | registry-resolved
    completeness: Optional[float] = None  # 0..1 weighted share of key metadata fields that are known
    is_self: bool = False  # the application's own package (declared by its manifest), not a dependency
    enriched: dict[str, dict[str, str]] = Field(default_factory=dict)  # field -> {value, source}
