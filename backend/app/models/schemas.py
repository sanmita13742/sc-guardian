from __future__ import annotations
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field


class RepositoryMetadata(BaseModel):
    repository: str
    path: str
    languages: List[str] = Field(default_factory=list)
    package_managers: List[str] = Field(default_factory=list)
    manifests: List[str] = Field(default_factory=list)
    lockfiles: List[str] = Field(default_factory=list)
    dockerfiles: List[str] = Field(default_factory=list)
    docker_compose_files: List[str] = Field(default_factory=list)
    cicd_files: List[str] = Field(default_factory=list)
    commit_hash: Optional[str] = None
    branch: Optional[str] = None
    status: str = "discovered"


class Component(BaseModel):
    name: str
    version: str
    ecosystem: str = "npm"
    type: str = "library"
    dependency_type: str = "direct"  # direct | transitive
    environment: str = "production"  # production | development | optional | peer
    parent: Optional[str] = None
    purl: Optional[str] = None
    source: str = "package-lock.json"
    declared_version: Optional[str] = None
    resolved_version: Optional[str] = None
    license: Optional[str] = None
    integrity: Optional[str] = None
    dependencies: Dict[str, str] = Field(default_factory=dict)
    depth: int = 1


class ComponentInventory(BaseModel):
    repository: str
    ecosystem: str = "npm"
    scan_timestamp: str
    total_components: int
    direct_dependencies: int
    transitive_dependencies: int
    production_dependencies: int
    development_dependencies: int
    manifests: List[str] = Field(default_factory=list)
    lockfiles: List[str] = Field(default_factory=list)
    unresolved_dependencies: List[str] = Field(default_factory=list)
    repository_metadata: Dict[str, Any] = Field(default_factory=dict)
    components: List[Component] = Field(default_factory=list)


class GraphNode(BaseModel):
    id: str
    label: str
    version: str
    dependency_type: str
    environment: str
    ecosystem: str = "npm"
    in_degree: int = 0
    out_degree: int = 0
    depth: int = 0
    metadata: Dict[str, Any] = Field(default_factory=dict)


class GraphEdge(BaseModel):
    id: str
    source: str
    target: str
    relationship: str = "depends_on"
    version_constraint: Optional[str] = None


class DependencyGraphData(BaseModel):
    repository: str
    nodes: List[GraphNode] = Field(default_factory=list)
    edges: List[GraphEdge] = Field(default_factory=list)
    summary: Dict[str, Any] = Field(default_factory=dict)


class SBOMComparison(BaseModel):
    sbom_format: str
    syft_version: Optional[str] = None
    generated_timestamp: str
    total_sbom_components: int
    total_inventory_components: int
    matched_components: int
    only_in_sbom: List[str] = Field(default_factory=list)
    only_in_inventory: List[str] = Field(default_factory=list)
    version_mismatches: List[Dict[str, Any]] = Field(default_factory=list)
    validation_status: str
