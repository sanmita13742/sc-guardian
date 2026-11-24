"""Unified domain models for Multi-CI pipeline analysis and container build extraction."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal, Optional

from pipeline_analysis.models import PipelineFinding

CIPlatform = Literal[
    "github_actions",
    "gitlab_ci",
    "jenkins",
    "circleci",
    "azure_pipelines",
    "generic_ci",
]


@dataclass
class CIDockerBuild:
    """Represents a container build directive discovered inside a CI pipeline."""
    dockerfile_path: str = "Dockerfile"
    context_path: str = "."
    image_tag: Optional[str] = None
    target_stage: Optional[str] = None
    build_args: dict[str, str] = field(default_factory=dict)
    builder_tool: str = "docker"  # docker | kaniko | buildah | buildx | azure_task
    ci_file: str = ""
    ci_job: str = ""
    line: int = 0


@dataclass
class UnifiedStep:
    """A single step or command inside a CI job."""
    name: str = ""
    command: Optional[str] = None
    uses: Optional[str] = None
    task: Optional[str] = None
    with_args: dict[str, Any] = field(default_factory=dict)
    env: dict[str, str] = field(default_factory=dict)
    line: int = 0


@dataclass
class UnifiedJob:
    """A distinct execution job/stage within a CI pipeline."""
    name: str
    stage: str = "default"
    runs_on: Optional[str] = None
    container_image: Optional[str] = None
    services: list[str] = field(default_factory=list)
    steps: list[UnifiedStep] = field(default_factory=list)
    docker_builds: list[CIDockerBuild] = field(default_factory=list)
    extra: dict[str, Any] = field(default_factory=dict)


@dataclass
class UnifiedPipeline:
    """Canonical representation of any CI pipeline across all supported platforms."""
    platform: CIPlatform
    file_path: str
    stages: list[str] = field(default_factory=list)
    jobs: dict[str, UnifiedJob] = field(default_factory=dict)
    triggers: list[str] = field(default_factory=list)
    docker_builds: list[CIDockerBuild] = field(default_factory=list)
    external_dependencies: list[dict[str, Any]] = field(default_factory=list)
    container_images: list[dict[str, Any]] = field(default_factory=list)
    findings: list[PipelineFinding] = field(default_factory=list)
    raw_parsed: dict[str, Any] = field(default_factory=dict)
    parse_success: bool = True
    error_message: Optional[str] = None
