"""Base interface and common utilities for Multi-CI platform adapters."""
from __future__ import annotations

import re
from abc import ABC, abstractmethod
from typing import Any, Optional

from pipeline_analysis.ci_models import CIDockerBuild, UnifiedPipeline
from pipeline_analysis.dockerfile import INSECURE, PIPE_TO_SHELL, classify_image, split_image
from pipeline_analysis.models import SECRET_LITERAL, PipelineFinding, redact_line

# Regex helpers for docker build directives in command strings
DOCKER_BUILD_RE = re.compile(
    r"\bdocker\s+build(?:x\s+build)?\s+(?P<args>[^;\n\r&|]+)",
    re.IGNORECASE,
)
KANIKO_BUILD_RE = re.compile(
    r"/kaniko/executor\s+(?P<args>[^;\n\r&|]+)",
    re.IGNORECASE,
)
BUILDAH_BUILD_RE = re.compile(
    r"\bbuildah\s+(?:bud|build)\s+(?P<args>[^;\n\r&|]+)",
    re.IGNORECASE,
)


class BaseCIAdapter(ABC):
    """Abstract base adapter for any CI/CD platform parser."""

    @property
    @abstractmethod
    def platform_id(self) -> str:
        """Machine identifier (e.g. github_actions, gitlab_ci, jenkins)."""
        ...

    @property
    @abstractmethod
    def platform_name(self) -> str:
        """Human-readable ecosystem name."""
        ...

    @abstractmethod
    def can_handle(self, file_path: str) -> bool:
        """Return True if this adapter should parse the given file."""
        ...

    @abstractmethod
    def analyze(self, text: str, file_path: str) -> UnifiedPipeline:
        """Parse pipeline content and return a UnifiedPipeline object."""
        ...

    # --- Common Helper Methods ---

    def _create_finding(
        self,
        rule_id: str,
        title: str,
        severity: str,
        file_path: str,
        line: int,
        snippet: str,
        subject: str,
        why: str,
        remediation: str,
        evidence_strength: str = "high",
        references: Optional[list[str]] = None,
        **extra: Any,
    ) -> PipelineFinding:
        """Convenience method to construct a standard PipelineFinding."""
        return PipelineFinding(
            rule_id=rule_id,
            category="ci",
            ecosystem=self.platform_name,
            title=title,
            severity=severity,
            file=file_path,
            line=line,
            snippet=redact_line(snippet.strip())[:200],
            subject=subject,
            why=why,
            remediation=remediation,
            evidence_strength=evidence_strength,
            references=references or [],
            extra=extra,
        )

    def _find_line(self, lines: list[str], needle: str, start: int = 0) -> int:
        """Find 1-based line number containing needle starting from index start."""
        if not needle:
            return 1
        for idx in range(start, len(lines)):
            if needle in lines[idx]:
                return idx + 1
        return 1

    def _scan_secret_literals(self, lines: list[str], file_path: str) -> list[PipelineFinding]:
        """Scan line-by-line for high-confidence committed credentials."""
        findings: list[PipelineFinding] = []
        for n, line in enumerate(lines, 1):
            if SECRET_LITERAL.search(line):
                findings.append(
                    self._create_finding(
                        rule_id="SEC001",
                        title=f"A credential appears to be committed in this {self.platform_name} pipeline",
                        severity="CRITICAL",
                        file_path=file_path,
                        line=n,
                        snippet=line,
                        subject="credential",
                        why="A live-looking API token or private key is stored directly in repository configuration.",
                        remediation="Revoke and rotate the exposed credential immediately; use the CI platform's secret store.",
                    )
                )
                break  # Alert once per file
        return findings

    def _extract_docker_build_from_shell(
        self,
        script_text: str,
        file_path: str,
        job_name: str,
        base_line: int = 1,
    ) -> list[CIDockerBuild]:
        """Extract Docker/Kaniko/Buildah build invocations from script lines."""
        builds: list[CIDockerBuild] = []
        for raw_line in script_text.splitlines():
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue

            # Standard Docker build / buildx
            m_docker = DOCKER_BUILD_RE.search(line)
            if m_docker:
                args = m_docker.group("args")
                builds.append(self._parse_docker_cli_args(args, file_path, job_name, base_line, "docker"))
                continue

            # Kaniko executor
            m_kaniko = KANIKO_BUILD_RE.search(line)
            if m_kaniko:
                args = m_kaniko.group("args")
                builds.append(self._parse_kaniko_args(args, file_path, job_name, base_line))
                continue

            # Buildah bud
            m_buildah = BUILDAH_BUILD_RE.search(line)
            if m_buildah:
                args = m_buildah.group("args")
                builds.append(self._parse_docker_cli_args(args, file_path, job_name, base_line, "buildah"))

        return builds

    def _parse_docker_cli_args(
        self, args_str: str, file_path: str, job_name: str, line: int, tool: str
    ) -> CIDockerBuild:
        """Parse flags like -t, -f, --target, context path from docker/buildah build command."""
        tokens = args_str.split()
        dockerfile = "Dockerfile"
        context = "."
        tag: Optional[str] = None
        target_stage: Optional[str] = None

        i = 0
        while i < len(tokens):
            token = tokens[i]
            if token in ("-f", "--file") and i + 1 < len(tokens):
                dockerfile = tokens[i + 1].strip("'\"")
                i += 2
            elif token in ("-t", "--tag") and i + 1 < len(tokens):
                tag = tokens[i + 1].strip("'\"")
                i += 2
            elif token == "--target" and i + 1 < len(tokens):
                target_stage = tokens[i + 1].strip("'\"")
                i += 2
            elif not token.startswith("-") and i == len(tokens) - 1:
                context = token.strip("'\"")
                i += 1
            else:
                i += 1

        return CIDockerBuild(
            dockerfile_path=dockerfile,
            context_path=context,
            image_tag=tag,
            target_stage=target_stage,
            builder_tool=tool,
            ci_file=file_path,
            ci_job=job_name,
            line=line,
        )

    def _parse_kaniko_args(
        self, args_str: str, file_path: str, job_name: str, line: int
    ) -> CIDockerBuild:
        """Parse kaniko executor arguments (--dockerfile, --context, --destination)."""
        tokens = args_str.split()
        dockerfile = "Dockerfile"
        context = "."
        tag: Optional[str] = None
        target_stage: Optional[str] = None

        for token in tokens:
            if token.startswith("--dockerfile="):
                dockerfile = token.split("=", 1)[1].strip("'\"")
            elif token.startswith("--context="):
                context = token.split("=", 1)[1].strip("'\"")
            elif token.startswith("--destination="):
                tag = token.split("=", 1)[1].strip("'\"")
            elif token.startswith("--target="):
                target_stage = token.split("=", 1)[1].strip("'\"")

        return CIDockerBuild(
            dockerfile_path=dockerfile,
            context_path=context,
            image_tag=tag,
            target_stage=target_stage,
            builder_tool="kaniko",
            ci_file=file_path,
            ci_job=job_name,
            line=line,
        )

    def _normalize_image_dict(
        self, raw_image: str, file_path: str, line: int, job_name: str = ""
    ) -> dict[str, Any]:
        """Convert a raw image reference into an SBOM/container image record."""
        nm, tag, dig = split_image(raw_image)
        return {
            "ref": raw_image,
            "name": nm,
            "tag": tag,
            "digest": dig,
            "kind": classify_image(nm),
            "file": file_path,
            "line": line,
            "job": job_name,
            "stage": 0,
            "final": False,
        }
