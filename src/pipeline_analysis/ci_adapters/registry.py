"""Registry and dispatcher for Multi-CI platform adapters."""
from __future__ import annotations

from typing import Optional

from pipeline_analysis.ci import analyze_generic_ci
from pipeline_analysis.ci_adapters.azure_pipelines import AzurePipelinesAdapter
from pipeline_analysis.ci_adapters.base import BaseCIAdapter
from pipeline_analysis.ci_adapters.circleci import CircleCIAdapter
from pipeline_analysis.ci_adapters.github_actions import GitHubActionsAdapter
from pipeline_analysis.ci_adapters.gitlab_ci import GitLabCIAdapter
from pipeline_analysis.ci_adapters.jenkins import JenkinsCIAdapter
from pipeline_analysis.ci_models import UnifiedPipeline


class GenericCIAdapter(BaseCIAdapter):
    """Fallback adapter for unrecognized CI files."""

    @property
    def platform_id(self) -> str:
        return "generic_ci"

    @property
    def platform_name(self) -> str:
        return "CI (generic)"

    def can_handle(self, file_path: str) -> bool:
        return True

    def analyze(self, text: str, file_path: str) -> UnifiedPipeline:
        findings, images = analyze_generic_ci(text, file_path)
        pipeline = UnifiedPipeline(
            platform=self.platform_id,
            file_path=file_path,
            findings=findings,
            container_images=images,
        )
        return pipeline


class CIAdapterRegistry:
    """Registry managing available CI platform adapters."""

    def __init__(self) -> None:
        self._adapters: list[BaseCIAdapter] = [
            GitHubActionsAdapter(),
            GitLabCIAdapter(),
            JenkinsCIAdapter(),
            CircleCIAdapter(),
            AzurePipelinesAdapter(),
        ]
        self._fallback = GenericCIAdapter()

    def register_adapter(self, adapter: BaseCIAdapter) -> None:
        """Register a new custom CI adapter at highest priority."""
        self._adapters.insert(0, adapter)

    def get_adapter(self, file_path: str) -> BaseCIAdapter:
        """Return the first adapter that can handle file_path, or fallback."""
        for adapter in self._adapters:
            if adapter.can_handle(file_path):
                return adapter
        return self._fallback

    def analyze_file(self, text: str, file_path: str) -> UnifiedPipeline:
        """Find matching adapter and execute pipeline analysis."""
        adapter = self.get_adapter(file_path)
        return adapter.analyze(text, file_path)


# Global singleton instance
REGISTRY = CIAdapterRegistry()


def get_adapter_for_file(file_path: str) -> BaseCIAdapter:
    return REGISTRY.get_adapter(file_path)


def analyze_ci_pipeline(text: str, file_path: str) -> UnifiedPipeline:
    return REGISTRY.analyze_file(text, file_path)
