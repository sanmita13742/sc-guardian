"""Multi-CI platform adapters package."""
from pipeline_analysis.ci_adapters.azure_pipelines import AzurePipelinesAdapter
from pipeline_analysis.ci_adapters.base import BaseCIAdapter
from pipeline_analysis.ci_adapters.circleci import CircleCIAdapter
from pipeline_analysis.ci_adapters.github_actions import GitHubActionsAdapter
from pipeline_analysis.ci_adapters.gitlab_ci import GitLabCIAdapter
from pipeline_analysis.ci_adapters.jenkins import JenkinsCIAdapter
from pipeline_analysis.ci_adapters.registry import (
    CIAdapterRegistry,
    analyze_ci_pipeline,
    get_adapter_for_file,
)

__all__ = [
    "BaseCIAdapter",
    "GitHubActionsAdapter",
    "GitLabCIAdapter",
    "JenkinsCIAdapter",
    "CircleCIAdapter",
    "AzurePipelinesAdapter",
    "CIAdapterRegistry",
    "get_adapter_for_file",
    "analyze_ci_pipeline",
]
