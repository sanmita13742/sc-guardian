"""Azure Pipelines adapter (azure-pipelines.yml)."""
from __future__ import annotations

import re
from typing import Any, Optional

import yaml

from pipeline_analysis.ci_adapters.base import BaseCIAdapter
from pipeline_analysis.ci_models import CIDockerBuild, UnifiedJob, UnifiedPipeline, UnifiedStep
from pipeline_analysis.dockerfile import INSECURE, PIPE_TO_SHELL
from pipeline_analysis.models import PipelineFinding

AZURE_FILE_RE = re.compile(r"(^|/)(azure-pipelines.*\.ya?ml|\.azure-pipelines/.*\.ya?ml)$", re.IGNORECASE)
AZURE_INJECTABLE = re.compile(
    r"\$\(\s*(?:Build\.(?:SourceVersionMessage|SourceBranchName)|System\.PullRequest\.\w+)\s*\)",
    re.IGNORECASE,
)


class AzurePipelinesAdapter(BaseCIAdapter):
    """Adapter for Azure DevOps Pipelines."""

    @property
    def platform_id(self) -> str:
        return "azure_pipelines"

    @property
    def platform_name(self) -> str:
        return "Azure Pipelines"

    def can_handle(self, file_path: str) -> bool:
        norm = file_path.replace("\\", "/")
        return bool(AZURE_FILE_RE.search(norm))

    def analyze(self, text: str, file_path: str) -> UnifiedPipeline:
        pipeline = UnifiedPipeline(platform=self.platform_id, file_path=file_path)
        lines = text.splitlines()

        try:
            data = yaml.safe_load(text)
        except Exception as e:
            pipeline.parse_success = False
            pipeline.error_message = str(e)
            return pipeline

        if not isinstance(data, dict):
            pipeline.parse_success = False
            pipeline.error_message = "Root must be a YAML mapping"
            return pipeline

        pipeline.raw_parsed = data

        # Stages & Jobs extraction
        # Azure pipelines can have:
        # 1. Top-level 'steps:'
        # 2. 'jobs:' list
        # 3. 'stages:' list containing jobs
        steps_list: list[dict[str, Any]] = []

        if isinstance(data.get("steps"), list):
            ujob = UnifiedJob(name="root_job")
            self._process_steps(data["steps"], ujob, pipeline, lines, file_path, "root_job")
            pipeline.jobs["root_job"] = ujob

        if isinstance(data.get("jobs"), list):
            for j in data["jobs"]:
                if isinstance(j, dict):
                    jname = str(j.get("job", j.get("name", "job")))
                    ujob = UnifiedJob(name=jname)
                    if isinstance(j.get("steps"), list):
                        self._process_steps(j["steps"], ujob, pipeline, lines, file_path, jname)
                    pipeline.jobs[jname] = ujob

        if isinstance(data.get("stages"), list):
            for stage in data["stages"]:
                if not isinstance(stage, dict):
                    continue
                sname = str(stage.get("stage", "stage"))
                pipeline.stages.append(sname)
                for j in stage.get("jobs") or []:
                    if isinstance(j, dict):
                        jname = str(j.get("job", j.get("name", f"{sname}_job")))
                        ujob = UnifiedJob(name=jname, stage=sname)
                        if isinstance(j.get("steps"), list):
                            self._process_steps(j["steps"], ujob, pipeline, lines, file_path, jname)
                        pipeline.jobs[jname] = ujob

        # Scan for committed secrets
        pipeline.findings.extend(self._scan_secret_literals(lines, file_path))
        return pipeline

    def _process_steps(
        self,
        steps: list[Any],
        ujob: UnifiedJob,
        pipeline: UnifiedPipeline,
        lines: list[str],
        file_path: str,
        jname: str,
    ) -> None:
        """Process Azure pipeline steps (task, script, bash, pwsh)."""
        for st_ in steps:
            if not isinstance(st_, dict):
                continue

            task = st_.get("task")
            script = st_.get("script") or st_.get("bash") or st_.get("powershell") or st_.get("pwsh")
            inputs = st_.get("inputs") or {}

            ustep = UnifiedStep(
                name=st_.get("displayName", task or "script"),
                task=task if isinstance(task, str) else None,
                command=script if isinstance(script, str) else None,
                with_args=inputs if isinstance(inputs, dict) else {},
            )
            ujob.steps.append(ustep)

            # Analyze Task
            if isinstance(task, str):
                ln = self._find_line(lines, task)
                pipeline.external_dependencies.append(
                    {"kind": "azure_task", "task": task, "file": file_path, "job": jname}
                )

                # Check task unpinned / outdated version (missing @ or @0/@1 where major is old)
                if "@" not in task:
                    pipeline.findings.append(
                        self._create_finding(
                            "AZ001",
                            f"Azure Pipelines task '{task}' is missing explicit version specification",
                            "LOW",
                            file_path,
                            ln,
                            f"task: {task}",
                            task,
                            "Tasks without explicit version pins default to the oldest or arbitrary runtime versions.",
                            "Pin an explicit major version: e.g. `task: Docker@2`.",
                        )
                    )

                # Check Docker task: task: Docker@2 / DockerCompose@0
                if task.startswith("Docker@") or task == "Docker":
                    cmd = str(inputs.get("command", "")).lower()
                    if cmd in ("build", "buildandpush", ""):
                        dfile = str(inputs.get("dockerfile", inputs.get("Dockerfile", "Dockerfile")))
                        ctx = str(inputs.get("buildContext", inputs.get("context", ".")))
                        repo = str(inputs.get("repository", ""))
                        tags = inputs.get("tags")
                        tag_str = None
                        if isinstance(tags, str) and tags.strip():
                            tag_str = f"{repo}:{tags.splitlines()[0].strip()}" if repo else tags.splitlines()[0].strip()
                        elif repo:
                            tag_str = repo

                        cdb = CIDockerBuild(
                            dockerfile_path=dfile,
                            context_path=ctx,
                            image_tag=tag_str,
                            builder_tool="Azure_Docker@2",
                            ci_file=file_path,
                            ci_job=jname,
                            line=ln,
                        )
                        ujob.docker_builds.append(cdb)
                        pipeline.docker_builds.append(cdb)

            # Analyze Script / Bash
            if isinstance(script, str):
                ln = self._find_line(lines, script.strip().splitlines()[0][:60]) if script.strip() else 1

                if PIPE_TO_SHELL.search(script):
                    pipeline.findings.append(
                        self._create_finding(
                            "AZ002",
                            f"Remote script is piped to shell in Azure step in job '{jname}'",
                            "HIGH",
                            file_path,
                            ln,
                            script.strip().splitlines()[0],
                            "curl|sh",
                            "Executes arbitrary code downloaded over the network with pipeline agent privileges.",
                            "Download to disk, verify a cryptographic checksum, then execute.",
                        )
                    )

                if INSECURE.search(script):
                    pipeline.findings.append(
                        self._create_finding(
                            "AZ004",
                            f"TLS verification disabled in Azure step in job '{jname}'",
                            "MEDIUM",
                            file_path,
                            ln,
                            script.strip().splitlines()[0],
                            "insecure",
                            "Disabling TLS verification leaves pipeline downloads open to interception.",
                            "Remove `--insecure` or `-k` flags from curl/wget commands.",
                        )
                    )

                for m in AZURE_INJECTABLE.finditer(script):
                    pipeline.findings.append(
                        self._create_finding(
                            "AZ003",
                            f"Untrusted Azure DevOps variable expanded in inline script in job '{jname}'",
                            "HIGH",
                            file_path,
                            ln,
                            m.group(0),
                            m.group(0),
                            "Direct macro expansion inside inline scripts occurs before execution, permitting command injection.",
                            "Map variable into the environment and access via environment variables.",
                        )
                    )
                    break

                # Extract Docker builds in script
                builds = self._extract_docker_build_from_shell(script, file_path, jname, ln)
                ujob.docker_builds.extend(builds)
                pipeline.docker_builds.extend(builds)
