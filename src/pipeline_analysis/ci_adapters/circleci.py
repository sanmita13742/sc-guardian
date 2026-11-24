"""CircleCI pipeline adapter (.circleci/config.yml)."""
from __future__ import annotations

import re
from typing import Any, Optional

import yaml

from pipeline_analysis.ci_adapters.base import BaseCIAdapter
from pipeline_analysis.ci_models import CIDockerBuild, UnifiedJob, UnifiedPipeline, UnifiedStep
from pipeline_analysis.dockerfile import INSECURE, PIPE_TO_SHELL
from pipeline_analysis.models import PipelineFinding

CIRCLECI_FILE_RE = re.compile(r"(^|/)\.circleci/config\.ya?ml$", re.IGNORECASE)


class CircleCIAdapter(BaseCIAdapter):
    """Adapter for CircleCI 2.1+ configuration."""

    @property
    def platform_id(self) -> str:
        return "circleci"

    @property
    def platform_name(self) -> str:
        return "CircleCI"

    def can_handle(self, file_path: str) -> bool:
        norm = file_path.replace("\\", "/")
        return bool(CIRCLECI_FILE_RE.search(norm))

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

        # Check Orbs
        orbs = data.get("orbs")
        if isinstance(orbs, dict):
            for orb_alias, orb_ref in orbs.items():
                if isinstance(orb_ref, str):
                    pipeline.external_dependencies.append(
                        {"kind": "orb", "alias": orb_alias, "ref": orb_ref, "file": file_path}
                    )
                    ln = self._find_line(lines, orb_ref)
                    # Check if orb is unpinned (@volatile or major version without minor/patch)
                    if "@volatile" in orb_ref or re.search(r"@\d+$", orb_ref):
                        pipeline.findings.append(
                            self._create_finding(
                                "CIR001",
                                f"CircleCI orb '{orb_alias}' uses floating or volatile version '{orb_ref}'",
                                "MEDIUM",
                                file_path,
                                ln,
                                f"{orb_alias}: {orb_ref}",
                                orb_ref,
                                "Floating or volatile orb versions permit upstream maintainers or attackers to change job execution logic without review.",
                                "Pin to a specific semantic version (e.g., `circleci/docker@2.1.4`).",
                            )
                        )

        # Parse Jobs
        raw_jobs = data.get("jobs") or {}
        if isinstance(raw_jobs, dict):
            for jname, job in raw_jobs.items():
                if not isinstance(job, dict):
                    continue

                ujob = UnifiedJob(name=jname)

                # Docker executors
                docker_list = job.get("docker") or []
                if isinstance(docker_list, list):
                    for entry in docker_list:
                        if isinstance(entry, dict) and entry.get("image"):
                            raw_img = str(entry["image"])
                            ln = self._find_line(lines, raw_img)
                            im_dict = self._normalize_image_dict(raw_img, file_path, ln, jname)
                            pipeline.container_images.append(im_dict)

                            if not im_dict.get("digest") and im_dict.get("tag") in (None, "latest"):
                                pipeline.findings.append(
                                    self._create_finding(
                                        "CIR002",
                                        f"CircleCI job '{jname}' uses unpinned docker executor image",
                                        "MEDIUM",
                                        file_path,
                                        ln,
                                        f"image: {raw_img}",
                                        raw_img,
                                        "Floating or latest executor images silently update dependencies and build environment tools.",
                                        "Pin an explicit version tag and sha256 digest: `image: cimg/python:3.11.4@sha256:...`.",
                                    )
                                )

                # Steps
                steps = job.get("steps") or []
                for st_ in steps:
                    if isinstance(st_, str):
                        ujob.steps.append(UnifiedStep(name=st_))
                        continue

                    if not isinstance(st_, dict):
                        continue

                    run_step = st_.get("run")
                    cmd_str = ""
                    sname = "step"

                    if isinstance(run_step, str):
                        cmd_str = run_step
                    elif isinstance(run_step, dict):
                        cmd_str = str(run_step.get("command", ""))
                        sname = str(run_step.get("name", "run"))
                    elif "setup_remote_docker" in st_:
                        sname = "setup_remote_docker"

                    ustep = UnifiedStep(name=sname, command=cmd_str if cmd_str else None)
                    ujob.steps.append(ustep)

                    if cmd_str:
                        ln = self._find_line(lines, cmd_str.strip().splitlines()[0][:60]) if cmd_str.strip() else 1

                        if PIPE_TO_SHELL.search(cmd_str):
                            pipeline.findings.append(
                                self._create_finding(
                                    "CIR003",
                                    f"Remote script is piped to shell in CircleCI job '{jname}'",
                                    "HIGH",
                                    file_path,
                                    ln,
                                    cmd_str.strip().splitlines()[0],
                                    "curl|sh",
                                    "Runs unverified code downloaded over the network with pipeline executor privileges.",
                                    "Download to disk, verify a cryptographic checksum, then execute.",
                                )
                            )

                        if INSECURE.search(cmd_str):
                            pipeline.findings.append(
                                self._create_finding(
                                    "CIR004",
                                    f"TLS verification disabled in CircleCI job '{jname}'",
                                    "MEDIUM",
                                    file_path,
                                    ln,
                                    cmd_str.strip().splitlines()[0],
                                    "insecure",
                                    "Disabling TLS verification leaves pipeline downloads open to interception.",
                                    "Remove `--insecure` or `-k` flags from curl/wget commands.",
                                )
                            )

                        # Extract Docker builds in run command
                        builds = self._extract_docker_build_from_shell(cmd_str, file_path, jname, ln)
                        ujob.docker_builds.extend(builds)
                        pipeline.docker_builds.extend(builds)

                pipeline.jobs[jname] = ujob

        # Scan for committed secrets
        pipeline.findings.extend(self._scan_secret_literals(lines, file_path))
        return pipeline
