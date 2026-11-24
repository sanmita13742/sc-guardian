"""GitLab CI/CD pipeline adapter."""
from __future__ import annotations

import re
from typing import Any, Optional

import yaml

from pipeline_analysis.ci_adapters.base import BaseCIAdapter
from pipeline_analysis.ci_models import CIDockerBuild, UnifiedJob, UnifiedPipeline, UnifiedStep
from pipeline_analysis.dockerfile import INSECURE, PIPE_TO_SHELL
from pipeline_analysis.models import PipelineFinding

GITLAB_CI_RE = re.compile(r"(^|/)\.gitlab-ci\.ya?ml$", re.IGNORECASE)
RESERVED_TOP_KEYS = {
    "stages",
    "variables",
    "include",
    "default",
    "workflow",
    "image",
    "services",
    "before_script",
    "after_script",
    "cache",
    "types",
}
UNTRUSTED_GITLAB_VARS = re.compile(
    r"\$(?:\{)?(?:CI_MERGE_REQUEST_(?:TITLE|DESCRIPTION|SOURCE_BRANCH_NAME)|"
    r"CI_COMMIT_(?:MESSAGE|TITLE|DESCRIPTION|TAG|REF_NAME)|CI_EXTERNAL_PULL_REQUEST_\w+)(?:\})?",
    re.IGNORECASE,
)


class GitLabCIAdapter(BaseCIAdapter):
    """Adapter for GitLab CI/CD pipelines (.gitlab-ci.yml)."""

    @property
    def platform_id(self) -> str:
        return "gitlab_ci"

    @property
    def platform_name(self) -> str:
        return "GitLab CI"

    def can_handle(self, file_path: str) -> bool:
        norm = file_path.replace("\\", "/")
        return bool(GITLAB_CI_RE.search(norm))

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

        # Stages
        stages = data.get("stages")
        if isinstance(stages, list):
            pipeline.stages = [str(s) for s in stages]

        # Top-level image and services
        top_image = data.get("image")
        if isinstance(top_image, (str, dict)):
            raw_img = top_image if isinstance(top_image, str) else str(top_image.get("name", ""))
            if raw_img and "$" not in raw_img:
                ln = self._find_line(lines, "image:")
                im_dict = self._normalize_image_dict(raw_img, file_path, ln, "global")
                pipeline.container_images.append(im_dict)
                if not im_dict.get("digest") and im_dict.get("tag") in (None, "latest"):
                    pipeline.findings.append(
                        self._create_finding(
                            "GL001",
                            "Default GitLab CI image is not pinned",
                            "MEDIUM",
                            file_path,
                            ln,
                            f"image: {raw_img}",
                            raw_img,
                            "Using an unpinned or latest tag allows unexpected upstream image changes.",
                            "Pin an explicit version tag and sha256 digest: `image: myimage:1.2.0@sha256:...`.",
                        )
                    )

        # Include directives
        includes = data.get("include")
        if includes:
            inc_list = includes if isinstance(includes, list) else [includes]
            for inc in inc_list:
                pipeline.external_dependencies.append({"kind": "include", "data": inc, "file": file_path})
                if isinstance(inc, dict) and inc.get("remote"):
                    remote_url = str(inc["remote"])
                    if remote_url.startswith("http://"):
                        ln = self._find_line(lines, remote_url)
                        pipeline.findings.append(
                            self._create_finding(
                                "GL003",
                                "GitLab CI includes remote template over plain HTTP",
                                "HIGH",
                                file_path,
                                ln,
                                f"remote: {remote_url}",
                                "http-include",
                                "Unencrypted template downloads can be intercepted and modified in transit.",
                                "Change remote URL to use HTTPS and verify template integrity.",
                            )
                        )

        # Iterate jobs
        for key, val in data.items():
            if key in RESERVED_TOP_KEYS or key.startswith("."):
                continue
            if not isinstance(val, dict):
                continue

            jname = key
            ujob = UnifiedJob(name=jname, stage=str(val.get("stage", "default")))

            # Job image
            job_img = val.get("image")
            if isinstance(job_img, (str, dict)):
                raw_jimg = job_img if isinstance(job_img, str) else str(job_img.get("name", ""))
                if raw_jimg and "$" not in raw_jimg:
                    ln = self._find_line(lines, raw_jimg)
                    im_dict = self._normalize_image_dict(raw_jimg, file_path, ln, jname)
                    pipeline.container_images.append(im_dict)
                    ujob.container_image = raw_jimg
                    if not im_dict.get("digest") and im_dict.get("tag") in (None, "latest"):
                        pipeline.findings.append(
                            self._create_finding(
                                "GL001",
                                f"Job '{jname}' uses an unpinned container image",
                                "MEDIUM",
                                file_path,
                                ln,
                                f"image: {raw_jimg}",
                                raw_jimg,
                                "Floating or latest tags may silently pull modified upstream layers.",
                                "Pin an explicit version and sha256 digest.",
                            )
                        )

            # Services (e.g. docker:dind)
            services = val.get("services") or []
            if isinstance(services, list):
                for s in services:
                    s_name = s if isinstance(s, str) else (s.get("name", "") if isinstance(s, dict) else "")
                    if s_name:
                        ujob.services.append(s_name)
                        ln = self._find_line(lines, s_name)
                        if "docker:dind" in s_name or (isinstance(s, dict) and s.get("privileged") is True):
                            pipeline.findings.append(
                                self._create_finding(
                                    "GL002",
                                    f"Job '{jname}' uses privileged Docker-in-Docker service",
                                    "MEDIUM",
                                    file_path,
                                    ln,
                                    f"services: {s_name}",
                                    "docker:dind",
                                    "Privileged DinD gives the container host-level capabilities, increasing the risk of container breakout.",
                                    "Prefer rootless container build tools like Kaniko or Buildah.",
                                    evidence_strength="medium",
                                )
                            )

            # Scripts
            script_blocks: list[str] = []
            for field_name in ("before_script", "script", "after_script"):
                cmds = val.get(field_name) or []
                if isinstance(cmds, list):
                    for cmd in cmds:
                        if isinstance(cmd, str):
                            script_blocks.append(cmd)
                            ustep = UnifiedStep(name=f"{field_name}_step", command=cmd)
                            ujob.steps.append(ustep)
                elif isinstance(cmds, str):
                    script_blocks.append(cmds)
                    ujob.steps.append(UnifiedStep(name=field_name, command=cmds))

            combined_script = "\n".join(script_blocks)

            # Check script-level rules
            for cmd in script_blocks:
                ln = self._find_line(lines, cmd[:60])

                if PIPE_TO_SHELL.search(cmd):
                    pipeline.findings.append(
                        self._create_finding(
                            "GL004",
                            f"Remote script piped into shell in job '{jname}'",
                            "HIGH",
                            file_path,
                            ln,
                            cmd,
                            "curl|sh",
                            "Executes arbitrary remote script with the runner job's tokens and privileges.",
                            "Download to disk, verify a pinned cryptographic hash or signature, and execute.",
                        )
                    )

                if INSECURE.search(cmd):
                    pipeline.findings.append(
                        self._create_finding(
                            "GL005",
                            f"TLS verification disabled in job '{jname}'",
                            "MEDIUM",
                            file_path,
                            ln,
                            cmd,
                            "insecure",
                            "Disabling TLS verification leaves network traffic open to man-in-the-middle tampering.",
                            "Remove `--insecure` or `GIT_SSL_NO_VERIFY` flags.",
                        )
                    )

                for m in UNTRUSTED_GITLAB_VARS.finditer(cmd):
                    pipeline.findings.append(
                        self._create_finding(
                            "GL006",
                            f"Untrusted GitLab CI variable expanded directly in script in job '{jname}'",
                            "HIGH",
                            file_path,
                            ln,
                            cmd,
                            m.group(0),
                            "User-controlled merge request titles or commit messages expanded inside bash steps enable command injection.",
                            "Store the variable into an environment variable or escape it securely.",
                        )
                    )
                    break

                if re.search(r"echo\s+.*CI_JOB_TOKEN", cmd, re.IGNORECASE):
                    pipeline.findings.append(
                        self._create_finding(
                            "GL007",
                            f"CI_JOB_TOKEN appears to be printed to logs in job '{jname}'",
                            "MEDIUM",
                            file_path,
                            ln,
                            cmd,
                            "token-echo",
                            "Printing job tokens to logs exposes them in build artifacts and job outputs.",
                            "Mask or omit token printing from shell scripts.",
                        )
                    )

            # Extract Docker / Kaniko / Buildah builds
            builds = self._extract_docker_build_from_shell(combined_script, file_path, jname)
            ujob.docker_builds.extend(builds)
            pipeline.docker_builds.extend(builds)

            pipeline.jobs[jname] = ujob

        # Scan for committed secrets
        pipeline.findings.extend(self._scan_secret_literals(lines, file_path))
        return pipeline
