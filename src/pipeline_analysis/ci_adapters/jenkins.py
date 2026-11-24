"""Jenkins pipeline adapter supporting Declarative and Scripted pipelines."""
from __future__ import annotations

import re
from typing import Any, Optional

from pipeline_analysis.ci_adapters.base import BaseCIAdapter
from pipeline_analysis.ci_models import CIDockerBuild, UnifiedJob, UnifiedPipeline, UnifiedStep
from pipeline_analysis.dockerfile import INSECURE, PIPE_TO_SHELL
from pipeline_analysis.models import PipelineFinding

JENKINS_FILE_RE = re.compile(r"(^|/)(Jenkinsfile(\..*)?|.*\.jenkinsfile)$", re.IGNORECASE)
DOCKER_AGENT_IMG_RE = re.compile(
    r"""(?:agent\s*\{\s*docker\s*\{\s*image\s*['"]([^'"]+)['"]|docker\.image\(\s*['"]([^'"]+)['"]\))""",
    re.IGNORECASE,
)
JENKINS_STAGE_RE = re.compile(r"""stage\(\s*['"]([^'"]+)['"]\s*\)""", re.IGNORECASE)
JENKINS_SH_RE = re.compile(r"""\b(?:sh|bat|powershell)\s+(?:['"]([^'"]+)['"]|""" + r'"""(.*?)""")' , re.DOTALL)
DOCKER_METHOD_BUILD_RE = re.compile(
    r"""docker\.build\(\s*['"]([^'"]+)['"](?:\s*,\s*['"]([^'"]+)['"])?\s*\)""",
    re.IGNORECASE,
)


class JenkinsCIAdapter(BaseCIAdapter):
    """Adapter for Jenkins Declarative and Scripted pipelines."""

    @property
    def platform_id(self) -> str:
        return "jenkins"

    @property
    def platform_name(self) -> str:
        return "Jenkins"

    def can_handle(self, file_path: str) -> bool:
        norm = file_path.replace("\\", "/")
        return bool(JENKINS_FILE_RE.search(norm))

    def analyze(self, text: str, file_path: str) -> UnifiedPipeline:
        pipeline = UnifiedPipeline(platform=self.platform_id, file_path=file_path)
        lines = text.splitlines()

        # Extract Docker agent images
        for m in DOCKER_AGENT_IMG_RE.finditer(text):
            img = m.group(1) or m.group(2)
            if img:
                ln = self._find_line(lines, img)
                im_dict = self._normalize_image_dict(img, file_path, ln, "agent")
                pipeline.container_images.append(im_dict)

                if not im_dict.get("digest") and im_dict.get("tag") in (None, "latest"):
                    pipeline.findings.append(
                        self._create_finding(
                            "JNK001",
                            f"Jenkins Docker agent uses unpinned image '{img}'",
                            "MEDIUM",
                            file_path,
                            ln,
                            f"image '{img}'",
                            img,
                            "Floating or latest tags pull modified upstream images without notification.",
                            "Pin an explicit version and image digest: `image 'myorg/build:1.0.0@sha256:...'`.",
                        )
                    )

        # Extract stages
        current_job: Optional[UnifiedJob] = None
        stages_found: list[str] = []

        for n, raw_line in enumerate(lines, 1):
            line = raw_line.strip()

            # Detect stage declaration
            m_stage = JENKINS_STAGE_RE.search(line)
            if m_stage:
                sname = m_stage.group(1)
                stages_found.append(sname)
                current_job = UnifiedJob(name=sname, stage=sname)
                pipeline.jobs[sname] = current_job

            # Shell step checks
            if re.search(r"\b(?:sh|bat|powershell)\b", line):
                if current_job:
                    current_job.steps.append(UnifiedStep(name="shell", command=line, line=n))

                if PIPE_TO_SHELL.search(line):
                    pipeline.findings.append(
                        self._create_finding(
                            "JNK002",
                            "Remote script is piped to shell in Jenkins step",
                            "HIGH",
                            file_path,
                            n,
                            line,
                            "curl|sh",
                            "Executes arbitrary code downloaded over the network with Jenkins agent privileges.",
                            "Download to a file, verify a checksum/signature, then run.",
                        )
                    )

                if INSECURE.search(line):
                    pipeline.findings.append(
                        self._create_finding(
                            "JNK005",
                            "TLS verification disabled in Jenkins shell step",
                            "MEDIUM",
                            file_path,
                            n,
                            line,
                            "insecure",
                            "Disabling TLS verification permits tampering with downloaded tools or dependencies.",
                            "Remove `--insecure` or `-k` flags from curl/wget commands.",
                        )
                    )

                # Script injection through Groovy GString interpolation: sh "echo ${params.FOO}"
                if re.search(r'sh\s+"[^"]*\$\{params\.[^"]*\}"', line):
                    pipeline.findings.append(
                        self._create_finding(
                            "JNK004",
                            "Unsafe Groovy string interpolation with build params inside `sh` step",
                            "HIGH",
                            file_path,
                            n,
                            line,
                            "params-interpolation",
                            "GString double-quote interpolation executes before passing the command to shell, permitting shell injection via user parameters.",
                            "Use single quotes with environment variables: `sh 'echo $PARAM_NAME'`.",
                            evidence_strength="high",
                        )
                    )

                # Plain credentials passed directly without withCredentials
                if re.search(r"\b(?:password|passwd|secret_key|api_key)\s*=\s*['\"][^'\"]+['\"]", line, re.I):
                    pipeline.findings.append(
                        self._create_finding(
                            "JNK003",
                            "Potential plain-text secret inside Jenkins step command",
                            "HIGH",
                            file_path,
                            n,
                            line,
                            "plain-secret",
                            "Passing raw credentials in shell commands exposes them to console logs and process tables.",
                            "Use `withCredentials` block to inject credentials securely.",
                        )
                    )

                # Extract Docker builds in shell
                builds = self._extract_docker_build_from_shell(
                    line, file_path, current_job.name if current_job else "global", n
                )
                if builds:
                    if current_job:
                        current_job.docker_builds.extend(builds)
                    pipeline.docker_builds.extend(builds)

            # docker.build("tag", "args") method
            m_db = DOCKER_METHOD_BUILD_RE.search(line)
            if m_db:
                tag = m_db.group(1)
                args = m_db.group(2) or "."
                cdb = CIDockerBuild(
                    dockerfile_path="Dockerfile",
                    context_path=args,
                    image_tag=tag,
                    builder_tool="jenkins-docker-plugin",
                    ci_file=file_path,
                    ci_job=current_job.name if current_job else "global",
                    line=n,
                )
                if current_job:
                    current_job.docker_builds.append(cdb)
                pipeline.docker_builds.append(cdb)

        pipeline.stages = stages_found
        # Scan for committed secrets
        pipeline.findings.extend(self._scan_secret_literals(lines, file_path))
        return pipeline
