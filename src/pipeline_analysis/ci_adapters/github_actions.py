"""GitHub Actions pipeline adapter."""
from __future__ import annotations

import re
from typing import Any, Optional

import yaml

from pipeline_analysis.ci import (
    DEPRECATED_BELOW,
    FIRST_PARTY,
    INJECTABLE,
    INJECTABLE_FIELDS,
    SHA40,
    UNTRUSTED_TRIGGERS,
    parse_action_ref,
)
from pipeline_analysis.ci_adapters.base import BaseCIAdapter
from pipeline_analysis.ci_models import CIDockerBuild, UnifiedJob, UnifiedPipeline, UnifiedStep
from pipeline_analysis.dockerfile import INSECURE, PIPE_TO_SHELL
from pipeline_analysis.models import PipelineFinding

GHA_FILE_RE = re.compile(r"^(.*/)?\.github/workflows/[^/]+\.ya?ml$", re.IGNORECASE)


class GitHubActionsAdapter(BaseCIAdapter):
    """Adapter for GitHub Actions workflows (.github/workflows/*.yml)."""

    @property
    def platform_id(self) -> str:
        return "github_actions"

    @property
    def platform_name(self) -> str:
        return "GitHub Actions"

    def can_handle(self, file_path: str) -> bool:
        norm = file_path.replace("\\", "/")
        return bool(GHA_FILE_RE.match(norm))

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

        # Triggers
        on = data.get("on", data.get(True))  # PyYAML parses unquoted 'on:' as True
        triggers = set(on) if isinstance(on, (dict, list)) else ({on} if isinstance(on, str) else set())
        triggers_set = {str(t) for t in triggers}
        pipeline.triggers = sorted(triggers_set)

        untrusted = bool(triggers_set & UNTRUSTED_TRIGGERS)
        pr_trigger = bool(triggers_set & {"pull_request", "pull_request_target"})

        # Global permissions check
        perms = data.get("permissions")
        raw_jobs = data.get("jobs") if isinstance(data.get("jobs"), dict) else {}

        if perms is None and not any(isinstance(j, dict) and j.get("permissions") is not None for j in raw_jobs.values()):
            pipeline.findings.append(
                self._create_finding(
                    "GHA004",
                    "No explicit token permissions (defaults may be read-write)",
                    "LOW",
                    file_path,
                    1,
                    "(no `permissions:` key)",
                    "permissions",
                    "Without an explicit `permissions:` block the GITHUB_TOKEN gets the repository default, which can include write access.",
                    "Add a top-level `permissions: contents: read` and grant extra scopes per job.",
                    evidence_strength="medium",
                    references=["https://docs.github.com/actions/security-guides/automatic-token-authentication"],
                )
            )

        if perms in ("write-all",) or (isinstance(perms, dict) and any(v == "write" for v in perms.values()) and untrusted):
            pipeline.findings.append(
                self._create_finding(
                    "GHA004",
                    "Over-broad GITHUB_TOKEN permissions",
                    "HIGH",
                    file_path,
                    self._find_line(lines, "permissions"),
                    "permissions: " + (perms if isinstance(perms, str) else "write scopes"),
                    "permissions",
                    "A write-capable token in a workflow reachable by untrusted input lets an attacker modify the repository.",
                    "Use least privilege (`contents: read`).",
                )
            )

        # Parse jobs
        for jname, job in raw_jobs.items():
            if not isinstance(job, dict):
                continue

            ujob = UnifiedJob(name=jname)
            runs_on = job.get("runs-on")
            ro = " ".join(map(str, runs_on)) if isinstance(runs_on, list) else str(runs_on or "")
            ujob.runs_on = ro

            if "self-hosted" in ro and pr_trigger:
                pipeline.findings.append(
                    self._create_finding(
                        "GHA006",
                        f"Job '{jname}' runs untrusted pull-request code on a self-hosted runner",
                        "HIGH",
                        file_path,
                        self._find_line(lines, "self-hosted"),
                        f"runs-on: {ro}",
                        jname,
                        "Self-hosted runners persist state and often have network access to internal systems; a malicious PR can pivot from them.",
                        "Use ephemeral GitHub-hosted runners for pull_request workflows, or require approval for outside contributors.",
                    )
                )

            if job.get("secrets") == "inherit":
                pipeline.findings.append(
                    self._create_finding(
                        "GHA005",
                        f"Job '{jname}' passes all secrets to a reusable workflow",
                        "MEDIUM",
                        file_path,
                        self._find_line(lines, "secrets: inherit"),
                        "secrets: inherit",
                        jname,
                        "Every repository secret is exposed to the called workflow.",
                        "Pass only the specific secrets required.",
                        evidence_strength="medium",
                    )
                )

            # Reusable workflow
            if isinstance(job.get("uses"), str):
                ref = parse_action_ref(job["uses"])
                if ref and ref.get("kind") == "action":
                    pipeline.external_dependencies.append(
                        {**ref, "file": file_path, "line": self._find_line(lines, job["uses"]), "job": jname, "reusable_workflow": True}
                    )

            # Steps
            steps = job.get("steps") or []
            for st_ in steps:
                if not isinstance(st_, dict):
                    continue

                uses = st_.get("uses")
                run = st_.get("run")
                withd = st_.get("with") or {}

                ustep = UnifiedStep(
                    name=st_.get("name", ""),
                    command=run if isinstance(run, str) else None,
                    uses=uses if isinstance(uses, str) else None,
                    with_args=withd if isinstance(withd, dict) else {},
                )
                ujob.steps.append(ustep)

                # Process uses:
                if isinstance(uses, str):
                    ref = parse_action_ref(uses)
                    ln = self._find_line(lines, uses)
                    if ref:
                        pipeline.external_dependencies.append({**ref, "file": file_path, "line": ln, "job": jname})

                        # Docker container used as action
                        if ref.get("kind") == "docker":
                            pipeline.container_images.append(
                                self._normalize_image_dict(uses.replace("docker://", ""), file_path, ln, jname)
                            )

                        if ref.get("kind") == "action" and not ref.get("pinned"):
                            branchy = ref["ref"] in ("main", "master", "latest", "develop", "dev", "trunk")
                            sev = "HIGH" if branchy else ("LOW" if ref.get("first_party") else "MEDIUM")
                            pipeline.findings.append(
                                self._create_finding(
                                    "GHA001",
                                    f"Action '{ref['name']}' is not pinned to a commit SHA",
                                    sev,
                                    file_path,
                                    ln,
                                    f"uses: {uses}",
                                    uses,
                                    ("The reference is a moving branch: " if branchy else "Tags can be moved or re-pointed: ")
                                    + "a compromised upstream changes what your pipeline runs.",
                                    f"Pin to the full 40-character commit SHA: `uses: {ref['name']}@<sha> # {ref['ref']}`.",
                                    references=["https://docs.github.com/actions/security-guides/security-hardening-for-github-actions#using-third-party-actions"],
                                    third_party=not ref.get("first_party"),
                                )
                            )

                        if ref.get("kind") == "action" and ref["name"].lower() in DEPRECATED_BELOW:
                            mm = re.match(r"^v?(\d+)", ref["ref"] or "")
                            if mm and int(mm.group(1)) < DEPRECATED_BELOW[ref["name"].lower()]:
                                pipeline.findings.append(
                                    self._create_finding(
                                        "GHA012",
                                        f"Action '{ref['name']}@{ref['ref']}' is an outdated major version",
                                        "MEDIUM",
                                        file_path,
                                        ln,
                                        f"uses: {uses}",
                                        uses + "#outdated",
                                        "This major runs on an end-of-life Node.js runtime or was deprecated/shut down by GitHub.",
                                        f"Upgrade to {ref['name']}@v{DEPRECATED_BELOW[ref['name'].lower()]} or newer.",
                                        evidence_strength="medium",
                                    )
                                )

                    # Check out of untrusted PR in privileged workflow
                    if "checkout" in uses:
                        r = str(withd.get("ref", ""))
                        if ("pull_request.head" in r or "head_ref" in r or "workflow_run.head" in r) and (
                            triggers_set & {"pull_request_target", "workflow_run"}
                        ):
                            pipeline.findings.append(
                                self._create_finding(
                                    "GHA002",
                                    f"Job '{jname}' checks out untrusted pull-request code in a privileged workflow",
                                    "CRITICAL",
                                    file_path,
                                    self._find_line(lines, "ref:", max(ln - 1, 0)),
                                    f"{', '.join(sorted(triggers_set & {'pull_request_target', 'workflow_run'}))} + checkout of PR head",
                                    jname,
                                    "Privileged workflows run with secrets and write tokens; checking out untrusted PR head allows arbitrary code execution.",
                                    "Never check out PR head code in pull_request_target/workflow_run workflows.",
                                    references=["https://securitylab.github.com/resources/github-actions-preventing-pwn-requests/"],
                                )
                            )

                    # Extract docker/build-push-action
                    if "docker/build-push-action" in uses:
                        tags_raw = withd.get("tags") or withd.get("tag") or ""
                        first_tag = tags_raw.strip().splitlines()[0] if isinstance(tags_raw, str) and tags_raw.strip() else None
                        dfile = str(withd.get("file") or "Dockerfile")
                        ctx = str(withd.get("context") or ".")
                        target = str(withd.get("target")) if withd.get("target") else None
                        cdb = CIDockerBuild(
                            dockerfile_path=dfile,
                            context_path=ctx,
                            image_tag=first_tag,
                            target_stage=target,
                            builder_tool="docker/build-push-action",
                            ci_file=file_path,
                            ci_job=jname,
                            line=ln,
                        )
                        ujob.docker_builds.append(cdb)
                        pipeline.docker_builds.append(cdb)

                # Process run:
                if isinstance(run, str):
                    ln = self._find_line(lines, run.strip().splitlines()[0][:60]) if run.strip() else 1

                    # Script injection
                    for m in INJECTABLE.finditer(run):
                        if INJECTABLE_FIELDS.search(m.group(0)):
                            pipeline.findings.append(
                                self._create_finding(
                                    "GHA003",
                                    "Script injection: untrusted event data is expanded inside a `run` step",
                                    "HIGH",
                                    file_path,
                                    ln,
                                    m.group(0),
                                    m.group(0),
                                    "The expression is substituted into the shell script before execution, allowing shell command injection.",
                                    'Pass the value via environment variable (`env: VAL: ${{ ... }}`) and reference "$VAL".',
                                    references=["https://securitylab.github.com/resources/github-actions-untrusted-input/"],
                                )
                            )
                            break

                    if PIPE_TO_SHELL.search(run):
                        pipeline.findings.append(
                            self._create_finding(
                                "GHA007",
                                "Remote script is piped into a shell in a workflow step",
                                "HIGH",
                                file_path,
                                ln,
                                run.strip().splitlines()[0],
                                "curl|sh",
                                "Runs whatever the remote server returns with the workflow's permissions and secrets.",
                                "Download, verify checksum/signature, then run.",
                            )
                        )

                    if INSECURE.search(run):
                        pipeline.findings.append(
                            self._create_finding(
                                "GHA008",
                                "TLS verification disabled in a workflow step",
                                "MEDIUM",
                                file_path,
                                ln,
                                run.strip().splitlines()[0],
                                "insecure",
                                "Allows tampering of downloaded tools and artifacts in transit.",
                                "Remove the insecure flag.",
                            )
                        )

                    if re.search(r"::(set-env|add-path)\b", run):
                        pipeline.findings.append(
                            self._create_finding(
                                "GHA009",
                                "Deprecated, injectable `set-env`/`add-path` workflow command",
                                "HIGH",
                                file_path,
                                ln,
                                run.strip().splitlines()[0],
                                "set-env",
                                "These commands were disabled because untrusted output can overwrite environment variables.",
                                "Write to $GITHUB_ENV or $GITHUB_PATH instead.",
                            )
                        )

                    if re.search(r"echo\s+[\"']?\$\{\{\s*secrets\.", run):
                        pipeline.findings.append(
                            self._create_finding(
                                "GHA010",
                                "A secret is echoed in a run step",
                                "MEDIUM",
                                file_path,
                                ln,
                                "echo ${{ secrets.* }}",
                                "secret echo",
                                "Secrets printed to logs can leak through build log retention or forks.",
                                "Never print secrets.",
                                evidence_strength="medium",
                            )
                        )

                    # Extract docker build CLI commands
                    builds = self._extract_docker_build_from_shell(run, file_path, jname, ln)
                    ujob.docker_builds.extend(builds)
                    pipeline.docker_builds.extend(builds)

            pipeline.jobs[jname] = ujob

        # Scan for committed secrets
        pipeline.findings.extend(self._scan_secret_literals(lines, file_path))
        return pipeline
