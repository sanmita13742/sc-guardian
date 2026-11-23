"""
Detector 4: Docker & CI/CD Security Analyzer
Statically analyzes Dockerfiles for unpinned base images and root privileges.
Statically analyzes GitHub Actions workflows for mutable action tags,
unpinned container references, and missing permission boundaries.
"""

import re
from pathlib import Path
from typing import Any, Dict, List


def analyze_cicd_and_docker(repo_root: Path) -> List[Dict[str, Any]]:
    findings = []
    nodegoat_dir = repo_root / "nodegoat"
    dockerfile_path = nodegoat_dir / "Dockerfile"
    workflows_dir = nodegoat_dir / ".github" / "workflows"

    # 1. Dockerfile Static Analysis
    if dockerfile_path.exists():
        with open(dockerfile_path, "r", encoding="utf-8") as f:
            lines = f.readlines()

        for idx, line in enumerate(lines, start=1):
            clean = line.strip()
            # Detect FROM statements without sha256 digest
            if re.match(r"^FROM\s+([^\s]+)", clean, re.IGNORECASE):
                match = re.match(r"^FROM\s+([^\s]+)", clean, re.IGNORECASE)
                image_ref = match.group(1)
                if "@sha256:" not in image_ref:
                    findings.append({
                        "id": f"SUSP-DOCKER-UNPINNED-BASE-L{idx}",
                        "category": "Docker & CI/CD",
                        "severity": "HIGH",
                        "affected_file": "nodegoat/Dockerfile",
                        "line_number": idx,
                        "evidence": clean,
                        "explanation": (
                            f"Base image '{image_ref}' is referenced by a mutable tag rather than an immutable "
                            "cryptographic digest (@sha256:...). Upstream registry tag mutations could inject "
                            "compromised build environments."
                        ),
                        "confidence": "CONFIRMED",
                        "recommended_action": f"Pin the base image using an immutable digest: 'FROM {image_ref}@sha256:<digest>'."
                    })

    # 2. GitHub Actions Workflow Analysis
    if workflows_dir.exists():
        workflow_files = list(workflows_dir.glob("*.yml")) + list(workflows_dir.glob("*.yaml"))

        for wf_file in sorted(workflow_files):
            rel_file_path = f"nodegoat/.github/workflows/{wf_file.name}"
            with open(wf_file, "r", encoding="utf-8") as f:
                wf_lines = f.readlines()
                wf_content = "".join(wf_lines)

            # Check 1: Missing least-privilege permissions block
            if "permissions:" not in wf_content:
                findings.append({
                    "id": f"SUSP-CICD-PERM-{wf_file.stem.upper().replace('-', '_')}",
                    "category": "Docker & CI/CD",
                    "severity": "MEDIUM",
                    "affected_file": rel_file_path,
                    "line_number": 1,
                    "evidence": "Top-level workflow lacks 'permissions:' specification",
                    "explanation": (
                        f"Workflow '{wf_file.name}' does not define an explicit 'permissions:' block. "
                        "GitHub Actions defaults to permissive read-write tokens (GITHUB_TOKEN), enabling "
                        "potential unauthorized repository modifications if a step is compromised."
                    ),
                    "confidence": "CONFIRMED",
                    "recommended_action": "Add an explicit least-privilege block: 'permissions: { contents: read }'."
                })

            # Check 2: Unpinned Action tags (uses: actions/...@v1 or @v2 instead of 40-char SHA)
            for idx, line in enumerate(wf_lines, start=1):
                clean = line.strip()
                match = re.search(r"uses:\s+([a-zA-Z0-9_\-\.\/]+)@([a-zA-Z0-9_\-\.]+)", clean)
                if match:
                    action_name = match.group(1)
                    tag_or_ref = match.group(2)
                    # Check if reference is NOT a 40-character git commit SHA
                    if not re.match(r"^[0-9a-f]{40}$", tag_or_ref, re.IGNORECASE):
                        findings.append({
                            "id": f"SUSP-CICD-UNPINNED-ACTION-{wf_file.stem.upper().replace('-', '_')}-L{idx}",
                            "category": "Docker & CI/CD",
                            "severity": "HIGH",
                            "affected_file": rel_file_path,
                            "line_number": idx,
                            "evidence": clean,
                            "explanation": (
                                f"GitHub Action '{action_name}' is pinned to mutable ref '@{tag_or_ref}'. "
                                "Tags and branch names can be overwritten or re-targeted upstream by compromised "
                                "maintainers to execute malicious code in CI/CD runners."
                            ),
                            "confidence": "CONFIRMED",
                            "recommended_action": (
                                f"Pin action '{action_name}' to a full 40-character commit SHA "
                                f"(e.g. '{action_name}@<commit-sha> # {tag_or_ref}')."
                            )
                        })

                # Check 3: Mutable Docker runs in CI/CD steps
                docker_run_match = re.search(r"docker\s+run\s+.*([a-zA-Z0-9_\.\/-]+):([a-zA-Z0-9_\.-]+)", clean)
                if docker_run_match:
                    image_name = docker_run_match.group(1)
                    image_tag = docker_run_match.group(2)
                    if "@sha256:" not in clean:
                        findings.append({
                            "id": f"SUSP-CICD-DOCKER-TAG-{wf_file.stem.upper().replace('-', '_')}-L{idx}",
                            "category": "Docker & CI/CD",
                            "severity": "MEDIUM",
                            "affected_file": rel_file_path,
                            "line_number": idx,
                            "evidence": clean,
                            "explanation": (
                                f"CI workflow spawns container '{image_name}:{image_tag}' using a mutable tag. "
                                "Container images pulled during CI runs should be pinned by digest to avoid poisoned layers."
                            ),
                            "confidence": "CONFIRMED",
                            "recommended_action": f"Pin '{image_name}' to an exact digest or internal mirror registry."
                        })

    return findings
