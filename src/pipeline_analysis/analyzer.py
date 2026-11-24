"""Pipeline Agent engine: analyse every Dockerfile, compose file and CI definition found by Recon.

Returns findings (with stable ids), the images and actions the repository depends on (to become SBOM components), and per-file coverage.
Only files already discovered by ``core.repository_inspector`` are read, through its path-confined, size-capped ``safe_read_text``.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from core.repository_inspector import safe_read_text
from pipeline_analysis.ci_adapters import analyze_ci_pipeline
from pipeline_analysis.dockerfile import analyze_compose, analyze_dockerfile
from pipeline_analysis.models import PipelineFinding

SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}


def is_github_workflow(path: str) -> bool:
    return bool(re.match(r"^(.*/)?\.github/workflows/[^/]+\.ya?ml$", path))


def analyze_repository(root: Path, dockerfiles: list[str], container_files: list[str], ci_files: list[str], scan_timestamp: str = "") -> dict[str, Any]:
    findings: list[PipelineFinding] = []
    images: list[dict] = []
    actions: list[dict] = []
    files: list[dict] = []
    seen_ci: set[str] = set()
    for rel in dockerfiles:
        text = safe_read_text(root, rel)
        if text is None:
            files.append({"file": rel, "type": "Dockerfile", "status": "unreadable"})
            continue
        f, im = analyze_dockerfile(text, rel)
        findings += f
        images += im
        files.append({"file": rel, "type": "Dockerfile", "status": "analysed", "findings": len(f), "images": len(im)})
    for rel in container_files:
        name = rel.rsplit("/", 1)[-1]
        if not name.lower().startswith(("docker-compose", "compose")):
            continue
        text = safe_read_text(root, rel)
        if text is None:
            files.append({"file": rel, "type": "compose", "status": "unreadable"})
            continue
        f, im = analyze_compose(text, rel)
        findings += f
        images += im
        files.append({"file": rel, "type": "compose", "status": "analysed", "findings": len(f), "images": len(im)})
    docker_builds: list[dict] = []
    for rel in ci_files:
        if rel in seen_ci:
            continue
        seen_ci.add(rel)
        if rel.endswith("/") or not re.search(r"\.(ya?ml|groovy)$|Jenkinsfile", rel, re.IGNORECASE):
            continue
        text = safe_read_text(root, rel)
        if text is None:
            files.append({"file": rel, "type": "CI", "status": "unreadable"})
            continue
        pipe_obj = analyze_ci_pipeline(text, rel)
        findings += pipe_obj.findings
        images += pipe_obj.container_images
        actions += pipe_obj.external_dependencies
        for db in pipe_obj.docker_builds:
            docker_builds.append(db.__dict__ if hasattr(db, "__dict__") else db)
        files.append({
            "file": rel,
            "type": f"{pipe_obj.platform} workflow",
            "status": "analysed" if pipe_obj.parse_success else "parse_error",
            "findings": len(pipe_obj.findings),
            "actions": len(pipe_obj.external_dependencies),
            "docker_builds": len(pipe_obj.docker_builds),
        })
    # stable ids, de-duplicated by (rule, file, line, subject), worst first
    uniq: dict[tuple, PipelineFinding] = {}
    for f in findings:
        uniq.setdefault((f.rule_id, f.file, f.line, f.subject), f)
    ordered = sorted(uniq.values(), key=lambda f: (SEV_ORDER.get(f.severity, 9), f.file, f.line, f.rule_id))
    for n, f in enumerate(ordered, 1):
        f.finding_id = f"PIPE-{n:03d}"
        f.scan_timestamp = scan_timestamp
    by_sev: dict[str, int] = {}
    for f in ordered:
        by_sev[f.severity] = by_sev.get(f.severity, 0) + 1
    unpinned_actions = [a for a in actions if a.get("kind") == "action" and not a.get("pinned")]
    return {"findings": [f.model_dump() for f in ordered], "images": images, "actions": actions, "files": files, "docker_builds": docker_builds,
            "summary": {"files_analysed": sum(1 for x in files if x["status"] == "analysed"), "findings": len(ordered), "by_severity": by_sev, "images": len(images), "actions": len(actions),
                        "actions_unpinned": len(unpinned_actions), "images_unpinned": sum(1 for i in images if not i.get("digest")), "docker_builds": len(docker_builds)}}
