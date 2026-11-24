"""Container image and build specification discovery engine."""
from __future__ import annotations

from pathlib import Path
from typing import Any, Optional

from containers.models import DiscoveredContainerAsset
from core.repository_inspector import safe_read_text
from pipeline_analysis.dockerfile import analyze_compose, parse_dockerfile, split_image


def discover_container_assets(
    repo_root: Path,
    dockerfiles: list[str],
    container_files: list[str],
    ci_docker_builds: Optional[list[dict[str, Any]]] = None,
) -> list[DiscoveredContainerAsset]:
    """Correlate Dockerfiles, Compose files, and CI Docker builds into canonical container assets."""
    assets: list[DiscoveredContainerAsset] = []
    seen_ids: set[str] = set()
    ci_builds = ci_docker_builds or []

    # Map dockerfile path normalized -> list of CI build directives
    ci_by_df: dict[str, list[dict[str, Any]]] = {}
    for b in ci_builds:
        df_target = str(b.get("dockerfile_path", "Dockerfile")).replace("\\", "/").lstrip("./")
        ci_by_df.setdefault(df_target, []).append(b)

    # 1. Process Dockerfiles
    for rel in dockerfiles:
        norm_rel = rel.replace("\\", "/").lstrip("./")
        text = safe_read_text(repo_root, rel)
        if text is None:
            continue

        instructions = parse_dockerfile(text)
        stages: list[str] = []
        base_images: list[str] = []

        for inst in instructions:
            if inst.op == "FROM":
                # FROM image [AS stage]
                parts = inst.args.split()
                if parts:
                    base_images.append(parts[0])
                if len(parts) >= 3 and parts[1].upper() == "AS":
                    stages.append(parts[2])

        final_base = base_images[-1] if base_images else None
        nm, tag, dig = split_image(final_base) if final_base else (None, None, None)

        # Match with any CI builds
        matching_ci = ci_by_df.get(norm_rel, [])
        # Also check just the filename if path didn't match directly
        if not matching_ci and "/" in norm_rel:
            matching_ci = ci_by_df.get(norm_rel.rsplit("/", 1)[-1], [])

        ci_jobs: list[str] = []
        target_tags: list[str] = []
        for cib in matching_ci:
            ci_file = cib.get("ci_file", "")
            ci_job = cib.get("ci_job", "")
            if ci_file and ci_job:
                ci_jobs.append(f"{ci_file}#{ci_job}")
            if cib.get("image_tag"):
                target_tags.append(str(cib["image_tag"]))

        primary_tag = target_tags[0] if target_tags else None
        aid = DiscoveredContainerAsset.generate_id(rel, primary_tag, final_base)
        if aid not in seen_ids:
            seen_ids.add(aid)
            assets.append(
                DiscoveredContainerAsset(
                    asset_id=aid,
                    source_type="dockerfile",
                    source_file=rel,
                    image_tag=primary_tag,
                    base_image=nm,
                    base_image_tag=tag,
                    base_image_digest=dig,
                    stage_names=stages,
                    associated_ci_jobs=ci_jobs,
                )
            )

    # 2. Process Docker Compose files
    for rel in container_files:
        name = rel.rsplit("/", 1)[-1].lower()
        if not name.startswith(("docker-compose", "compose")):
            continue
        text = safe_read_text(repo_root, rel)
        if text is None:
            continue

        _, im_list = analyze_compose(text, rel)
        for im in im_list:
            raw_ref = im.get("ref", "")
            nm = im.get("name")
            tag = im.get("tag")
            dig = im.get("digest")
            aid = DiscoveredContainerAsset.generate_id(rel, raw_ref, None)
            if aid not in seen_ids:
                seen_ids.add(aid)
                assets.append(
                    DiscoveredContainerAsset(
                        asset_id=aid,
                        source_type="compose",
                        source_file=rel,
                        image_tag=raw_ref,
                        base_image=nm,
                        base_image_tag=tag,
                        base_image_digest=dig,
                    )
                )

    handled_dockerfiles = {rel.replace("\\", "/").lstrip("./") for rel in dockerfiles}
    for rel in dockerfiles:
        if "/" in rel:
            handled_dockerfiles.add(rel.rsplit("/", 1)[-1])

    # 3. Process any remaining CI Docker builds not linked to discovered Dockerfiles
    for b in ci_builds:
        df_target = str(b.get("dockerfile_path", "Dockerfile"))
        norm_df = df_target.replace("\\", "/").lstrip("./")
        if norm_df in handled_dockerfiles or (norm_df.rsplit("/", 1)[-1] in handled_dockerfiles):
            continue
        tag = b.get("image_tag")
        ci_file = b.get("ci_file", "")
        ci_job = b.get("ci_job", "")
        aid = DiscoveredContainerAsset.generate_id(df_target, tag, None)
        if aid not in seen_ids:
            seen_ids.add(aid)
            assets.append(
                DiscoveredContainerAsset(
                    asset_id=aid,
                    source_type="ci_pipeline",
                    source_file=df_target,
                    image_tag=tag,
                    associated_ci_jobs=[f"{ci_file}#{ci_job}"] if ci_file and ci_job else [],
                )
            )

    return assets
