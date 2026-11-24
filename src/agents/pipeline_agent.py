"""Pipeline Agent: analyses container and CI/CD definitions and adds the images/actions the repository depends on to the SBOM."""
from __future__ import annotations

import re

from agents.runtime import Runtime
from agents.specialists import ScanState
from containers.discovery import discover_container_assets
from containers.trivy_image_scanner import scan_container_image
from core.models import Component
from pipeline_analysis.analyzer import analyze_repository

ICON_EVIDENCE = {"container": "dockerfile", "ci": "workflow"}


def _docker_purl(img: dict) -> str:
    name = img["name"].replace("docker.io/", "").replace("index.docker.io/", "")
    if name.startswith("library/"):
        name = name[len("library/"):]
    ver = img.get("digest") or img.get("tag")
    return f"pkg:docker/{name}" + (f"@{ver}" if ver else "")


def _action_purl(a: dict) -> str:
    return f"pkg:github/{a['name']}" + (f"@{a['ref']}" if a.get("ref") else "")


class PipelineAgent:
    name = "Pipeline Agent"

    def run(self, st: ScanState, rt: Runtime) -> None:
        insp = st.insp
        if not (insp.dockerfiles or insp.container_files or insp.ci_files):
            rt.skip("pipeline", "no Dockerfile, compose file or CI/CD definition found")
            st.pipe = {"findings": [], "images": [], "actions": [], "files": [], "summary": {"files_analysed": 0, "findings": 0, "by_severity": {}, "images": 0, "actions": 0, "actions_unpinned": 0, "images_unpinned": 0}}
            return
        with rt.step("pipeline", f"Analysing {len(insp.dockerfiles)} Dockerfile(s), {len(insp.container_files)} compose/container file(s), {len(insp.ci_files)} CI/CD file(s) (parsed, never executed)") as b:
            res = analyze_repository(st.repo_dir, insp.dockerfiles, insp.container_files, insp.ci_files, st.info.scan_timestamp)
            st.pipe = res
            for f in res["findings"]:  # every finding is backed by an evidence record the explanations and policies can cite
                kind = ICON_EVIDENCE.get(f["category"], "pipeline")
                f["evidence_id"] = st.evidence.add(kind, "pipeline-analyzer", f["finding_id"], f"{f['rule_id']}: {f['title']}", {"rule": f["rule_id"], "snippet": f["snippet"], "severity": f["severity"]},
                                                   source=f"{f['file']}:{f['line']}")
            for fi in res["files"]:
                rt.progress("pipeline", f"{fi['type']} {fi['file']}: " + (f"{fi.get('findings', 0)} finding(s)" if fi["status"] == "analysed" else fi["status"]), file=fi["file"])
            sm = res["summary"]
            sev = ", ".join(f"{n} {k}" for k, n in sorted(sm["by_severity"].items(), key=lambda kv: ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"].index(kv[0]))) or "none"
            rt.observe("pipeline", f"{sm['findings']} finding(s) ({sev}); {sm['images']} base image(s) ({sm['images_unpinned']} not digest-pinned); {sm['actions']} CI action(s) ({sm['actions_unpinned']} not pinned to a SHA)")
            # Correlate Dockerfiles, Compose, and CI builds into container assets
            assets = discover_container_assets(st.repo_dir, insp.dockerfiles, insp.container_files, res.get("docker_builds", []))
            res["container_assets"] = [a.__dict__ for a in assets]

            # Opt-in Trivy container image scanning
            container_vulns: list[dict] = []
            s = getattr(st.ctx, "s", None)
            if s and getattr(s, "container_scan_enabled", False):
                rt.progress("pipeline", f"Opt-in container scanning active: evaluating up to {s.container_scan_max_images} image(s)...")
                for asset in assets[:s.container_scan_max_images]:
                    target_ref = asset.image_tag or (f"{asset.base_image}:{asset.base_image_tag}" if asset.base_image and asset.base_image_tag else asset.base_image)
                    if not target_ref:
                        continue
                    findings, meta = scan_container_image(target_ref, asset, s)
                    for cf in findings:
                        cv = {
                            "finding_id": f"VULN-CONT-{len(container_vulns) + 1:03d}",
                            "component_ref": f"pkg:docker/{cf.package_name}@{cf.installed_version}",
                            "component_refs": [],
                            "package_name": cf.package_name,
                            "ecosystem": cf.os_distribution or "Container",
                            "installed_version": cf.installed_version,
                            "purl": f"pkg:docker/{cf.package_name}@{cf.installed_version}",
                            "vulnerability_ids": [cf.vuln_id],
                            "cve_ids": [cf.vuln_id] if cf.vuln_id.startswith("CVE-") else [],
                            "primary_id": cf.vuln_id,
                            "summary": cf.title or (cf.description[:200] if cf.description else None),
                            "severity": cf.severity,
                            "severity_source": "Trivy",
                            "cvss_score": cf.cvss_score,
                            "affected_status": "confirmed_affected",
                            "affected_status_reason": f"Detected in container image {cf.image_tag}",
                            "fixed_versions": [cf.fixed_version] if cf.fixed_version else [],
                            "recommended_fix": cf.fixed_version,
                            "references": [{"url": r, "type": "ADVISORY"} for r in cf.references],
                            "advisory_urls": cf.references,
                            "dependency_type": "container_package",
                            "sources": ["Trivy"],
                            "scan_timestamp": st.info.scan_timestamp,
                            "asset_type": "container_image",
                            "container_details": {
                                "image_name": cf.image_tag,
                                "source_file": cf.source_file,
                                "package_type": cf.package_type,
                                "os_distribution": cf.os_distribution,
                                "layer_diff_id": cf.layer_diff_id,
                                "target": cf.target,
                            },
                        }
                        # complete the record with the model's defaults so every later stage (risk, explain, remediate, export) can rely on the same fields
                        from vulnerability.vulnerability_models import VulnerabilityFinding
                        cv["service_dir"] = (cf.source_file.rsplit("/", 1)[0] if "/" in (cf.source_file or "") else ".") or "."
                        cv["source_packages"] = [cf.image_tag or "image"]
                        cv["root_component"] = cf.image_tag or "image"
                        cv = VulnerabilityFinding(**cv).model_dump()
                        container_vulns.append(cv)
                        st.evidence.add("container", "trivy-scanner", cv["finding_id"], f"{cf.vuln_id}: {cf.package_name} ({cf.severity})", cv, source=f"{cf.source_file}:{cf.image_tag}")

                if container_vulns:
                    rt.observe("pipeline", f"Container scanner identified {len(container_vulns)} container vulnerability finding(s)")
            res["container_findings"] = container_vulns

            crit = [f for f in res["findings"] if f["severity"] == "CRITICAL"]
            if crit:
                rt.decide("pipeline", f"Escalate {len(crit)} critical pipeline finding(s) to risk scoring", reason="; ".join(sorted({f['title'] for f in crit}))[:200], agent="Supervisor")
            self._add_components(st, rt, res)
            b["message"] = f"{sm['findings']} findings, {sm['images']} images, {sm['actions']} actions, {len(assets)} container assets"

    @staticmethod
    def _add_components(st: ScanState, rt: Runtime, res: dict) -> None:
        """Images and CI actions are part of the supply chain: record them in the inventory and in the SBOM document."""
        have = {c.purl for c in st.components if c.purl}
        entries = st.sbom_doc.setdefault("components", []) if st.sbom_doc else None
        added = 0
        for img in res["images"]:
            purl = _docker_purl(img)
            if purl in have:
                continue
            have.add(purl)
            c = Component(bom_ref=purl, name=img["name"], version=img.get("digest") or img.get("tag") or "latest", type="container", purl=purl, ecosystem=None, purl_type="docker",
                          locations=[img["file"]], service_dir=".", found_by="pipeline-analyzer", sources=["pipeline"], source_type="registry",
                          provenance={"image_kind": {"source": "inferred:heuristic", "confidence": "medium", "evidence": img["kind"], "conflicts": []}})
            st.components.append(c)
            added += 1
            if entries is not None:
                entries.append({"bom-ref": purl, "type": "container", "name": img["name"], "version": c.version, "purl": purl,
                                "properties": [{"name": "sc-guardian:image-kind", "value": img["kind"]}, {"name": "sc-guardian:pinned-by-digest", "value": str(bool(img.get("digest"))).lower()},
                                               {"name": "sc-guardian:location:0:path", "value": img["file"]}]})
        for a in res["actions"]:
            if a.get("kind") != "action" or not a.get("ref"):
                continue
            purl = _action_purl(a)
            if purl in have:
                continue
            have.add(purl)
            c = Component(bom_ref=purl, name=a["name"], version=a["ref"], type="library", purl=purl, ecosystem=None, purl_type="github", locations=[a["file"]], service_dir=".",
                          found_by="pipeline-analyzer", sources=["pipeline"], source_type="git")
            st.components.append(c)
            added += 1
            if entries is not None:
                entries.append({"bom-ref": purl, "type": "library", "name": a["name"], "version": a["ref"], "purl": purl,
                                "properties": [{"name": "sc-guardian:pinned-by-sha", "value": str(bool(a.get("pinned"))).lower()}, {"name": "sc-guardian:location:0:path", "value": a["file"]}]})
        if added:
            rt.observe("pipeline", f"{added} container image/CI action component(s) added to the SBOM (type container / pkg:github)")
