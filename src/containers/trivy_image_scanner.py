"""Controlled Trivy container image vulnerability scanner wrapper."""
from __future__ import annotations

import json
import logging
import subprocess
from typing import Any, Optional

from config.settings import Settings, get_settings
from containers.models import ContainerScanFinding, DiscoveredContainerAsset
from core.safe_env import scrubbed_env
from sbom.trivy_runner import resolve_trivy

logger = logging.getLogger(__name__)


def parse_trivy_image_json(
    json_text: str,
    image_tag: str,
    source_file: str = "",
) -> list[ContainerScanFinding]:
    """Parse Trivy image scan JSON output into normalized ContainerScanFinding records."""
    findings: list[ContainerScanFinding] = []
    if not json_text or not json_text.strip():
        return findings

    try:
        data = json.loads(json_text)
    except Exception as e:
        logger.warning("Failed to decode Trivy image output as JSON: %s", e)
        return findings

    results = data.get("Results") or []
    finding_idx = 1

    for res in results:
        target_name = str(res.get("Target", ""))
        target_class = str(res.get("Class", ""))  # e.g., "os-pkgs", "lang-pkgs"
        target_type = str(res.get("Type", ""))    # e.g., "debian", "alpine", "pip", "npm"

        pkg_type = "os_pkg" if target_class == "os-pkgs" or target_type in ("debian", "ubuntu", "alpine", "redhat", "centos", "apk", "rpm") else "lang_pkg"

        for v in res.get("Vulnerabilities") or []:
            vid = str(v.get("VulnerabilityID", ""))
            pname = str(v.get("PkgName", ""))
            inst_ver = str(v.get("InstalledVersion", ""))
            fixed_ver = v.get("FixedVersion")
            sev = str(v.get("Severity", "UNKNOWN")).upper()
            if sev not in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
                sev = "UNKNOWN"

            # Parse CVSS score
            cvss_obj = v.get("CVSS") or {}
            cvss_val: Optional[float] = None
            for src_key in ("nvd", "redhat", "ghsa"):
                if src_key in cvss_obj and isinstance(cvss_obj[src_key], dict):
                    score = cvss_obj[src_key].get("V3Score")
                    if score is not None:
                        try:
                            cvss_val = float(score)
                            break
                        except (ValueError, TypeError):
                            pass

            layer_diff = (v.get("Layer") or {}).get("DiffID")
            refs = v.get("References") or []
            if v.get("PrimaryURL") and v["PrimaryURL"] not in refs:
                refs = [v["PrimaryURL"]] + list(refs)

            fid = f"CONT-{finding_idx:04d}"
            finding_idx += 1

            findings.append(
                ContainerScanFinding(
                    finding_id=fid,
                    vuln_id=vid,
                    package_name=pname,
                    installed_version=inst_ver,
                    fixed_version=str(fixed_version) if (fixed_version := fixed_ver) else None,
                    severity=sev,
                    cvss_score=cvss_val,
                    package_type=pkg_type,
                    os_distribution=target_type if pkg_type == "os_pkg" else None,
                    target=target_name,
                    layer_diff_id=str(layer_diff) if layer_diff else None,
                    title=str(v.get("Title", f"{vid} in {pname}")),
                    description=str(v.get("Description", "")),
                    references=[str(r) for r in refs[:5]],
                    image_tag=image_tag,
                    source_file=source_file,
                )
            )

    return findings


def scan_container_image(
    image_ref: str,
    asset: DiscoveredContainerAsset,
    settings: Optional[Settings] = None,
) -> tuple[list[ContainerScanFinding], dict[str, Any]]:
    """Execute Trivy image scan against an image reference, returning findings and execution metadata."""
    s = settings or get_settings()

    if not s.container_scan_enabled:
        asset.scan_status = "skipped"
        return [], {"ok": False, "skipped": True, "reason": "Container scanning is disabled (opt-in)"}

    trivy_bin = resolve_trivy(s)
    if not trivy_bin:
        asset.scan_status = "skipped"
        asset.scan_error = "Trivy binary not found on PATH"
        return [], {"ok": False, "skipped": True, "reason": "Trivy binary not found"}

    cmd = [
        trivy_bin,
        "image",
        "--format", "json",
        "--quiet",
        "--scanners", "vuln",
    ]

    # Select vulnerability types based on settings
    vuln_types: list[str] = []
    if s.container_scan_os_packages:
        vuln_types.append("os")
    if s.container_scan_app_packages:
        vuln_types.append("library")
    if vuln_types:
        cmd.extend(["--vuln-type", ",".join(vuln_types)])

    cmd.append(image_ref)

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",  # Trivy emits UTF-8 JSON; the Windows default (cp1252) crashes on it and silently yields zero findings
            timeout=s.container_scan_timeout_s,
            shell=False,
            env=scrubbed_env(),
        )
    except subprocess.TimeoutExpired:
        asset.scan_status = "failed"
        asset.scan_error = f"Trivy scan timed out after {s.container_scan_timeout_s}s"
        logger.warning("Trivy image scan timed out for %s", image_ref)
        return [], {"ok": False, "error": asset.scan_error}
    except Exception as e:
        asset.scan_status = "failed"
        asset.scan_error = f"Subprocess execution error: {e}"
        logger.warning("Trivy scan execution failed for %s: %s", image_ref, e)
        return [], {"ok": False, "error": str(e)}

    if proc.returncode != 0:
        err_msg = proc.stderr.strip() or f"Trivy exited with code {proc.returncode}"
        asset.scan_status = "failed"
        asset.scan_error = err_msg
        logger.info("Trivy image scan failed for %s: %s", image_ref, err_msg)
        return [], {"ok": False, "error": err_msg}

    findings = parse_trivy_image_json(proc.stdout, image_ref, asset.source_file)
    asset.scan_status = "scanned"
    return findings, {"ok": True, "count": len(findings)}
