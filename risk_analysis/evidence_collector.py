"""Collect traceable evidence for every finding (SBOM, advisory, graph, repository/Git)."""
from __future__ import annotations

from typing import Any, Optional


def _repo_block(repo: dict) -> dict:
    return {"repository_url": repo.get("url"), "commit_sha": repo.get("commit_sha"), "branch": repo.get("branch"),
            "scan_id": repo.get("scan_id"), "scan_timestamp": repo.get("scan_timestamp")}


def collect_vulnerability_evidence(f: dict, repo: dict, sbom_id: Optional[str], lock_index: dict) -> dict[str, Any]:
    lock = lock_index.get((f["service_dir"], f["ecosystem"], f["package_name"], f["installed_version"]))
    return {
        "kind": "vulnerability", "finding_id": f["finding_id"],
        "advisory": {"ids": f["vulnerability_ids"], "cve_ids": f["cve_ids"], "primary_id": f["primary_id"], "summary": f.get("summary"),
                     "sources": f["sources"], "urls": f["advisory_urls"], "retrieved_at": f.get("retrieved_at"),
                     "published": f.get("published"), "modified": f.get("modified"),
                     "affected_ranges": f["affected_ranges"], "fixed_versions": f["fixed_versions"],
                     "recommended_fix": f["recommended_fix"], "severity": f["severity"], "severity_source": f["severity_source"],
                     "cvss_score": f["cvss_score"], "cvss_vector": f["cvss_vector"], "cvss_version": f.get("cvss_version"),
                     "kev": f["kev"], "kev_info": f.get("kev_info"), "affected_status": f["affected_status"],
                     "affected_status_reason": f.get("affected_status_reason")},
        "component": {"name": f["package_name"], "ecosystem": f["ecosystem"], "version": f["installed_version"], "purl": f.get("purl"),
                      "bom_ref": f["component_ref"], "sbom_id": sbom_id, "service_dir": f.get("service_dir")},
        "dependency": {"type": f["dependency_type"], "roots": f["roots"], "immediate_parents": f["immediate_parents"],
                       "exposures": [{"root": e["root"], "relationship": e["relationship"], "depth": e["depth"],
                                      "paths": e["paths"][:5], "immediate_parents": e["immediate_parents"]} for e in f["exposures"]],
                       "dev_dependency": f.get("dev_dependency")},
        "repository": {**_repo_block(repo), "lockfile": lock.get("lockfile") if lock else None,
                       "lockfile_record": lock.get("record") if lock else None,
                       "lockfile_integrity": lock.get("integrity") if lock else None},
        "notes": f.get("notes", []),
    }


def collect_typosquat_evidence(f: dict, repo: dict, sbom_id: Optional[str]) -> dict[str, Any]:
    return {
        "kind": "typosquatting", "finding_id": f["finding_id"],
        "detection": {"package": f["package_name"], "ecosystem": f["ecosystem"], "similar_to": f["similar_to"],
                      "similarity_score": f["similarity_score"], "edit_distance": f["edit_distance"], "techniques": f["techniques"],
                      "reference_source": f["reference_source"], "evidence": f["evidence"], "registry": f.get("registry", {}),
                      "evidence_strength": f["evidence_strength"], "caveats": f["caveats"]},
        "component": {"name": f["package_name"], "ecosystem": f["ecosystem"], "versions": f["versions"],
                      "bom_refs": f["component_refs"], "sbom_id": sbom_id, "services": f["services"]},
        "dependency": {"type": f["dependency_type"], "roots": f["roots"]},
        "repository": _repo_block(repo), "notes": [],
    }


def collect_lockfile_evidence(c: dict, repo: dict, sbom_id: Optional[str]) -> dict[str, Any]:
    return {
        "kind": "lockfile_change", "finding_id": c["finding_id"],
        "change": {"file": c["file"], "package": c["package_name"], "ecosystem": c["ecosystem"], "change_type": c["change_type"],
                   "previous": c["previous"], "new": c["new"], "classification": c["classification"], "signals": c["signals"],
                   "reasons": c["reasons"], "evidence_strength": c["evidence_strength"], "diff_excerpt": c["diff_excerpt"],
                   "manifest_changed": c["manifest_changed"], "manifest_files_changed": c["manifest_files_changed"]},
        "git": {"commit": c["commit"], "baseline": c["baseline"], "baseline_mode": c["baseline_mode"], "commit_info": c["commit_info"]},
        "component": {"name": c["package_name"], "ecosystem": c["ecosystem"], "sbom_id": sbom_id},
        "dependency": {"type": (c.get("new") or c.get("previous") or {}).get("direct")},
        "repository": _repo_block(repo), "notes": [],
    }
