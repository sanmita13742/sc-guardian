from __future__ import annotations

import html
import json
from collections import Counter
from typing import Any


def _md(value: Any) -> str:
    return str(value if value is not None else "Unavailable").replace("|", "\\|").replace("\n", " ")


def _table(headers: list[str], rows: list[list[Any]]) -> str:
    result = ["| " + " | ".join(headers) + " |", "|" + "|".join("---" for _ in headers) + "|"]
    result.extend("| " + " | ".join(_md(value) for value in row) + " |" for row in rows)
    return "\n".join(result)


def build_report(
    manifest: dict[str, Any],
    graph: dict[str, Any],
    vulnerabilities: dict[str, Any],
    changes: dict[str, Any],
    ci: dict[str, Any],
    source_evidence: list[dict[str, Any]],
    artifact_hashes: dict[str, str],
) -> tuple[dict[str, Any], str, str]:
    summary = graph["stats"]
    findings = vulnerabilities["findings"]
    package_counts = Counter((item["package_name"], item["package_version"]) for item in findings)
    marked = [item for item in findings if item["package_name"] == "marked"]
    case = changes.get("case_study")
    warnings = list(graph.get("info", {}).get("warnings") or []) + list(changes.get("warnings") or [])
    if vulnerabilities["graph_match_counts"].get("unmatched"):
        warnings.append(f"{vulnerabilities['graph_match_counts']['unmatched']} vulnerability instances could not be mapped to graph metadata")
    overall = "completed_with_warnings" if warnings else "completed"
    report = {
        "schema": "nodegoat-guardian-report-v1",
        "overall_status": overall,
        "repository_url": manifest["repository_url"],
        "commit_sha": manifest["commit_sha"],
        "scan_timestamp": manifest["completed_at"],
        "tool_versions": manifest.get("tool_versions") or {},
        "methodology": {"target_executed": False, "analysis": ["CycloneDX lockfile-only inventory", "OSV lockfile scan", "exact-ID dependency graph", "bounded Git dependency history", "static CI/container inspection"]},
        "inventory": summary,
        "vulnerability_summary": {key: vulnerabilities[key] for key in ("scanner_package_entry_count", "finding_count", "unique_advisory_count", "unique_cve_count", "affected_package_version_count", "graph_match_counts")},
        "suspicious_change_summary": {"count": changes.get("suspicious_change_count", 0), "case_study": case},
        "ci_inspection": ci,
        "marked_case_study": {"findings": marked, "source_evidence": source_evidence, "reachability": "candidate" if marked and source_evidence else "unassessed"},
        "artifact_hashes": artifact_hashes,
        "warnings": warnings,
        "limitations": [
            "Known vulnerable versions are not proof of runtime exploitation.",
            "Package dependency paths are not vulnerable-function call paths.",
            "Reference-only graph nodes lack verified component metadata.",
            "Git history search is bounded and may omit older changes outside the fetched history.",
            "OSV coverage, advisory aliases, and severity fields depend on upstream data at scan time.",
        ],
    }

    tool_versions = report["tool_versions"]
    lines = [
        "# Software Supply Chain Guardian — Day 1 Evidence Report",
        "",
        "## 1. Executive summary and overall analysis status",
        "",
        f"**Status:** `{overall}`  ",
        f"**Target:** `{manifest['repository_url']}`  ",
        f"This static analysis identified **{vulnerabilities['unique_advisory_count']} unique advisory IDs** affecting **{vulnerabilities['affected_package_version_count']} package/version pairs**. It did not execute the target application and does not claim runtime exploitation.",
        "",
        "## 2. Scan provenance",
        "",
        _table(["Field", "Value"], [
            ["Repository", manifest["repository_url"]], ["Commit SHA", manifest["commit_sha"]], ["Scan time", manifest["completed_at"]],
            ["CycloneDX specification", graph.get("info", {}).get("specVersion")], ["SBOM generator", tool_versions.get("cyclonedx_npm")],
            ["OSV scanner", tool_versions.get("osv_scanner")], ["Target application executed", "No"],
        ]),
        "",
        "## 3. Methodology",
        "",
        "The pipeline performed lockfile-only CycloneDX generation, official schema validation, exact `bom-ref` graph reconciliation, OSV scanning of the same pinned `package-lock.json`, bounded Git dependency-history comparison, and static CI/container inspection. Repository application code and lifecycle scripts were not executed.",
        "",
        "## 4. SBOM inventory",
        "",
        _table(["Metric", "Count"], [["SBOM component records", summary["component_record_count"]], ["SBOM dependency records", summary["dependency_record_count"]], ["Graph nodes", summary["total_nodes"]], ["Reference-only nodes", summary["unresolved_node_count"]], ["OSV scanner package entries", vulnerabilities["scanner_package_entry_count"]]]),
        "",
        "## 5. Dependency graph",
        "",
        _table(["Metric", "Count"], [["Unique nodes", summary["total_nodes"]], ["Unique edges", summary["total_edges"]], ["Direct connections", summary["direct_connections"]], ["Transitive connections", summary["transitive_connections"]], ["Other connections", summary["other_connections"]], ["Global leaves", summary["leaf_node_count"]], ["Shared hubs", summary["shared_hub_count"]]]),
        "",
        "Dependency records, graph nodes, unique edges, and OSV package entries count different entities and are intentionally reported separately.",
        "",
        "## 6. Known vulnerability summary",
        "",
        _table(["Metric", "Count"], [["Finding instances", vulnerabilities["finding_count"]], ["Unique advisory IDs", vulnerabilities["unique_advisory_count"]], ["Unique CVE aliases", vulnerabilities["unique_cve_count"]], ["Affected package/version pairs", vulnerabilities["affected_package_version_count"]], ["Ambiguous graph mappings", vulnerabilities["graph_match_counts"]["ambiguous"]], ["Unmatched graph mappings", vulnerabilities["graph_match_counts"]["unmatched"]]]),
        "",
        _table(["Package/version", "Advisory instances"], [[f"{name}@{version}", count] for (name, version), count in package_counts.most_common(25)]),
        "",
        "## 7. Prioritized case study: marked",
        "",
        f"The scanner returned **{len(marked)}** advisory findings for the resolved `marked` package instance(s). Static source inspection found **{len(source_evidence)}** relevant lines. Reachability is classified as **{'candidate' if marked and source_evidence else 'unassessed'}**, not confirmed runtime exploitation.",
        "",
        _table(["Advisory", "Version", "Severity", "Fixes", "Graph mapping"], [[item["advisory_id"], item["package_version"], item["severity"]["value"], ", ".join(item["fixed_versions"]) or "Not provided", item["graph_match"]["status"]] for item in marked]),
        "",
        _table(["Source evidence", "Line", "Observed text", "Commit SHA"], [[item["path"], item["line"], item.get("observation") or item["type"], item.get("commit_sha")] for item in source_evidence]),
        "",
        "## 8. Suspicious supply-chain change case study",
        "",
    ]
    if case:
        lines.extend([
            f"A historical `{case['change_type']}` changed `{case['package_name']}` from `{case['before']}` to `{case['after']}` at `{case['child_sha']}` (parent `{case['parent_sha']}`).",
            "",
            f"Newly applicable advisory IDs from the before/after OSV set comparison: {', '.join(case['newly_applicable_advisory_ids']) or 'Unavailable or none'}. Assessment: **{case['assessment']}**. This is not evidence of malicious compromise.",
        ])
    else:
        lines.append("No explainable downgrade was found within the bounded fetched history; this remains unresolved rather than being reported as clean.")
    lines.extend([
        "",
        "## 9. CI/CD or container inspection",
        "",
        f"Static inspection covered: {', '.join(ci['files_inspected']) or 'no eligible file found'}. It recorded {len(ci['observations'])} observations and {ci['risk_signal_count']} grounded risk signals. No workflow or image was executed.",
        "",
        _table(["File:line", "Kind", "Observed value", "Signal"], [[f"{item['file']}:{item['line']}", item['kind'], item['value'], item.get('risk_signal') or 'No risk established'] for item in ci["observations"][:50]]),
        "",
        "## 10. Evidence table",
        "",
        _table(["Evidence type", "Location", "Identity / observation", "SHA or advisory URL"],
            [["artifact", name, "saved analysis evidence", digest] for name, digest in sorted(artifact_hashes.items())]
            + [["source", f"{item['path']}:{item['line']}", item.get("observation") or "static source match", item.get("commit_sha")] for item in source_evidence]
            + [["scanner advisory", "osv-raw.json", f"{item['package_name']}@{item['package_version']} — {item['advisory_id']}", next((e.get("url") for e in item.get("evidence") or [] if e.get("url")), "URL not provided")] for item in findings[:50]]),
        "",
        "## 11. Data quality, limitations and next steps",
        "",
    ])
    lines.extend(f"- {item}" for item in report["limitations"])
    if warnings:
        lines.extend(["", "### Warnings", ""] + [f"- {warning}" for warning in warnings])
    markdown = "\n".join(lines) + "\n"
    escaped = html.escape(markdown)
    html_report = f"""<!doctype html><html><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width\"><title>Guardian Evidence Report</title><style>body{{font:15px/1.55 system-ui;margin:40px auto;max-width:1100px;padding:0 20px;color:#172033}}pre{{white-space:pre-wrap;overflow-wrap:anywhere}}@media print{{body{{margin:0;max-width:none}}}}</style></head><body><pre>{escaped}</pre></body></html>"""
    return report, markdown, html_report
