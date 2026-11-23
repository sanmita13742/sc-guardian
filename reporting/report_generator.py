"""Human-readable consolidated security report (Markdown and HTML)."""
from __future__ import annotations

import html
from typing import Any


def _md_table(rows: list[list[str]], header: list[str]) -> str:
    if not rows:
        return "_None._\n"
    out = ["| " + " | ".join(header) + " |", "|" + "|".join("---" for _ in header) + "|"]
    for r in rows:
        out.append("| " + " | ".join(str(c).replace("|", "\\|").replace("\n", " ") for c in r) + " |")
    return "\n".join(out) + "\n"


def generate_markdown(result: dict) -> str:
    r, s = result["repo"], result.get("summary", {})
    risk = {a["finding_id"]: a for a in result.get("risk_assessments", [])}
    expl = result.get("explanations", {})
    L: list[str] = []
    L.append(f"# Supply Chain Security Report - {r['name']}\n")
    L.append(f"- **Repository:** {r['url']}\n- **Branch/ref:** {r.get('branch') or r.get('ref') or 'default'}\n- **Commit:** `{r['commit_sha']}`\n"
             f"- **Scan ID:** {r['scan_id']}  |  **Scanned:** {r['scan_timestamp']}\n- **Status:** {result.get('status')}\n"
             f"- **Tools:** " + ", ".join(f"{k} {v}" for k, v in result.get("tool_versions", {}).items()) + "\n")
    L.append("> This report lists findings with evidence. **An absence of findings is not proof that the repository is safe**; "
             "see 'Coverage and limitations'.\n")
    L.append("## Summary\n")
    L.append(_md_table([[k, v] for k, v in [
        ("Components (packages)", s.get("components")), ("Vulnerability findings (confirmed)", s.get("vulnerabilities_confirmed")),
        ("Vulnerability findings (unconfirmed)", s.get("vulnerabilities_unknown")), ("Direct / transitive vulnerable", f"{s.get('vuln_direct')} / {s.get('vuln_transitive')}"),
        ("Known exploited (KEV)", s.get("kev")), ("With fix available", s.get("with_fix")),
        ("Typosquatting candidates", s.get("typosquatting")), ("Suspicious/unexplained lockfile changes", s.get("lockfile_findings")),
        ("Risk: CRITICAL/HIGH/MEDIUM/LOW", " / ".join(str(s.get("by_risk", {}).get(l, 0)) for l in ("CRITICAL", "HIGH", "MEDIUM", "LOW")))]], ["Metric", "Value"]))
    q = result.get("quality", {})
    L.append("## SBOM and quality\n")
    L.append(f"- Inventory source: **{result.get('inventory_source')}**; inventory status: **{q.get('inventory_status')}**; relationships: **{q.get('dependency_relationships')}**; metadata: **{q.get('metadata_status')}**")
    L.append(f"- Missing metadata: {q.get('missing_metadata')}; unresolved components: {q.get('unresolved_components')}; lockfile entries not in SBOM: {q.get('lockfile_missing_from_sbom_count')}\n")
    L.append("## Vulnerabilities\n")
    rows = []
    for f in result.get("vulnerabilities", []):
        a = risk.get(f["finding_id"], {})
        rows.append([f["finding_id"], f["primary_id"], f"{f['package_name']} {f['installed_version']}", f["severity"] or "n/a",
                     f["cvss_score"] if f["cvss_score"] is not None else "n/a", f["affected_status"], ", ".join(f["fixed_versions"][:2]) or "none recorded",
                     f["dependency_type"], a.get("label", "")])
    L.append(_md_table(rows, ["ID", "Advisory", "Package", "CVSS sev.", "CVSS", "Status", "Fixed in", "Dependency", "Risk"]))
    for f in result.get("vulnerabilities", [])[:40]:
        e = expl.get(f["finding_id"])
        a = risk.get(f["finding_id"], {})
        L.append(f"### {f['finding_id']} - {f['primary_id']} in {f['package_name']} {f['installed_version']}\n")
        if e:
            L.append(f"**{e['headline']}**\n")
            for k in ("what", "why", "how_entered", "direct_transitive", "impact", "remediation", "unknown"):
                L.append(f"- *{k.replace('_', ' ')}*: {e['sections'][k]}".replace("\n", "\n  "))
            L.append("\nRisk factors: " + "; ".join(e["risk_factors"]) + "\n")
    L.append("## Suspicious changes\n")
    L.append("### Typosquatting (similarity is a signal, not proof)\n")
    L.append(_md_table([[t["finding_id"], t["package_name"], t["similar_to"], f"{t['similarity_score']}%", t["evidence_strength"],
                         risk.get(t["finding_id"], {}).get("label", ""), "; ".join(t["evidence"][:2])] for t in result.get("typosquatting", [])],
                       ["ID", "Package", "Similar to", "Similarity", "Evidence", "Risk", "Evidence detail"]))
    L.append("### Modified lockfiles\n")
    la = result.get("lockfile_analysis", {})
    L.append(f"Comparison: {la.get('summary')}\n")
    L.append(_md_table([[c["finding_id"], c["commit"][:10], c["file"], c["package_name"], c["change_type"],
                         f"{(c['previous'] or {}).get('version')} -> {(c['new'] or {}).get('version')}", c["classification"],
                         risk.get(c["finding_id"], {}).get("label", ""), " ".join(c["reasons"][:1])] for c in result.get("lockfile_changes", [])],
                       ["ID", "Commit", "File", "Package", "Change", "Version", "Classification", "Risk", "Why"]))
    L.append("## Coverage and limitations\n")
    for lim in result.get("limitations", []):
        L.append(f"- {lim}")
    for k, v in result.get("source_status", {}).items():
        L.append(f"- Source **{k}**: {v.get('state')}" + (f" - errors: {v.get('errors')[:2]}" if v.get("errors") else ""))
    for e in result.get("errors", []):
        L.append(f"- Stage error ({e['stage']}): {e['error']}")
    return "\n".join(L) + "\n"


def generate_html(result: dict) -> str:
    md = generate_markdown(result)
    body = []
    in_table = False
    for line in md.splitlines():
        if line.startswith("|"):
            cells = [html.escape(c.strip()) for c in line.strip().strip("|").split("|")]
            if set("".join(cells)) <= set("-: "):
                continue
            tag = "th" if not in_table else "td"
            if not in_table:
                body.append("<table>")
                in_table = True
            body.append("<tr>" + "".join(f"<{tag}>{c}</{tag}>" for c in cells) + "</tr>")
            continue
        if in_table:
            body.append("</table>")
            in_table = False
        if line.startswith("### "):
            body.append(f"<h3>{html.escape(line[4:])}</h3>")
        elif line.startswith("## "):
            body.append(f"<h2>{html.escape(line[3:])}</h2>")
        elif line.startswith("# "):
            body.append(f"<h1>{html.escape(line[2:])}</h1>")
        elif line.startswith("> "):
            body.append(f"<blockquote>{html.escape(line[2:])}</blockquote>")
        elif line.strip():
            body.append(f"<p>{html.escape(line.lstrip('- '))}</p>")
    if in_table:
        body.append("</table>")
    css = ("body{font-family:system-ui,Segoe UI,sans-serif;max-width:1100px;margin:2rem auto;padding:0 1rem;color:#1b1f24}"
           "table{border-collapse:collapse;width:100%;margin:.5rem 0 1rem;font-size:.85rem}th,td{border:1px solid #d0d7de;padding:4px 8px;text-align:left}"
           "th{background:#f6f8fa}blockquote{border-left:4px solid #d4a72c;background:#fff8c5;margin:1rem 0;padding:.5rem 1rem}")
    return f"<!doctype html><html><head><meta charset='utf-8'><title>Supply chain report</title><style>{css}</style></head><body>{''.join(body)}</body></html>"
