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


def _guardian_sections(result: dict, extras: dict) -> list[str]:
    """Sections required by the Guardian report: prioritised actions with evidence, pipeline, package risk, remediation + validation, policy, AI disclosure, remaining risk, audit trail."""
    L: list[str] = []
    risk = {a["finding_id"]: a for a in result.get("risk_assessments", [])}
    inv = result.get("investigations") or {}
    vulns = {f["finding_id"]: f for f in result.get("vulnerabilities", [])}
    an = result.get("analyst") or {}
    if an:
        L.append("## Executive summary\n")
        L.append(f"**{an.get('headline')}**\n")
        for p_ in an.get("paragraphs", []):
            L.append(f"- {p_}")
        L.append("")
    top = sorted(inv.values(), key=lambda i: (risk.get(i["finding_id"], {}).get("priority", "P9"), -risk.get(i["finding_id"], {}).get("score", 0)))
    top = [i for i in top if risk.get(i["finding_id"], {}).get("priority") in ("P0", "P1")][:12]
    L.append("## Prioritised findings (P0/P1) with evidence\n")
    if top:
        rows = []
        for i in top:
            f, a = vulns[i["finding_id"]], risk.get(i["finding_id"], {})
            rows.append([a.get("priority"), f["finding_id"], f"{f['package_name']} {f['installed_version']}", f["primary_id"], f["severity"] or "n/a", i["verdict"].replace("_", " "), f"{i['confidence']['label']} ({i['confidence']['score']})",
                         f"{f['epss']:.1%}" if f.get("epss") is not None else "n/a", "KEV" if f["kev"] else "", " ".join(f"`{e}`" for e in i["evidence_ids"][:3])])
        L.append(_md_table(rows, ["Priority", "ID", "Package", "Advisory", "CVSS", "Verdict", "Confidence", "EPSS", "KEV", "Evidence"]))
        for i in top[:6]:
            L.append(f"- **{i['finding_id']}** - {i['rationale']}" + ("  _(AI-assisted, grounded)_" if i.get("ai_assisted") else ""))
        L.append("")
    else:
        L.append("_No P0/P1 findings._\n")
    cnt: dict[str, int] = {}
    for i in inv.values():
        cnt[i["verdict"]] = cnt.get(i["verdict"], 0) + 1
    if cnt:
        L.append("Verdicts across all findings: " + ", ".join(f"{k.replace('_', ' ')} {v}" for k, v in sorted(cnt.items(), key=lambda kv: -kv[1])) + ". Reachability is package-level import evidence, not a call graph; 'no import evidence' is not proof of safety.\n")
    pl = result.get("pipeline") or {}
    if pl.get("findings"):
        L.append("## Pipeline and container findings\n")
        L.append(_md_table([[f["finding_id"], f["severity"], f["rule_id"], f["title"], f"{f['file']}:{f['line']}" if f["line"] else f["file"], risk.get(f["finding_id"], {}).get("label", "")] for f in pl["findings"][:60]],
                           ["ID", "Severity", "Rule", "Finding", "Where", "Risk"]))
    pk = (result.get("package_risk") or {}).get("findings") or []
    if pk:
        L.append("## Package risk signals\n")
        L.append(_md_table([[f["finding_id"], f["severity"], f["rule_id"], f["subject"], f["title"]] for f in pk[:40]], ["ID", "Severity", "Signal", "Package", "Finding"]))
    rem = (result.get("remediation") or {}).get("items") or []
    approvals = extras.get("approvals") or {}
    if rem:
        L.append("## Recommended actions and validation\n")
        rows = []
        for r_ in rem:
            wi = r_.get("what_if") or {}
            rows.append([r_["id"], r_["priority"], r_["action"], r_["title"], len(wi.get("fixed", [])) if wi else "n/a", len(wi.get("remaining", [])) if wi else "n/a", len(wi.get("newly_introduced", [])) if wi else "n/a",
                         (r_.get("compatibility") or {}).get("breaking_risk", ""), (r_.get("validation") or {}).get("patch_applies"), approvals.get(r_.get("fingerprint"), {}).get("state", "pending")])
        L.append(_md_table(rows, ["ID", "Priority", "Action", "Proposal", "Fixed", "Remaining", "New", "Breaking risk", "Patch applies", "Approval"]))
        L.append("Validation is a static what-if (registry-resolved dependency tree + OSV re-match + before/after SBOM diff). The repository's build and tests were **not** run unless a sandbox result is listed. Proposals are never applied automatically.\n")
    if result.get("policy_result"):
        pr = result["policy_result"]
        L.append(f"## Policy gate: {'PASS' if pr['passed'] else 'FAIL'} (`{pr['policy']}`)\n")
        L.append(f"{pr['blocking']} blocking, {pr['warnings']} warning(s), {pr['info']} info, {pr['waived']} waived.\n")
        L.append(_md_table([[v["rule_id"], v["action"], v["subject"]] for v in pr["violations"][:30]], ["Rule", "Action", "Subject"]))
    L.append("## Responsible AI and automation disclosure\n")
    llm_calls = result.get("llm_calls") or []
    ai = [i for i in inv.values() if i.get("ai_assisted")]
    L.append(f"- Detection, matching, scoring, reachability, EPSS/KEV lookups, what-if simulation and policy evaluation are **deterministic and rule-based**.")
    L.append(f"- LLM use in this scan: **{'yes (' + str(len(llm_calls)) + ' call(s), ' + str(len(ai)) + ' investigation(s) accepted after grounding checks)' if llm_calls else 'none'}**. Prompts never contain source code beyond short import snippets, and secrets are redacted before sending.")
    L.append("- AI proposals are accepted only if they cite existing evidence ids, mention only facts present in the evidence, and do not contradict hard evidence; rejected proposals are recorded.")
    L.append("- Every remediation requires explicit human approval; nothing is applied, pushed or merged by the tool.\n")
    L.append("## Remaining and accepted risk\n")
    dec = extras.get("decisions") or {}
    open_p = [i for i in top if dec.get((result.get("memory") or {}).get("fingerprints", {}).get(i["finding_id"], "")) is None]
    L.append(f"- Open P0/P1 findings: **{len(open_p)}**; analyst decisions on record: **{len(dec)}**.")
    for fp, d in list(dec.items())[:15]:
        L.append(f"  - {d['decision'].replace('_', ' ')}: {d.get('title') or fp} - {d['reason']}" + (f" (expires {d['expires_at'][:10]})" if d.get("expires_at") else ""))
    L.append("")
    audit = extras.get("audit") or []
    if audit:
        L.append("## Audit trail\n")
        L.append(_md_table([[a["at"], a["actor"], a["action"], a["subject"], a["detail"]] for a in audit[:25]], ["When", "Who", "Action", "Subject", "Detail"]))
    return L


def generate_markdown(result: dict, extras: dict | None = None) -> str:
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
    L += _guardian_sections(result, extras or {})
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


def generate_html(result: dict, extras: dict | None = None) -> str:
    md = generate_markdown(result, extras)
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
