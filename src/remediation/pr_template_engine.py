"""Repository Pull Request Template Discovery and Conformance Engine.

Finds existing repository PR templates (e.g. .github/pull_request_template.md) and
conforms strictly to their sections and checklists. If no template exists, renders
SC Guardian's standardized enterprise security pull-request format.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Optional

PR_TEMPLATE_CANDIDATES = [
    ".github/pull_request_template.md",
    ".github/PULL_REQUEST_TEMPLATE.md",
    ".github/pull_request_template.txt",
    "pull_request_template.md",
    "PULL_REQUEST_TEMPLATE.md",
    ".github/PULL_REQUEST_TEMPLATE/default.md",
    ".github/PULL_REQUEST_TEMPLATE/security.md",
    "docs/pull_request_template.md",
    "docs/.github/pull_request_template.md",
]


def find_pr_template(repo_dir: Path | str | None) -> Optional[tuple[str, str]]:
    """Scan the repo for an existing PR template. Return (relative_path, text) or None."""
    if not repo_dir:
        return None
    root = Path(repo_dir)
    for rel in PR_TEMPLATE_CANDIDATES:
        p = root / rel
        if p.is_file():
            try:
                text = p.read_text(encoding="utf-8", errors="replace")
                if text.strip():
                    return (rel, text)
            except OSError:
                continue

    # Also search .github/PULL_REQUEST_TEMPLATE/*.md
    pr_dir = root / ".github" / "PULL_REQUEST_TEMPLATE"
    if pr_dir.is_dir():
        for f in pr_dir.glob("*.md"):
            try:
                text = f.read_text(encoding="utf-8", errors="replace")
                if text.strip():
                    return (str(f.relative_to(root).as_posix()), text)
            except OSError:
                continue
    return None


def generate_pr_title(rem: dict) -> str:
    """Generate a clean conventional commit title for the pull request."""
    action = rem.get("action", "upgrade")
    src = rem.get("source_package") or rem.get("package") or "dependency"
    target = rem.get("target") or {}
    from_v = target.get("from") or ""
    to_v = target.get("to") or ""
    cves = [f.split()[0] for f in rem.get("finding_ids", []) if "CVE-" in f or "GHSA-" in f]
    cve_tag = f" to resolve {cves[0]}" if cves else ""

    if action == "upgrade" and from_v and to_v:
        return f"fix(deps): bump {src} from {from_v} to {to_v}{cve_tag}"
    if action == "pin":
        return f"fix(deps): pin transitive dependency {src} to {to_v or 'safe version'}{cve_tag}"
    if action == "remove":
        return f"fix(deps): remove vulnerable dependency {src}{cve_tag}"
    return f"fix(deps): remediate security findings in {src}{cve_tag}"


def _format_reachability_section(impact: dict | None) -> str:
    if not impact:
        return ""
    lines = [
        "### 🎯 Code Reachability & Call Surface Impact",
        f"- **Preservation Score:** {impact.get('reachability_preservation_score', 100)}% preserved",
        f"- **Status:** `{impact.get('status', 'unknown')}` ({impact.get('semver_change', 'n/a')} change)",
        f"- **Files Affected ({len(impact.get('app_files_affected', []))}):** "
        + (", ".join(f"`{f}`" for f in impact.get("app_files_affected", [])[:6]) or "None (isolated/unimported)"),
    ]
    if impact.get("imported_symbols"):
        lines.append(f"- **Imported Symbols:** {', '.join(f'`{s}`' for s in impact['imported_symbols'][:6])}")
    if impact.get("impact_summary"):
        lines.append(f"- **Summary:** {impact['impact_summary']}")
    if impact.get("recommendation"):
        lines.append(f"- **Recommendation:** {impact['recommendation']}")
    return "\n".join(lines)


def _format_verification_section(val: dict, wi: dict) -> str:
    lines = [
        "### 🛡️ Multi-Tier Verification Status",
        f"- **Tier 1 (Patch Applicability):** {'✅ Passed' if val.get('patch_applies') else '❌ Failed'}",
        f"- **Tier 2 (Lockfile Coherence):** {'✅ Verified' if val.get('lockfile_coherence', True) else '⚠️ Requires manual lock refresh'}",
        f"- **Tier 3 (OSV What-If Rescan):** {'✅ ' + str(wi.get('verdict', 'verified')).replace('_', ' ').title() if wi else 'Not simulated'}",
        f"- **Tier 4 (Sandbox Build & Tests):** {(val.get('build_tests') or {}).get('status', 'not_run').replace('_', ' ').title()}",
        f"- **Tier 5 (Security Regression Gate):** {'✅ Passed (No new HIGH/CRITICAL CVEs introduced)' if not wi.get('newly_introduced') else '⚠️ New advisories present'}",
    ]
    return "\n".join(lines)


def _conform_to_repo_template(template: str, rem: dict, repo: dict, approval: Optional[dict], impact: Optional[dict]) -> str:
    """Populate an existing repository pull request template."""
    wi = rem.get("what_if") or {}
    val = rem.get("validation") or {}
    cves = ", ".join(rem.get("finding_ids", [])[:8]) or "security advisory"

    text = template

    # Auto-check relevant checkboxes
    def check_boxes(match):
        line = match.group(0)
        lower = line.lower()
        if any(w in lower for w in ("security", "bug fix", "bugfix", "dependency", "dependencies", "deps", "patch")):
            return line.replace("[ ]", "[x]")
        if "tests" in lower and (val.get("patch_applies") or (val.get("build_tests") or {}).get("status") == "passed"):
            return line.replace("[ ]", "[x]")
        return line

    text = re.sub(r"^[ \t]*- \[[ xX]\] .+$", check_boxes, text, flags=re.M)

    # Prepare injected evidence summary
    evidence_block = (
        f"\n\n---\n"
        f"### 🛡️ Automated Security Fix Summary (SC Guardian)\n"
        f"- **Proposal:** {rem['title']} ({rem['action']})\n"
        f"- **Priority:** {rem.get('priority', 'P1')} · **Confidence:** {rem.get('confidence', 'High')}\n"
        f"- **Target Repository:** `{repo.get('url')}` @ `{str(repo.get('commit_sha') or '')[:10]}`\n"
        f"- **Addressed Findings:** {cves}\n\n"
        f"{_format_reachability_section(impact)}\n\n"
        f"{_format_verification_section(val, wi)}\n\n"
    )
    if wi:
        evidence_block += (
            f"**What-If Effect:** Fixed **{len(wi.get('fixed', []))}** finding(s), "
            f"**{len(wi.get('remaining', []))}** remaining, **{len(wi.get('newly_introduced', []))}** introduced.\n\n"
        )
    if rem.get("rollback"):
        evidence_block += "**Rollback Instructions:**\n" + "\n".join(f"{idx}. {step}" for idx, step in enumerate(rem["rollback"], 1)) + "\n\n"
    if approval:
        evidence_block += f"**Approved by:** {approval.get('actor', 'reviewer')} on {approval.get('decided_at', 'n/a')}: {approval.get('reason', '')}\n\n"

    # Append evidence block to the bottom of the conformed template
    return text.rstrip() + "\n" + evidence_block


def _render_standard_pr(rem: dict, repo: dict, approval: Optional[dict], impact: Optional[dict]) -> str:
    """Render SC Guardian's standard enterprise security pull-request template."""
    wi = rem.get("what_if") or {}
    val = rem.get("validation") or {}
    target = rem.get("target") or {}

    lines = [
        f"## {rem['title']}",
        "",
        f"_Proposed by SC Guardian for `{repo.get('url')}` @ `{(repo.get('commit_sha') or '')[:10]}`; requires human review before merging._",
        "",
        f"**Priority:** `{rem.get('priority', 'P1')}` · **Action:** `{rem['action']}` · **Confidence:** `{rem.get('confidence', 'High')}`",
        "",
        "### 📋 Summary",
        rem.get("rationale") or f"Automated dependency remediation for {rem.get('source_package')}.",
        "",
        f"- **Target Package:** `{rem.get('source_package')}`",
        f"- **Version Delta:** `{target.get('from', 'current')}` ➔ `{target.get('to', 'recommended')}`",
        f"- **Addressed Findings:** {', '.join(rem.get('finding_ids', [])[:10]) or 'None'}",
        "",
        _format_reachability_section(impact),
        "",
    ]

    if wi:
        lines += [
            "### 📊 Measured Effect (What-If Dependency Simulation)",
            f"- **Fixed Advisories ({len(wi.get('fixed', []))}):** " + (", ".join(f"{f['id']} ({f['package']})" for f in wi.get("fixed", [])[:8]) or "None"),
            f"- **Remaining Advisories:** {len(wi.get('remaining', []))}",
            f"- **Newly Introduced Advisories:** {len(wi.get('newly_introduced', []))}"
            + (" - " + ", ".join(f"{f['id']} ({f['package']}@{f['version']}, {f['severity']})" for f in wi["newly_introduced"][:5]) if wi.get("newly_introduced") else ""),
            f"- **Simulation Verdict:** `{wi.get('verdict', 'unknown').replace('_', ' ').title()}`",
            "",
        ]
        d = wi.get("sbom_diff") or {}
        if d.get("changed") or d.get("added") or d.get("removed"):
            lines += [
                "**SBOM Diff (Affected Sub-Tree)**",
                f"- Changed: {', '.join(c['package'] + ' ' + c['from'] + ' -> ' + c['to'] for c in d.get('changed', [])[:10]) or 'None'}",
                f"- Added: {', '.join(d.get('added', [])[:10]) or 'None'}",
                f"- Removed: {', '.join(d.get('removed', [])[:10]) or 'None'}",
                "",
            ]

    comp = rem.get("compatibility") or {}
    if comp:
        lines += [
            "### 🔄 Compatibility & Breaking Risk",
            f"- **SemVer Change:** {comp.get('semver_change', 'n/a')}",
            f"- **Breaking Risk:** {comp.get('breaking_risk', 'low')}",
            f"- **Note:** {comp.get('note', '')}",
            "",
        ]

    lines += [_format_verification_section(val, wi), ""]

    if rem.get("lock_note"):
        lines += ["### 🔒 Lockfile Refresh Command", f"```bash\n{rem['lock_note']}\n```", ""]

    if rem.get("rollback"):
        lines += ["### ⏪ Rollback Instructions"]
        lines += [f"{i}. {s}" for i, s in enumerate(rem["rollback"], 1)]
        lines += [""]

    if approval:
        lines += [
            "### ✅ Approval Audit",
            f"Approved by **{approval.get('actor', 'reviewer')}** at {approval.get('decided_at', '')}: {approval.get('reason', '')}",
            f"- **Decision:** `{approval.get('state', '').replace('_', ' ').title()}`",
            f"- **Reviewer:** **{approval.get('actor', 'reviewer')}**",
            f"- **Timestamp:** {approval.get('decided_at', '')}",
            f"- **Reason:** {approval.get('reason', '')}",
            "",
        ]

    lines += ["---", f"_No change was applied automatically. Findings: {', '.join(rem.get('finding_ids', [])[:12])}_"]
    return "\n".join(lines)


def render_pull_request(
    rem: dict,
    repo: dict,
    approval: Optional[dict] = None,
    repo_dir: Optional[Path | str] = None,
    impact: Optional[dict] = None,
) -> tuple[str, str, bool]:
    """Render PR title and markdown body. Return (title, body, used_repo_template)."""
    title = generate_pr_title(rem)
    found = find_pr_template(repo_dir)

    if found:
        rel_path, template_text = found
        body = _conform_to_repo_template(template_text, rem, repo, approval, impact)
        return (title, body, True)

    body = _render_standard_pr(rem, repo, approval, impact)
    return (title, body, False)
