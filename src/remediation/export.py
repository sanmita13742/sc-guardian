"""Exports of an approved remediation: unified diff and pull-request description. Nothing is pushed or merged anywhere."""
from __future__ import annotations

from typing import Optional

from remediation.pr_template_engine import render_pull_request


def patch_text(rem: dict) -> str:
    p = rem.get("patch")
    return p["diff"] if p else ""


def pr_markdown(rem: dict, repo: dict, approval: Optional[dict], repo_dir: Optional[str] = None) -> str:
    r_dir = repo_dir or repo.get("repo_dir") or repo.get("path")
    impact = rem.get("reachability_impact")
    _, body, _ = render_pull_request(rem, repo, approval, repo_dir=r_dir, impact=impact)
    return body
    wi = rem.get("what_if") or {}
    val = rem.get("validation") or {}
    L = [f"## {rem['title']}", "",
         f"_Proposed by SC Guardian for `{repo.get('url')}` @ `{(repo.get('commit_sha') or '')[:10]}`; requires human review before merging._", "",
         f"**Priority:** {rem['priority']} · **Action:** {rem['action']} · **Confidence:** {rem.get('confidence')}", "", "### Why", rem.get("rationale", ""), ""]
    if wi:
        L += ["### Measured effect (static what-if: registry resolution + OSV re-match)",
              f"- Fixed: **{len(wi.get('fixed', []))}** finding(s) " + ", ".join(f"{f['id']} ({f['package']})" for f in wi.get("fixed", [])[:8]),
              f"- Remaining in this group: **{len(wi.get('remaining', []))}**",
              f"- Newly introduced: **{len(wi.get('newly_introduced', []))}**" + (" - " + ", ".join(f"{f['id']} ({f['package']}@{f['version']}, {f['severity']})" for f in wi["newly_introduced"][:5]) if wi.get("newly_introduced") else ""), ""]
        d = wi.get("sbom_diff") or {}
        if d.get("changed") or d.get("added") or d.get("removed"):
            L += ["**SBOM diff (this dependency sub-tree)**", f"- changed: {', '.join(c['package'] + ' ' + c['from'] + ' -> ' + c['to'] for c in d.get('changed', [])[:10]) or 'none'}",
                  f"- added: {', '.join(d.get('added', [])[:10]) or 'none'}", f"- removed: {', '.join(d.get('removed', [])[:10]) or 'none'}", ""]
    c = rem.get("compatibility") or {}
    if c:
        L += ["### Compatibility", f"- Version change: **{c.get('semver_change')}** (breaking-change risk: {c.get('breaking_risk')}). {c.get('note', '')}", ""]
    if rem.get("lock_note"):
        L += [f"After applying, refresh the lockfile: {rem['lock_note']}", ""]
    L += ["### Validation"]
    L += [f"- Patch applies cleanly: {val.get('patch_applies')}", f"- Build/tests: {(val.get('build_tests') or {}).get('status', 'not_run')}" + (f" - {(val.get('build_tests') or {}).get('reason', '')}" if (val.get('build_tests') or {}).get('status') != 'passed' else ""), ""]
    L += ["### Rollback"] + [f"1. {s}" if i == 0 else f"{i + 1}. {s}" for i, s in enumerate(rem.get("rollback", []))] + [""]
    if approval:
        L += ["### Approval", f"{approval['state'].replace('_', ' ').title()} by **{approval['actor']}** at {approval['decided_at']}: {approval['reason']}", ""]
    L += ["---", "_No change was applied automatically. Findings: " + ", ".join(rem.get("finding_ids", [])[:12]) + "_"]
    return "\n".join(L)
