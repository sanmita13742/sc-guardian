"""Remediation: ranked, validated proposals with a human approval gate and an audit trail."""
from __future__ import annotations

import streamlit as st

from config.settings import get_settings
from remediation.delivery import (
    can_dispatch_gh_cli,
    commit_and_create_pr_branch,
    get_remediation_severity_tier,
)
from remediation.export import patch_text, pr_markdown
from remediation.pr_template_engine import find_pr_template, render_pull_request
from storage.database import Database
from storage.memory import Memory
from ui.components.common import df, page_header, require_result

ICON = {"upgrade": "⬆️", "pin": "📌", "remove": "🗑️", "replace": "🔁", "mitigate": "🛡️", "block": "⛔", "escalate": "📣"}
STATE = {"approved": "✅ approved", "rejected": "❌ rejected", "needs_review": "🔎 needs review"}


def _mem() -> Memory:
    return Memory(Database(get_settings().db_path))


def render() -> None:
    page_header(
        "Remediation",
        "Validated fixes. Low/Medium severity PRs are automated; High/Critical severity proposals require manual human acceptance or ignore.",
    )
    r = require_result()
    if not r:
        return
    rem = r.get("remediation") or {}
    items = rem.get("items") or []
    if not items:
        st.info("No remediation proposals for this scan (no vulnerability findings, remediation disabled, or this stored scan predates the Remediation Agent).")
        return
    repo = r["repo"]
    try:
        mem = _mem()
        approvals = mem.approvals(repo["url"])
    except Exception as e:  # noqa: BLE001
        st.warning(f"Approval storage unavailable: {e}")
        mem, approvals = None, {}

    vs = rem.get("validation_summary") or {}
    fixed = sum(len((i.get("what_if") or {}).get("fixed", [])) for i in items)
    auto_count = sum(1 for i in items if i.get("automation_tier") == "automated" or i.get("priority") in ("P2", "P3"))
    manual_count = len(items) - auto_count

    c = st.columns(5)
    c[0].metric("Proposals", len(items))
    c[1].metric("Findings Fixed", fixed)
    c[2].metric("⚡ Auto-PR (Low/Med)", auto_count)
    c[3].metric("👤 Manual Review (High/Crit)", manual_count)
    c[4].metric("Approved", sum(1 for i in items if approvals.get(i["fingerprint"], {}).get("state") == "approved"))

    if rem.get("groups_not_planned"):
        st.caption(f"{rem['groups_not_planned']} lower-priority source-package group(s) were not planned (limit or time budget).")

    # Table filter by automation policy
    col_f1, _ = st.columns([1, 2])
    policy_filter = col_f1.selectbox("Filter by Automation Policy", ["All Proposals", "⚡ Automated (Low/Medium)", "👤 Manual Review Required (High/Critical)"])

    rows = []
    for i in items:
        wi = i.get("what_if") or {}
        ap = approvals.get(i["fingerprint"])
        tier = i.get("automation_tier") or ("manual_review" if i.get("priority") in ("P0", "P1") else "automated")
        policy_label = "👤 Manual Review" if tier == "manual_review" else "⚡ Auto-PR"

        if policy_filter == "⚡ Automated (Low/Medium)" and tier != "automated":
            continue
        if policy_filter == "👤 Manual Review Required (High/Critical)" and tier != "manual_review":
            continue

        rows.append({
            "ID": i["id"],
            "Priority": i["priority"],
            "Policy": policy_label,
            "Action": f"{ICON.get(i['action'], '')} {i['action']}",
            "Proposal": i["title"],
            "Fixes": len(wi.get("fixed", [])) if wi else "n/a",
            "Remaining": len(wi.get("remaining", [])) if wi else "n/a",
            "New": len(wi.get("newly_introduced", [])) if wi else "n/a",
            "Breaking risk": (i.get("compatibility") or {}).get("breaking_risk", ""),
            "Confidence": i.get("confidence", ""),
            "Approval": STATE.get(ap["state"], "pending") if ap else "pending",
        })
    df(rows, height=300)

    # Proposal inspector
    pick = st.selectbox(
        "Select Proposal to Inspect",
        [i["id"] for i in items],
        format_func=lambda x: next(f"{x} · {i['priority']} · {'[⚡ Auto]' if i.get('automation_tier') == 'automated' else '[👤 Manual]'} {i['title']}" for i in items if i["id"] == x),
    )
    i = next(x for x in items if x["id"] == pick)
    wi, val = i.get("what_if") or {}, i.get("validation") or {}
    ap = approvals.get(i["fingerprint"])
    tier = i.get("automation_tier") or ("manual_review" if i.get("priority") in ("P0", "P1") else "automated")
    is_manual = (tier == "manual_review" or i.get("priority") in ("P0", "P1"))

    st.markdown(f"### {ICON.get(i['action'], '')} {i['title']}")
    st.markdown(i.get("rationale", ""))

    # --- SEVERITY & AUTOMATION POLICY BAR WITH ACCEPT / IGNORE ACTIONS ---
    if is_manual:
        st.warning(
            "⚠️ **Human Intervention Required (High / Critical Severity)**  \n"
            "This proposal addresses High or Critical risk findings. By policy, changes **will not** be committed or sent without explicit manual human approval. "
            "Please **Accept** to create the PR branch or **Ignore** to dismiss."
        )
        c_acc, c_ign, _ = st.columns([1.5, 1, 1.5])
        if c_acc.button("✅ Accept & Create PR", key=f"quick_accept_{i['id']}", type="primary", use_container_width=True):
            if mem:
                mem.set_approval(repo["url"], i["fingerprint"], "approved", "Accepted manually by analyst in Streamlit UI", i["title"], "analyst")
            r_dir = repo.get("repo_dir") or repo.get("local_path") or repo.get("path") or "."
            res = commit_and_create_pr_branch(r_dir, i, repo, {"state": "approved", "actor": "analyst", "reason": "Accepted manually by analyst in Streamlit UI"})
            st.session_state[f"pr_res_{i['id']}"] = res
            if res.get("status") == "success":
                st.success(f"🎉 Proposal accepted! Changes committed to branch `{res.get('branch', 'remediation/...')}`.")
            else:
                st.error(f"❌ Failed to create PR branch: {res.get('error')}")

        if c_ign.button("🚫 Ignore / Dismiss", key=f"quick_ignore_{i['id']}", type="secondary", use_container_width=True):
            if mem:
                mem.set_approval(repo["url"], i["fingerprint"], "rejected", "Ignored manually by analyst in Streamlit UI", i["title"], "analyst")
            st.info(f"🚫 Proposal `{i['id']}` ignored.")
            st.rerun()
    else:
        st.success(
            "⚡ **Automated Pull Request Policy Active (Low / Medium Severity)**  \n"
            "This proposal addresses Low or Medium risk findings. Pull requests are automated and sent without requiring human intervention."
        )
        c_auto_act, c_auto_ign, _ = st.columns([1.5, 1, 1.5])
        if c_auto_act.button("🚀 Commit & Create PR Branch", key=f"auto_commit_{i['id']}", type="primary", use_container_width=True):
            r_dir = repo.get("repo_dir") or repo.get("local_path") or repo.get("path") or "."
            res = commit_and_create_pr_branch(r_dir, i, repo, {"state": "approved", "actor": "auto-policy", "reason": "Automated Low/Medium severity PR"})
            st.session_state[f"pr_res_{i['id']}"] = res
            if res.get("status") == "success":
                st.success(f"🎉 Changes committed to branch `{res['branch']}`! PR markdown saved to `{res.get('pr_file')}`.")
            else:
                st.error(f"❌ Failed to create PR branch: {res.get('error')}")

        if c_auto_ign.button("🚫 Ignore Proposal", key=f"auto_ignore_{i['id']}", type="secondary", use_container_width=True):
            if mem:
                mem.set_approval(repo["url"], i["fingerprint"], "rejected", "Overridden and ignored manually by analyst in Streamlit UI", i["title"], "analyst")
            st.info(f"🚫 Proposal `{i['id']}` ignored.")
            st.rerun()

    # Show persistent PR status if already dispatched in session
    pr_status_disp = st.session_state.get(f"pr_res_{i['id']}")
    if pr_status_disp:
        if pr_status_disp.get("status") == "success":
            st.success(f"🎉 Branch `{pr_status_disp['branch']}` created and committed! PR markdown file: `{pr_status_disp.get('pr_file')}`")
        elif pr_status_disp.get("status") == "error":
            st.error(f"❌ Branch commit failed: {pr_status_disp.get('error')}")

    if i.get("alternatives"):
        for a in i["alternatives"]:
            st.caption(f"Alternative ({a['action']}): {a['note']}")

    impact = i.get("reachability_impact") or {}
    if impact:
        with st.expander(f"🎯 Code Reachability Impact ({impact.get('reachability_preservation_score', 100)}% preserved · {impact.get('status', 'unknown')})", expanded=True):
            c_a, c_b = st.columns(2)
            c_a.metric("Preservation Score", f"{impact.get('reachability_preservation_score', 100)}%")
            c_b.metric("App Files Affected", len(impact.get("app_files_affected", [])))
            st.markdown(f"**Impact Summary:** {impact.get('impact_summary', 'N/A')}")
            if impact.get("app_files_affected"):
                st.caption("Files: " + ", ".join(f"`{f}`" for f in impact["app_files_affected"][:8]))
            if impact.get("imported_symbols"):
                st.caption("Symbols: " + ", ".join(f"`{s}`" for s in impact["imported_symbols"][:8]))
            if impact.get("recommendation"):
                st.info(f"💡 {impact['recommendation']}")

    t_eff, t_patch, t_val, t_appr = st.tabs(["Measured effect", "Patch & rollback", "Validation", "Approval & export"])
    with t_eff:
        if not wi:
            st.info("This proposal could not be simulated (no fixed version, or the registry did not resolve a tree).")
        else:
            m = st.columns(4)
            m[0].metric("Fixed", len(wi["fixed"]))
            m[1].metric("Remaining", len(wi["remaining"]))
            m[2].metric("Newly introduced", len(wi["newly_introduced"]))
            m[3].metric("Verdict", wi["verdict"].replace("_", " "))
            st.caption(wi.get("method", ""))
            if wi["fixed"]:
                st.markdown("**Fixed**")
                df(wi["fixed"], height="content")
            if wi["newly_introduced"]:
                st.warning("The proposed versions bring in advisories that are not in the project today:")
                df(wi["newly_introduced"], height="content")
            if wi.get("already_present_elsewhere"):
                st.caption(f"{wi['already_present_elsewhere']} advisory(ies) on the new dependency tree already exist in this project via another path (not counted as introduced).")
            d = wi["sbom_diff"]
            st.markdown("**Before / after SBOM of this dependency sub-tree**")
            a, b_, c3 = st.columns(3)
            a.metric("Version changes", len(d["changed"]))
            b_.metric("Added", len(d["added"]))
            c3.metric("Removed", len(d["removed"]))
            if d["changed"]:
                df([{"Package": x["package"], "Before": x["from"], "After": x["to"]} for x in d["changed"]], height=min(260, 40 + 35 * len(d["changed"])))
            if d["added"] or d["removed"]:
                with st.expander("Added / removed packages"):
                    st.write("Added: " + (", ".join(d["added"][:40]) or "none"))
                    st.write("Removed: " + (", ".join(d["removed"][:40]) or "none"))
            if wi.get("candidates_tried"):
                with st.expander("Versions tried (parent-upgrade search)"):
                    df([{"Version": c_["version"], "Advisories left": c_["remaining"], "New HIGH/CRITICAL": c_["new_high"]} for c_ in wi["candidates_tried"]], height="content")
    with t_patch:
        comp = i.get("compatibility") or {}
        if comp:
            st.markdown(f"**Compatibility:** {comp.get('semver_change')} change, breaking-change risk **{comp.get('breaking_risk')}**. {comp.get('note', '')}")
        if i.get("patch"):
            st.markdown(f"**Proposed change to** `{i['patch']['path']}`")
            st.code(i["patch"]["diff"], language="diff")
            if i.get("lock_note"):
                st.caption(f"Then refresh the lockfile: {i['lock_note']}")
            if patch_text(i):
                st.download_button("📥 Download .patch", patch_text(i), file_name=f"{i['id']}.patch", mime="text/x-diff", key=f"t_patch_dl_{i['id']}")
        else:
            st.info("No automatic patch could be produced for this proposal (manual change or no manifest found); the rationale lists what to do.")
        st.markdown("**Rollback**")
        for n, s in enumerate(i.get("rollback", []), 1):
            st.markdown(f"{n}. {s}")
    with t_val:
        matrix = val.get("matrix") or {}
        if matrix:
            st.markdown("#### 🛡️ Multi-Tier Verification Matrix")
            t_rows = []
            for k, m_item in matrix.items():
                p_val = m_item.get("passed")
                status_icon = "✅ Passed" if p_val is True else "❌ Failed" if p_val is False else "⏳ Opt-In / Pending"
                t_rows.append({"Tier": m_item.get("name", k), "Status": status_icon, "Details": m_item.get("details", "")})
            df(t_rows, height=180)

        st.markdown(f"- Patch applies cleanly (`git apply --check`): **{val.get('patch_applies')}**")
        st.markdown(f"- Static what-if rescan: **{'done' if val.get('what_if_run') else 'not possible'}**")
        bt = val.get("build_tests") or {}
        st.markdown(f"- Build and tests: **{bt.get('status', 'not_run')}** - {bt.get('reason', '') or bt.get('attribution', '')}")
        for run in bt.get("runs", []):
            with st.expander(f"{run['phase']} - exit code {run['exit_code']} ({run['seconds']}s)"):
                st.code(run["log_tail"] or "(no output)", language="text")
        if bt.get("baseline"):
            st.caption(f"Baseline (without the patch): {bt['baseline']['status']}")
        from sandbox.runner import docker_status
        ds = docker_status()
        ap_ = approvals.get(i["fingerprint"])
        if i.get("patch") and ap_ and ap_["state"] == "approved":
            if not ds["available"]:
                st.info("Optional sandbox validation is unavailable: " + ds["reason"])
            else:
                st.warning("Sandbox validation downloads dependencies and RUNS this repository's own build/test commands in Docker. "
                           "Single-container tests run without a network; validated Compose tests use an internal-only service network.")
                ok = st.checkbox("I approve running this repository's build and tests in a Docker sandbox", key=f"sbx_ok_{i['id']}")
                if st.button("Run sandbox validation", disabled=not ok, key=f"sbx_{i['id']}"):
                    from sandbox.runner import validate_in_sandbox
                    mem.audit(repo["url"], ap_["actor"], "sandbox_validation_started", i["title"], "approved by checkbox")
                    box = st.status("Running in Docker ...", expanded=True)
                    res_ = validate_in_sandbox(get_settings(), repo, i, progress=lambda m: box.write(m))
                    box.update(label=f"Sandbox result: {res_['status']}", state="complete")
                    i.setdefault("validation", {})["build_tests"] = res_
                    try:
                        Database(get_settings().db_path).save_scan(r)
                    except Exception:  # noqa: BLE001
                        pass
                    mem.audit(repo["url"], ap_["actor"], f"sandbox_validation_{res_['status']}", i["title"], str(res_.get("reason") or res_.get("attribution") or ""))
                    st.rerun()
        else:
            st.caption("Sandbox validation becomes available after a proposal is approved.")
        if i.get("evidence_id"):
            st.caption(f"Evidence `{i['evidence_id']}`")
    with t_appr:
        if ap:
            st.success(f"{STATE[ap['state']].title()} by **{ap['actor']}** on {ap['decided_at']}: {ap['reason']}")
        if mem is None:
            st.stop()
        with st.form(f"approve_{i['id']}", clear_on_submit=True):
            c1, c2 = st.columns([1, 1])
            decision = c1.radio("Decision", ["approved", "rejected", "needs_review"], format_func=lambda x: STATE[x], horizontal=True)
            actor = c2.text_input("Your name", value="analyst")
            reason = st.text_input("Reason (required)", value="Manual review decision recorded via Streamlit")
            if st.form_submit_button("Record decision"):
                try:
                    mem.set_approval(repo["url"], i["fingerprint"], decision, reason, i["title"], actor or "analyst")
                    st.rerun()
                except ValueError as e:
                    st.error(str(e))
        approved = bool((ap and ap["state"] == "approved") or not is_manual)
        if approved:
            st.markdown("---")
            st.markdown("### 🤖 Remediation Agent Delivery")

            t_info = i.get("target") or {}
            src_name = i.get("source_package") or i.get("package") or "dep"
            target_v = t_info.get("to") or "fix"
            branch_default = f"remediation/fix-{src_name}-{target_v}"
            tmpl_found = find_pr_template(repo.get("repo_dir") or repo.get("local_path") or repo.get("path") or ".")

            c_info1, c_info2 = st.columns(2)
            c_info1.markdown(f"**Target Branch:** `{branch_default}`")
            c_info2.markdown(f"**PR Template:** `{'✅ ' + tmpl_found[0] if tmpl_found else 'Standard Security PR Template'}`")

            c_act1, c_act2 = st.columns([1, 1])
            if c_act1.button("🚀 Commit & Create PR Branch", key=f"commit_btn_{i['id']}", type="primary", use_container_width=True):
                r_dir = repo.get("repo_dir") or repo.get("local_path") or repo.get("path") or "."
                res = commit_and_create_pr_branch(r_dir, i, repo, ap or {"state": "approved", "actor": "auto-policy", "reason": "Automated Low/Medium severity PR"})
                st.session_state[f"pr_res_{i['id']}"] = res
                if res.get("status") == "success":
                    st.success(f"🎉 Branch `{res['branch']}` created and changes committed!")
                    st.markdown(f"**PR markdown saved to:** `{res.get('pr_file')}`")
                else:
                    st.error(f"Git commit failed: {res.get('error')}")

            pr_res = st.session_state.get(f"pr_res_{i['id']}") or i.get("delivery_result")
            if pr_res and pr_res.get("gh_cli_available"):
                target_repo = pr_res.get("target_repo") or repo.get("url")
                st.info(f"GitHub CLI is available. This command is locked to the scanned repository: `{target_repo}`")
                args = pr_res.get("gh_pr_args") or []
                command = " ".join(f'\"{arg}\"' if any(c.isspace() for c in str(arg)) else str(arg) for arg in args)
                st.code(command, language="bash")

            with st.expander("Preview Formatted Pull Request Body"):
                pr_t, pr_b, used_tmpl = render_pull_request(i, repo, ap or {"state": "approved", "actor": "auto-policy"}, repo_dir=repo.get("repo_dir") or repo.get("local_path") or ".", impact=i.get("reachability_impact"))
                st.caption(f"Template Conformance: {tmpl_found[0] if tmpl_found else 'Standard Enterprise Security PR Format'}")
                st.code(pr_b, language="markdown")

            st.markdown("---")
            st.markdown("**Manual Export**")
            e1, e2 = st.columns(2)
            if patch_text(i):
                e1.download_button("Download .patch", patch_text(i), file_name=f"{i['id']}.patch", mime="text/x-diff", use_container_width=True)
            e2.download_button("Download PR description (.md)", pr_markdown(i, repo, ap), file_name=f"{i['id']}-pr.md", mime="text/markdown", use_container_width=True)
            st.caption("Apply with `git apply <file>.patch` on a branch, review, run the tests, then open the PR yourself.")
        else:
            st.info("Patch and PR text can be exported only after a reviewer approves this proposal.")

    with st.expander("Audit trail"):
        try:
            df([{"When": a["at"], "Who": a["actor"], "Action": a["action"], "Subject": a["subject"], "Detail": a["detail"]} for a in mem.audit_log(repo["url"])] if mem else [], height=260)
        except Exception:  # noqa: BLE001
            st.caption("Audit log unavailable.")
