"""Remediation: ranked, validated proposals with a human approval gate and an audit trail."""
from __future__ import annotations

import streamlit as st

from config.settings import get_settings
from remediation.export import patch_text, pr_markdown
from storage.database import Database
from storage.memory import Memory
from ui.components.common import df, page_header, require_result

ICON = {"upgrade": "⬆️", "pin": "📌", "remove": "🗑️", "replace": "🔁", "mitigate": "🛡️", "block": "⛔", "escalate": "📣"}
STATE = {"approved": "✅ approved", "rejected": "❌ rejected", "needs_review": "🔎 needs review"}


def _mem() -> Memory:
    return Memory(Database(get_settings().db_path))


def render() -> None:
    page_header("Remediation", "Validated, reviewable fixes. Nothing is applied automatically: a human approves before a patch or PR description can be exported.")
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
    c = st.columns(5)
    c[0].metric("Proposals", len(items))
    c[1].metric("Findings they fix", fixed)
    c[2].metric("Reduce risk (verified)", vs.get("reduces_risk", 0))
    c[3].metric("Introduce new risk", vs.get("introduces_risk", 0))
    c[4].metric("Approved", sum(1 for i in items if approvals.get(i["fingerprint"], {}).get("state") == "approved"))
    if rem.get("groups_not_planned"):
        st.caption(f"{rem['groups_not_planned']} lower-priority source-package group(s) were not planned (limit or time budget).")

    rows = []
    for i in items:
        wi = i.get("what_if") or {}
        ap = approvals.get(i["fingerprint"])
        rows.append({"ID": i["id"], "Priority": i["priority"], "Action": f"{ICON.get(i['action'], '')} {i['action']}", "Proposal": i["title"], "Fixes": len(wi.get("fixed", [])) if wi else "n/a",
                     "Remaining": len(wi.get("remaining", [])) if wi else "n/a", "New": len(wi.get("newly_introduced", [])) if wi else "n/a",
                     "Breaking risk": (i.get("compatibility") or {}).get("breaking_risk", ""), "Confidence": i.get("confidence", ""), "Approval": STATE.get(ap["state"], "pending") if ap else "pending"})
    df(rows, height=320)

    pick = st.selectbox("Proposal", [i["id"] for i in items], format_func=lambda x: next(f"{x} · {i['priority']} · {i['title']}" for i in items if i["id"] == x))
    i = next(x for x in items if x["id"] == pick)
    wi, val = i.get("what_if") or {}, i.get("validation") or {}
    ap = approvals.get(i["fingerprint"])

    st.markdown(f"### {ICON.get(i['action'], '')} {i['title']}")
    st.markdown(i.get("rationale", ""))
    if i.get("alternatives"):
        for a in i["alternatives"]:
            st.caption(f"Alternative ({a['action']}): {a['note']}")

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
        else:
            st.info("No automatic patch could be produced for this proposal (manual change or no manifest found); the rationale lists what to do.")
        st.markdown("**Rollback**")
        for n, s in enumerate(i.get("rollback", []), 1):
            st.markdown(f"{n}. {s}")
    with t_val:
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
                st.warning("Sandbox validation downloads dependencies and RUNS this repository's own build/test commands inside an isolated Docker container (tests run without network).")
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
            st.caption("Sandbox validation becomes available after a reviewer approves this proposal.")
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
            actor = c2.text_input("Your name", value="reviewer")
            reason = st.text_input("Reason (required)")
            if st.form_submit_button("Record decision"):
                try:
                    mem.set_approval(repo["url"], i["fingerprint"], decision, reason, i["title"], actor or "reviewer")
                    st.rerun()
                except ValueError as e:
                    st.error(str(e))
        approved = bool(ap and ap["state"] == "approved")
        if approved:
            st.markdown("**Export** (approved)")
            e1, e2 = st.columns(2)
            if patch_text(i):
                e1.download_button("Download .patch", patch_text(i), file_name=f"{i['id']}.patch", mime="text/x-diff", use_container_width=True)
            e2.download_button("Download PR description (.md)", pr_markdown(i, repo, ap), file_name=f"{i['id']}-pr.md", mime="text/markdown", use_container_width=True)
            st.caption("Apply with `git apply <file>.patch` on a branch, review, run the tests, then open the PR yourself. The Guardian never pushes or merges.")
        else:
            st.info("Patch and PR text can be exported only after a reviewer approves this proposal.")

    with st.expander("Audit trail"):
        try:
            df([{"When": a["at"], "Who": a["actor"], "Action": a["action"], "Subject": a["subject"], "Detail": a["detail"]} for a in mem.audit_log(repo["url"])] if mem else [], height=260)
        except Exception:  # noqa: BLE001
            st.caption("Audit log unavailable.")
