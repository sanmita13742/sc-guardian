"""Fix Report: every remediation that was fixed, with its scoring, the files that changed and a one-page PDF per fix."""
from __future__ import annotations

import streamlit as st

from remediation.apply_local import applied_record, undo_in_place
from remediation.local_trial import trial_record
from reporting.fix_pdf import HAS_REPORTLAB, build_pdf
from reporting.fix_report import SEV_ORDER, collect_fixes, totals
from ui.components.common import df, page_header, require_result

SEV_ICON = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🔵", "UNKNOWN": "⚪"}


def render() -> None:
    page_header("Fix Report", "Every remediation that was fixed: what it resolved, how the risk changed, which files were edited, and a one-page PDF to share.")
    r = require_result()
    if not r:
        return
    repo = r["repo"]
    vulns = r.get("vulnerabilities") or []
    items = (r.get("remediation") or {}).get("items") or []
    delivered = {k[len("pr_res_"):]: v for k, v in st.session_state.items() if k.startswith("pr_res_") and isinstance(v, dict)}
    fixes = collect_fixes(r, trial_loader=trial_record, delivered=delivered)
    t = totals(fixes, len(vulns))

    m = st.columns(4)
    m[0].metric("Fixes applied", t["fixes"])
    m[1].metric("Findings fixed", t["findings_fixed"])
    m[2].metric("Findings remaining", t["remaining"], help="Total findings minus those resolved by the fixes below (rescan the project to confirm)")
    m[3].metric("Proposals still open", max(len(items) - len(fixes), 0))

    if not fixes:
        st.info("No fix has been applied yet. Open **Remediation**, press **Resolve** on a proposal, then **Accept & Apply Changes**; it will appear here with a downloadable PDF."
                if repo.get("source") == "local" else
                "No fix has been committed yet. On **Remediation**, create a branch for a proposal; it will appear here with a downloadable PDF.")
        return

    name = (repo.get("name") or "project").replace(" ", "-")
    c1, c2 = st.columns([3, 1])
    c1.caption(f"{len(fixes)} fix(es), newest first. Each PDF is a single page with the vulnerability scoring, the fix, the files and the validation record.")
    if HAS_REPORTLAB:
        c2.download_button("⬇ All fixes (PDF)", build_pdf(fixes), file_name=f"{name}-fix-report.pdf", mime="application/pdf", type="primary", use_container_width=True, key="pdf_all")
    else:
        c2.caption("PDF export disabled (install 'reportlab')")

    for n, f in enumerate(fixes):
        top = next((k for k in SEV_ORDER if f["severity_counts"].get(k)), "UNKNOWN")
        with st.expander(f"{f['id']} · {f['title']} · {len(f['findings'])} finding(s) fixed", expanded=(n == 0)):
            h1, h2 = st.columns([4, 1])
            h1.caption(f"{f['how']} · {(f['applied_at'] or '').replace('T', ' ').replace('Z', ' UTC')} · priority {f['priority'] or '-'}")
            if HAS_REPORTLAB:
                h2.download_button("⬇ PDF", build_pdf([f]), file_name=f"{name}-{f['id']}.pdf", mime="application/pdf", key=f"pdf_{f['id']}", use_container_width=True)
            else:
                h2.caption("PDF disabled")

            k = st.columns(4)
            k[0].metric("Findings fixed", len(f["findings"]))
            k[1].metric("Highest severity", f"{SEV_ICON[top]} {top.title()}" if f["findings"] else "n/a")
            k[2].metric("Top risk score", f"{f['max_score']:.0f} → 0" if f["max_score"] is not None else "n/a", help="Highest contextual score among the fixed findings, before and after")
            v = f["validation"]
            k[3].metric("Validation", {"passed": "Passed", "failed": "Failed", "static": "Static"}.get(v["status"], "n/a"), help=f"tests: {str(v.get('tests', 'n/a')).replace('_', ' ')}")

            t_vuln, t_chg, t_val = st.tabs(["Vulnerabilities fixed", "What changed", "Validation"])
            with t_vuln:
                df([{"": SEV_ICON.get(x["severity"], ""), "ID": x["id"], "Package": f"{x['package']}@{x['version']}", "Severity": x["severity"].title(),
                     "CVSS": x["cvss"] if x["cvss"] is not None else "n/a", "Risk": (x["risk"] or "n/a").title(),
                     "Score": f"{x['score']:.0f}/100" if x["score"] is not None else "n/a", "Priority": x["priority"] or "-", "Fixed in": x["fixed_in"]} for x in f["findings"]],
                   height="content")
                rc = f["risk_counts"]
                st.caption("Contextual risk before this fix: " + " · ".join(f"{rc[q]} {q.lower()}" for q in ("CRITICAL", "HIGH", "MEDIUM", "LOW") if rc.get(q)) + " · after: all resolved.")
                if f["rationale"]:
                    st.markdown("**Why this fix**")
                    st.markdown(f["rationale"])
            with t_chg:
                tg = f["target"]
                st.markdown(f"**{tg.get('package', '-')}** · `{tg.get('from') or '-'}` → `{tg.get('to') or '-'}`" + (f" · {f['repo']['path']}" if f["repo"].get("path") else ""))
                for ch in f["changes"]:
                    st.markdown(f"`{ch['path']}` · {ch['kind']} · **+{ch['added']}** / **−{ch['removed']}**")
                    if ch["lines"] and ch["kind"] != "lockfile":
                        st.code("\n".join(ch["lines"][:30]), language="diff")
                if f["lock"].get("note"):
                    st.caption(f"Lockfile: {f['lock']['note']}")
            with t_val:
                if v["steps"]:
                    for stp in v["steps"]:
                        st.markdown(f"{'✅' if stp['ok'] else '❌'} **{stp['step']}** · {stp['detail']}")
                else:
                    st.caption("No clone validation record for this fix (static what-if only).")
                for w in v["warnings"]:
                    st.warning(w)
            if repo.get("source") == "local":
                prop = next((x for x in items if x["id"] == f["id"]), None)
                root = repo.get("local_path") or repo.get("repo_dir") or repo.get("path") or "."
                if prop and applied_record(root, prop) and st.button("↩️ Undo this change (restore the original files)", key=f"undo_{f['id']}"):
                    res = undo_in_place(root, prop)
                    if res["status"] == "success":
                        st.rerun()
                    else:
                        st.error(res["error"])
