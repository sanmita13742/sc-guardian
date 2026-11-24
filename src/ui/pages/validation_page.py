"""Fix Validation: run the Fix Validation Agent on human-approved remediation proposals and inspect the evidence.

Approval happens on the Remediation page; this page only validates. Running the sandbox executes the repository's own
install/test commands in Docker, so it needs an explicit consent tick every time.
"""
from __future__ import annotations

import os
import queue
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Optional

import pandas as pd
import streamlit as st

from config.settings import get_settings
from storage.database import Database
from storage.memory import Memory
from ui.components.common import df, page_header, require_result
from validation import history
from validation.decider import Decider
from validation.fix_validator import ValidationError, is_human_approval, validate_fix

VERDICT_STYLE = {  # verdict -> (colour, label, meaning)
    "verified_fixed": ("#3fb950", "Verified fixed", "Targeted findings are gone and tests that actually ran still pass."),
    "fixed_untested": ("#58a6ff", "Fixed, untested", "Targeted findings are gone, but no executed test confirms the behaviour."),
    "partial": ("#d29922", "Partial", "Some targeted findings are gone, some remain."),
    "no_effect": ("#8b949e", "No effect", "None of the targeted findings disappeared."),
    "regressed": ("#f85149", "Regressed", "The change broke install/tests or introduced an equally severe finding."),
    "inconclusive": ("#a371f7", "Inconclusive", "The evidence needed for a verdict could not be produced."),
}
CHECK_ICON = {True: "✅", False: "❌", None: "—"}


@st.cache_data(ttl=30, show_spinner=False)
def _docker() -> dict:
    from sandbox.runner import docker_status
    return docker_status()


def _approval_label(ap: Optional[dict]) -> str:
    if not ap or ap.get("state") != "approved":
        return f"— {ap['state'].replace('_', ' ')}" if ap else "— none"
    return f"✅ {ap.get('actor')}" if is_human_approval(ap) else "🤖 auto-policy (needs a person)"


def _verdict_card(fa: dict) -> None:
    color, label, meaning = VERDICT_STYLE.get(fa.get("verdict"), ("#8b949e", fa.get("verdict") or "unknown", ""))
    st.markdown(
        f"<div style='border:1px solid {color}66; background:{color}1f; border-radius:8px; padding:12px 16px; margin:6px 0 10px 0;'>"
        f"<div style='font-size:12px; color:#8b949e;'>{fa.get('remediation_id')} · validated {fa.get('created_at', '')} · approved by {fa.get('approved_by') or 'n/a'}</div>"
        f"<div style='font-size:20px; font-weight:700; color:{color}; margin:2px 0;'>{label}</div>"
        f"<div style='font-size:13px; color:#c9d1d9;'>{meaning}</div></div>",
        unsafe_allow_html=True,
    )
    for reason in fa.get("reasons") or []:
        st.markdown(f"- {reason}")


def _findings(rows: list[dict]) -> list[dict]:
    return [{"advisory": f.get("advisory"), "package": f.get("package"), "version": f.get("version"), "severity": f.get("severity"),
             "risk": f.get("risk_label"), "priority": f.get("priority"), "service": f.get("service")} for f in rows]


def _tab_comparison(cmp: Optional[dict]) -> None:
    if not cmp or cmp.get("available") is False:
        st.info("No before/after comparison: the patched tree could not be rescanned.")
        return
    c = st.columns(4)
    c[0].metric("Targeted fixed", len(cmp.get("targeted_fixed") or []))
    c[1].metric("Targeted remaining", len(cmp.get("targeted_remaining") or []))
    c[2].metric("Newly introduced", len(cmp.get("newly_introduced") or []))
    c[3].metric("Other resolved", len(cmp.get("other_resolved") or []))
    if cmp.get("target_versions_present") is False:
        st.warning("Planned versions not observed in the rescanned inventory: " + ", ".join(cmp.get("missing_target_versions") or []))
    for title, key in (("Targeted findings remaining", "targeted_remaining"), ("Targeted findings fixed", "targeted_fixed"),
                       ("Newly introduced findings", "newly_introduced"), ("Other findings resolved", "other_resolved")):
        if cmp.get(key):
            st.markdown(f"**{title}**")
            df(_findings(cmp[key]), key=f"fv_{key}")
    changes = [{"component": x["key"].split("|")[-1], "service": x["key"].split("|")[1], "kind": kind, "before": ", ".join(x.get("before") or []),
                "after": ", ".join(x.get("after") or [])}
               for kind, key in (("changed", "components_changed"), ("added", "components_added"), ("removed", "components_removed")) for x in cmp.get(key) or []]
    st.markdown("**Component versions**")
    df(changes, key="fv_components") if changes else st.caption("No component version changed in the rescanned inventory.")
    labels = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"]
    rb, ra = cmp.get("risk_before") or {}, cmp.get("risk_after") or {}
    if rb or ra:
        st.markdown("**Risk labels, whole project (before vs after)**")
        idx = [f"{n} {x}" for n, x in enumerate(labels, 1)]  # numbered so the chart keeps severity order (it sorts categories alphabetically)
        st.bar_chart(pd.DataFrame({"before": [rb.get(x, 0) for x in labels], "after": [ra.get(x, 0) for x in labels]}, index=idx), stack=False, height=220)
    st.caption(f"Suspicious-change findings: {cmp.get('suspicious_before', 0)} before → {cmp.get('suspicious_after', 0)} after")
    pvo = cmp.get("predicted_vs_observed")
    if pvo:
        st.markdown("**Predicted (static what-if) vs observed**")
        df([{"measure": m, "predicted": pvo.get(f"predicted_{m}"), "observed": pvo.get(f"observed_{m}")} for m in ("fixed", "remaining", "new")], key="fv_pvo")
        st.caption(f"The scan predicted '{pvo.get('predicted_verdict')}'. Only the observed column is evidence.")


def _tab_sandbox(rep: dict) -> None:
    sb = rep.get("sandbox") or {}
    c = st.columns(4)
    c[0].metric("Sandbox", sb.get("status", "n/a"))
    ev = sb.get("test_evidence") or {}
    c[1].metric("Tests executed", "unknown" if ev.get("executed") is None and ev else ev.get("executed", "n/a"))
    c[2].metric("Baseline", ((sb.get("baseline") or {}).get("status") or "not needed") + (" (reused)" if sb.get("baseline_cached") else ""))
    c[3].metric("Cache volume", (sb.get("cache") or {}).get("scope", "none"), help=(sb.get("cache") or {}).get("volume"))
    if sb.get("reason"):
        st.info(sb["reason"])
    if sb.get("attribution"):
        st.caption(f"Failure attribution: {sb['attribution']}")
    if sb.get("recipe"):
        r = sb["recipe"]
        st.caption(f"Image `{r.get('image')}` · install `{r.get('install')}` · test `{r.get('test')}` · {sb.get('isolation') or ''}")
    runs = list(sb.get("runs") or []) + [dict(x, phase=f"baseline {x.get('phase')}") for x in (sb.get("baseline") or {}).get("runs") or [] if x]
    if rep.get("lockfile_regeneration"):
        runs.append({**rep["lockfile_regeneration"], "phase": "lockfile regeneration"})
    for run in runs:
        with st.expander(f"{run.get('phase')} · exit {run.get('exit_code')} · {run.get('seconds')} s"):
            st.code(run.get("log_tail") or "(no output)", language="text")
    if not runs:
        st.caption("Nothing was run in Docker for this validation.")


def _tab_agent(rep: dict) -> None:
    ag = rep.get("agent") or {}
    dec = ag.get("decider") or {}
    st.caption(f"Decision model: {'on' if dec.get('enabled') else 'off'} · {dec.get('model')} · threshold {dec.get('threshold')}. "
               "The model only answers narrow questions; its answer is used only above the threshold and may only make a verdict more cautious.")
    rows = [{"step": d.get("step"), "question": d.get("question"), "answer": str(d.get("answer")), "decided by": d.get("source"),
             "p": d.get("probability"), "reason": d.get("reason")} for d in ag.get("decisions") or []]
    df(rows, key="fv_decisions") if rows else st.caption("No decision point was reached in this run.")
    for n in ag.get("notes") or []:
        st.warning(f"Note for the {n.get('for')}: **{n.get('finding')}** ({n.get('source')}) - {n.get('detail')}")
    calls = dec.get("calls") or []
    if calls:
        st.markdown("**Model calls** (metadata only; the state sent is never stored)")
        df([{k: c.get(k) for k in ("questions", "ok", "http_status", "seconds", "error")} for c in calls], key="fv_calls")


def _tab_timings(rep: dict) -> None:
    t = dict(((rep.get("agent") or {}).get("timings_seconds") or {}))
    total = t.pop("total", rep.get("seconds"))
    if not t:
        st.caption("No timings recorded.")
        return
    st.metric("Total", f"{total} s")
    st.bar_chart(pd.DataFrame({"seconds": list(t.values())}, index=list(t.keys())), height=220, horizontal=True)


def _tab_provenance(run: dict) -> None:
    pv, rep = run.get("provenance") or {}, run.get("report") or {}
    sig = rep.get("signature") or {}
    st.caption(("Signed." if sig.get("signed") else "Unsigned statement: ") + (sig.get("note") or "")
               + (" cosign is installed." if sig.get("cosign_available") else ""))
    st.markdown("**Outputs (subjects)**")
    df([{"name": s.get("name"), "sha256": (s.get("digest") or {}).get("sha256")} for s in pv.get("subject") or []], key="fv_subjects")
    st.markdown("**Inputs (resolved dependencies)**")
    deps = ((pv.get("predicate") or {}).get("buildDefinition") or {}).get("resolvedDependencies") or []
    df([{"uri": d.get("uri"), "digest": ", ".join(f"{k}:{v}" for k, v in (d.get("digest") or {}).items())} for d in deps], key="fv_materials")
    st.markdown("**Downloads**")
    cols = st.columns(len(run.get("files") or {}) or 1)
    for col, (name, path) in zip(cols, (run.get("files") or {}).items()):
        try:
            col.download_button(name, Path(path).read_bytes(), file_name=name, mime="application/json", key=f"fv_dl_{name}", width="stretch")
        except OSError:
            col.caption(f"{name} missing")


def _run(scan_id: str, ids: list[str], settings, use_sandbox: bool, workers: int, actor: str) -> list[dict]:
    """Run validations in worker threads; progress is relayed through a queue because Streamlit elements must be updated from this thread."""
    q: "queue.Queue[str]" = queue.Queue()
    results: dict[str, dict] = {}

    def one(rid: str) -> None:
        try:
            out = validate_fix(scan_id, rid, settings=settings, actor=actor, use_sandbox=use_sandbox, progress=lambda m: q.put(f"[{rid}] {m}"))
            results[rid] = {"remediation_id": rid, "verdict": out["final_assessment"]["verdict"]}
        except ValidationError as e:
            results[rid] = {"remediation_id": rid, "error": str(e)}
        except Exception as e:  # noqa: BLE001 - shown to the user, never swallowed
            results[rid] = {"remediation_id": rid, "error": f"{type(e).__name__}: {str(e)[:300]}"}
        q.put(f"[{rid}] finished")

    box = st.status(f"Validating {len(ids)} proposal(s) ...", expanded=True)
    t0 = time.time()
    pool = ThreadPoolExecutor(max_workers=max(1, workers))
    futures = [pool.submit(one, rid) for rid in ids]
    while not all(f.done() for f in futures) or not q.empty():
        try:
            box.write(q.get(timeout=0.5))
        except queue.Empty:
            pass
    pool.shutdown()
    errors = [r for r in results.values() if "error" in r]
    box.update(label=f"Finished in {time.time() - t0:.0f} s" + (f" · {len(errors)} error(s)" if errors else ""), state="error" if errors else "complete", expanded=bool(errors))
    for e in errors:
        st.error(f"{e['remediation_id']}: {e['error']}")
    return [results[r] for r in ids if r in results]


def render() -> None:
    page_header("Fix Validation", "Proves whether an approved fix actually reduces risk: sandboxed install and tests, regenerated SBOM, rescan, "
                                  "before/after comparison and provenance. Approve proposals on the Remediation page first.")
    r = require_result()
    if not r:
        return
    s = get_settings()
    db = Database(s.db_path)
    repo, scan_id = r["repo"], r["repo"]["scan_id"]
    items = [i for i in (r.get("remediation") or {}).get("items") or [] if i.get("patch")]
    try:
        approvals = Memory(db).approvals(repo["url"])
    except Exception:  # noqa: BLE001
        approvals = {}
    runs = {x["remediation_id"]: x for x in history.list_runs(s.artifacts_dir, scan_id)}
    ds, dec = _docker(), Decider()

    c = st.columns(4)
    c[0].metric("Docker", "running" if ds.get("available") else "unavailable", help=ds.get("version") or ds.get("reason"))
    c[1].metric("Decision model", "on" if dec.enabled else "off (rules only)", help=dec.model if dec.enabled else "Set OPENROUTER_API_KEY in .env to enable.")
    c[2].metric("Package cache", os.environ.get("SCG_SANDBOX_CACHE", "auto"), help="auto: shared for npm/Go/Cargo (hash-verified), per repository for pip/Maven")
    c[3].metric("Validated", f"{len(runs)} / {len(items)}", help="Proposals with a patch that have a stored validation result")
    if source := repo.get("source"):
        if source == "local-fixture":
            st.warning("This scan was made from a local directory; validation needs a GitHub scan (it re-clones the repository at the scanned commit).")

    if not items:
        st.info("This scan has no remediation proposals with a patch, so there is nothing to validate.")
        return

    st.markdown("#### Proposals")
    df([{"id": i["id"], "title": i.get("title"), "priority": i.get("priority"), "tier": i.get("automation_tier") or "",
         "approval": _approval_label(approvals.get(i.get("fingerprint"))), "last verdict": (runs.get(i["id"]) or {}).get("verdict") or ""} for i in items],
       key="fv_items")
    human = [i["id"] for i in items if is_human_approval(approvals.get(i.get("fingerprint")))]
    waiting = [i["id"] for i in items if i["id"] not in human]
    if waiting:
        st.caption(f"{len(waiting)} proposal(s) need a person's approval before they can be validated: {', '.join(waiting)}. "
                   "Use the Decision form on the 🛠️ Remediation page (automatic policy approvals do not count).")

    st.markdown("#### Run validation")
    if not human:
        st.info("No proposal has a human approval yet.")
    else:
        with st.container(border=True):
            pick = st.multiselect("Proposals", human, default=human[:1], key="fv_pick")
            a, b = st.columns([2, 1])
            use_sandbox = a.toggle("Use Docker sandbox (install, tests, lockfile regeneration)", value=bool(ds.get("available")), disabled=not ds.get("available"),
                                   help=None if ds.get("available") else ds.get("reason"))
            workers = b.number_input("Workers", 1, 2, 1, help="Each sandbox uses 2 CPU / 2 GB")
            consent = True
            if use_sandbox:
                st.warning("The sandbox downloads dependencies and runs this repository's own install and test commands inside an isolated Docker container "
                           "(no host secrets, tests without network). A NodeGoat-sized project takes about 8-10 minutes; keep this tab open.")
                consent = st.checkbox("I approve running this repository's build and tests in a Docker sandbox", key="fv_consent")
            actor = st.text_input("Your name (recorded in the audit log)", value="analyst", key="fv_actor")
            if st.button("Validate", type="primary", disabled=not (pick and consent and actor.strip()), key="fv_go"):
                done = _run(scan_id, pick, s, use_sandbox, int(workers), actor.strip())
                if done:
                    st.session_state["fv_view"] = done[0]["remediation_id"]
                    st.session_state["fv_last"] = done
                    st.rerun()  # refresh the counts, table and results from the stored files
            for x in st.session_state.pop("fv_last", []):
                (st.error if "error" in x else st.success)(f"{x['remediation_id']}: " + (x.get("error") or f"validated, verdict {x['verdict']}"))

    st.markdown("#### Results")
    if not runs:
        st.caption("No validation has been run for this scan yet.")
        return
    ids = [i["id"] for i in items if i["id"] in runs] + [x for x in runs if x not in {i["id"] for i in items}]
    default = st.session_state.get("fv_view")
    view = st.selectbox("Proposal", ids, index=ids.index(default) if default in ids else 0,
                        format_func=lambda x: f"{x} · {(runs.get(x) or {}).get('verdict')}", key="fv_view_select")
    run = history.load_run(s.artifacts_dir, scan_id, view)
    if not run or not run.get("final"):
        st.error("The stored result for this proposal could not be read.")
        return
    fa, rep = run["final"], run.get("report") or {}
    _verdict_card(fa)
    checks = fa.get("checks") or {}
    st.markdown(" · ".join(f"{CHECK_ICON.get(v, '—')} {k.replace('_', ' ')}" for k, v in checks.items()))
    for lim in fa.get("limitations") or []:
        st.caption(f"Limitation: {lim}")
    t = st.tabs(["Before / After", "Sandbox", "Agent decisions", "Timings", "Provenance"])
    with t[0]:
        _tab_comparison(run.get("comparison"))
    with t[1]:
        _tab_sandbox(rep)
    with t[2]:
        _tab_agent(rep)
    with t[3]:
        _tab_timings(rep)
    with t[4]:
        _tab_provenance(run)

    with st.expander(f"All validations for this scan ({len(runs)})"):
        df(list(runs.values()), key="fv_history")
