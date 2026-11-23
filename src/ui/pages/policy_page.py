"""Policy & Gate: evaluate declarative YAML policies against the loaded scan (the same engine the CLI uses in CI)."""
from __future__ import annotations

import streamlit as st

from config.settings import get_settings
from policy.engine import POLICY_DIR, PolicyError, evaluate, load_policy, parse_policy, to_rego
from storage.database import Database
from storage.memory import Memory
from ui.components.common import df, page_header, require_result

ACTION_ICON = {"block": "⛔", "warn": "⚠️", "info": "ℹ️"}


def render() -> None:
    page_header("Policy & Gate", "Policy-as-code over the evidence: block unsafe components or builds, warn on hygiene. The same YAML runs in CI via guardian.py.")
    r = require_result()
    if not r:
        return
    names = sorted(p.stem for p in POLICY_DIR.glob("*.yaml"))
    c1, c2 = st.columns([1, 2])
    choice = c1.selectbox("Policy", names + ["(custom YAML)"], index=names.index("default") if "default" in names else 0)
    try:
        if choice == "(custom YAML)":
            text = c2.text_area("Policy YAML", value=(POLICY_DIR / "default.yaml").read_text(encoding="utf-8") if (POLICY_DIR / "default.yaml").exists() else "rules: []", height=260)
            pol = parse_policy(text, "custom")
        else:
            pol = load_policy(choice)
            c2.caption(pol.get("description", ""))
    except PolicyError as e:
        st.error(f"Policy error: {e}")
        return

    try:
        waivers = Memory(Database(get_settings().db_path)).decisions(r["repo"]["url"])
    except Exception:  # noqa: BLE001
        waivers = {}
    res = evaluate(pol, r, waivers)
    if res["passed"]:
        st.success(f"✅ PASS - policy `{res['policy']}`: no blocking violations ({res['warnings']} warning(s), {res['waived']} waived).")
    else:
        st.error(f"⛔ FAIL - policy `{res['policy']}`: {res['blocking']} blocking violation(s), {res['warnings']} warning(s), {res['waived']} waived. A CI run of `guardian.py gate` would exit with code 1.")

    m = st.columns(4)
    m[0].metric("Blocking", res["blocking"])
    m[1].metric("Warnings", res["warnings"])
    m[2].metric("Waived (decisions/exceptions)", res["waived"])
    m[3].metric("Rules / facts evaluated", f"{res['rules_evaluated']} / {res['facts_evaluated']}")

    t_v, t_r, t_w, t_c = st.tabs(["Violations", "By rule", "Waived", "CI usage & Rego"])
    with t_v:
        f1, f2 = st.columns(2)
        acts = f1.multiselect("Action", ["block", "warn", "info"], default=["block", "warn"])
        txt = f2.text_input("Search")
        rows = [v for v in res["violations"] if (not acts or v["action"] in acts) and (not txt or txt.lower() in (v["rule_id"] + v["subject"]).lower())]
        st.caption(f"{len(rows)} violation(s)")
        df([{"Action": f"{ACTION_ICON[v['action']]} {v['action']}", "Rule": v["rule_id"], "Finding": v["finding_id"], "Subject": v["subject"], "Evidence": ", ".join(v["evidence_ids"][:2])} for v in rows], height=380)
    with t_r:
        desc = {x["id"]: x for x in pol["rules"]}
        df([{"Rule": k, "Action": desc[k].get("action", "block"), "Matches": n, "Description": desc[k].get("description", "")} for k, n in sorted(res["by_rule"].items(), key=lambda kv: -kv[1])], height=320)
        untriggered = [x["id"] for x in pol["rules"] if x["id"] not in res["by_rule"]]
        if untriggered:
            st.caption("Rules with no match: " + ", ".join(untriggered))
    with t_w:
        if res["waived_items"]:
            df([{"Rule": v["rule_id"], "Subject": v["subject"], "Waived by": v["waiver"]["source"], "Reason": v["waiver"]["reason"], "Expires": v["waiver"].get("expires") or ""} for v in res["waived_items"]], height=260)
        else:
            st.caption("No waived findings. Record analyst decisions on the Risk page (accepted risk / false positive) - they appear here and never hide the finding.")
    with t_c:
        st.markdown("**Gate a pipeline** (exit code 1 when the policy blocks):")
        st.code(f"python guardian.py scan {r['repo']['url']} --policy {choice if choice != '(custom YAML)' else 'path/to/policy.yaml'}\npython guardian.py gate latest --policy strict --json", language="bash")
        st.markdown("**GitHub Actions** step: see `.github/workflows/guardian.yml`.")
        st.markdown("**Equivalent OPA / Conftest policy** (illustrative export of the same rules; the YAML engine is authoritative):")
        st.code(to_rego(pol), language="text")
        st.download_button("Download policy result (JSON)", __import__("json").dumps(res, indent=2, default=str), file_name=f"{r['repo']['name']}-policy-{res['policy']}.json", mime="application/json")
