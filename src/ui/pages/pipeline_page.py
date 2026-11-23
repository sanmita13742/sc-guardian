"""Pipeline & Containers: Dockerfile, compose and CI/CD findings, base images and CI actions."""
from __future__ import annotations

import streamlit as st

from ui.components.common import badge, df, page_header, require_result

SEV_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
ICON = {"CRITICAL": "🟥", "HIGH": "🟧", "MEDIUM": "🟨", "LOW": "🟦", "INFO": "⬜"}


def render() -> None:
    page_header("Pipeline & Containers", "Dockerfiles, compose files and CI/CD workflows analysed statically - nothing is built or executed.")
    r = require_result()
    if not r:
        return
    p = r.get("pipeline") or {}
    sm = p.get("summary") or {}
    if not p or not (p.get("files") or p.get("findings")):
        st.info("No Dockerfile, docker-compose file or CI/CD workflow was found in this repository (or this stored scan predates pipeline analysis).")
        return

    c = st.columns(5)
    c[0].metric("Files analysed", sm.get("files_analysed", 0))
    c[1].metric("Findings", sm.get("findings", 0))
    c[2].metric("Critical / High", sum(sm.get("by_severity", {}).get(k, 0) for k in ("CRITICAL", "HIGH")))
    c[3].metric("Base images not digest-pinned", f"{sm.get('images_unpinned', 0)} / {sm.get('images', 0)}")
    c[4].metric("Actions not SHA-pinned", f"{sm.get('actions_unpinned', 0)} / {sm.get('actions', 0)}")

    risks = {a["finding_id"]: a for a in r.get("risk_assessments", [])}
    t_find, t_img, t_act, t_files = st.tabs(["Findings", "Container images", "CI actions", "Coverage"])

    with t_find:
        f1, f2, f3 = st.columns([1, 1, 2])
        sev = f1.multiselect("Severity", SEV_ORDER, default=[s for s in SEV_ORDER if s in ("CRITICAL", "HIGH", "MEDIUM")])
        cats = f2.multiselect("Area", ["container", "ci"], format_func=lambda x: {"container": "Docker / containers", "ci": "CI/CD pipelines"}[x])
        text = f3.text_input("Search rule, file or text", placeholder="e.g. GHA001, Dockerfile, root ...")
        rows = [f for f in p["findings"] if (not sev or f["severity"] in sev) and (not cats or f["category"] in cats)
                and (not text or text.lower() in (f["rule_id"] + f["file"] + f["title"] + f["snippet"]).lower())]
        st.caption(f"Showing {len(rows)} of {len(p['findings'])} findings")
        df([{"ID": f["finding_id"], "Severity": f"{ICON.get(f['severity'], '')} {f['severity']}", "Rule": f["rule_id"], "Finding": f["title"], "Where": f"{f['file']}:{f['line']}" if f["line"] else f["file"],
             "Risk": (risks.get(f["finding_id"]) or {}).get("label", "")} for f in rows], height=360)
        if rows:
            pick = st.selectbox("Details", [f["finding_id"] for f in rows], format_func=lambda i: next(f"{i} - {f['title']}" for f in rows if f["finding_id"] == i))
            f = next(x for x in rows if x["finding_id"] == pick)
            a = risks.get(pick)
            st.markdown(f"**{f['title']}**  \n`{f['file']}" + (f":{f['line']}" if f["line"] else "") + "`" + (f" · risk {badge(a['label'])} (score {a['score']})" if a else ""))
            if f["snippet"]:
                st.code(f["snippet"], language="dockerfile" if f["category"] == "container" else "yaml")
            st.markdown(f"**Why it matters:** {f['why']}")
            st.markdown(f"**How to fix:** {f['remediation']}")
            if f.get("references"):
                st.caption("References: " + " · ".join(f["references"]))
            st.caption(f"Evidence `{f.get('evidence_id')}` · {'directly visible in the file' if f['evidence_strength'] == 'high' else 'pattern-based (heuristic)'}")

    with t_img:
        imgs = p.get("images") or []
        df([{"Image": i["ref"], "Registry class": i["kind"], "Tag": i.get("tag") or "(none)", "Digest-pinned": "yes" if i.get("digest") else "no", "Final stage": "yes" if i.get("final") else "",
             "Where": f"{i['file']}:{i['line']}"} for i in imgs], height=300)
        st.caption("official = Docker Official Image · verified-registry = well-known registry (gcr.io, mcr.microsoft.com, quay.io, ghcr.io ...) · community = individual publisher · unknown-registry = unrecognised host. Classification is heuristic.")

    with t_act:
        acts = p.get("actions") or []
        df([{"Action": a["name"] + (a.get("path") or ""), "Ref": a.get("ref") or "", "Pinned to SHA": "yes" if a.get("pinned") else "no", "Publisher": "first-party" if a.get("first_party") else "third-party",
             "Job": a.get("job", ""), "Where": f"{a['file']}:{a['line']}"} for a in acts if a.get("kind") == "action"], height=300)

    with t_files:
        df(p.get("files") or [], height=300)
