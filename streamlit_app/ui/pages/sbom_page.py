"""Page 2: SBOM explorer and quality assessment."""
from __future__ import annotations

import streamlit as st

from ui.components.common import df, kv_table, page_header, read_file, require_result


def render() -> None:
    page_header("SBOM Explorer", "Component inventory, CycloneDX structural validation, and quality assessment.")
    r = require_result()
    if not r:
        return

    q, comps = r.get("quality", {}), [c for c in r["components"] if c["type"] != "file" and not c.get("is_self")]
    src = r.get("inventory_source")
    if src != "syft":
        st.caption(f"Inventory source: **{src}** (lockfile parsing)")

    c = st.columns(5)
    c[0].metric("Components", len(comps))
    c[1].metric("Inventory", (q.get("inventory_status") or "n/a").replace("_", " ").title())
    c[2].metric("Relationships", q.get("dependency_relationships", "n/a"))
    c[3].metric("Metadata", (q.get("metadata_status") or "n/a").replace("_", " ").title())
    c[4].metric("Unresolved", q.get("unresolved_components", 0))

    t1, t2, t3, t_raw, t4 = st.tabs(["Components", "Quality", "Validation & Syft", "Raw CycloneDX", "Downloads"])

    with t1:
        f1, f2, f3 = st.columns([1, 1, 2])
        ecos = sorted({x["ecosystem"] or x["purl_type"] or "unknown" for x in comps})
        sel_e = f1.multiselect("Ecosystem", ecos, placeholder="All ecosystems")
        svcs = sorted({x["service_dir"] or "." for x in comps})
        sel_s = f2.multiselect("Service", svcs, placeholder="All services")
        text = f3.text_input("Search package or PURL", placeholder="Filter by name...")

        rows = [x for x in comps if (not sel_e or (x["ecosystem"] or x["purl_type"] or "unknown") in sel_e)
                and (not sel_s or (x["service_dir"] or ".") in sel_s)
                and (not text or text.lower() in (x["name"] + (x["purl"] or "")).lower())]

        st.caption(f"Showing {len(rows)} of {len(comps)} components")
        df([{"Name": x["name"], "Version": x["version"], "Ecosystem": x["ecosystem"] or x["purl_type"],
             "Service": x["service_dir"], "License": ", ".join(x["licenses"]) or "n/a",
             "Supplier": x["supplier"] or "n/a", "PURL": x["purl"]} for x in rows], height=380)

        if rows:
            with st.expander("Component Inspector", expanded=False):
                pick = st.selectbox("Inspect component", [f"{x['name']}@{x['version']}" for x in rows[:300]])
                idx = [f"{x['name']}@{x['version']}" for x in rows[:300]].index(pick)
                kv_table({k: v for k, v in rows[idx].items() if k not in ("hashes",)})

    with t2:
        col_m1, col_m2 = st.columns(2)
        with col_m1:
            st.markdown(f"**Missing Lockfile Entries** ({q.get('lockfile_missing_from_sbom_count', 0)})")
            df(q.get("lockfile_missing_from_sbom", []), height=220)
        with col_m2:
            st.markdown(f"**SBOM Components Absent from Lockfiles** ({q.get('sbom_absent_from_lockfile_count', 0)})")
            df(q.get("sbom_absent_from_lockfile", []), height=220)

        st.caption(f"Relationships: {q.get('relationship_edges', 0)} edges recorded · {q.get('missing_relationships', 0)} components without relationships")

    with t3:
        v = r["sbom"].get("validation", {})
        st.markdown(f"**Spec:** CycloneDX {r['sbom'].get('spec_version', '1.5')} &nbsp;·&nbsp; **Valid:** {v.get('valid', True)} &nbsp;·&nbsp; **Components:** {v.get('stats', {}).get('components', 0)}")
        if r.get("syft"):
            sy = r["syft"]
            st.markdown(f"**Syft Version:** `{sy.get('version', 'n/a')}` &nbsp;·&nbsp; **Duration:** `{sy.get('duration_s', 0)}s` &nbsp;·&nbsp; **Exit Code:** `{sy.get('exit_code', 0)}`")
            if sy.get("command"):
                st.code(" ".join(sy["command"]), language="bash")

    with t_raw:
        raw = read_file(r.get("sbom_path"))
        if not raw:
            st.info("No CycloneDX artifact file available.")
        else:
            import json as _json
            doc = _json.loads(raw)
            view = st.radio("Section", ["Header", "Components", "Dependencies", "Raw JSON"], horizontal=True)
            if view == "Header":
                st.json({k: v for k, v in doc.items() if k not in ("components", "dependencies")})
            elif view == "Components":
                size = 25
                total = len(doc.get("components", []))
                page = st.number_input("Page (25/page)", 1, max(1, (total + size - 1) // size), 1)
                st.json(doc["components"][(page - 1) * size: page * size])
            elif view == "Dependencies":
                size = 40
                total = len(doc.get("dependencies", []))
                page = st.number_input("Page (40/page)", 1, max(1, (total + size - 1) // size), 1, key="dep_p")
                st.json(doc.get("dependencies", [])[(page - 1) * size: page * size])
            else:
                lines = raw.decode("utf-8", "replace").splitlines()
                st.code("\n".join(lines[:2000]), language="json")

    with t4:
        data = read_file(r.get("sbom_path"))
        if data:
            st.download_button("Download CycloneDX JSON (Syft)", data, file_name=f"{r['repo']['name']}-sbom.cdx.json", mime="application/json", use_container_width=True)
        else:
            st.info("No SBOM artifact file available.")
