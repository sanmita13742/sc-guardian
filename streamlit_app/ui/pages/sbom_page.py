"""Page 2: SBOM explorer and quality assessment."""
from __future__ import annotations

import streamlit as st

from ui.components.common import df, kv_table, read_file, repo_caption, require_result


def render() -> None:
    st.header("SBOM Explorer")
    r = require_result()
    if not r:
        return
    repo_caption(r)
    q, comps = r.get("quality", {}), [c for c in r["components"] if c["type"] != "file" and not c.get("is_self")]
    src = r.get("inventory_source")
    if src != "syft":
        st.warning(f"Inventory source: **{src}**. No Syft CycloneDX SBOM is available for this scan; components below come from lockfile parsing only.")
    c = st.columns(5)
    c[0].metric("Components", len(comps))
    c[1].metric("Inventory status", (q.get("inventory_status") or "n/a").replace("_", " "))
    c[2].metric("Relationships", q.get("dependency_relationships", "n/a"))
    c[3].metric("Metadata", (q.get("metadata_status") or "n/a").replace("_", " "))
    c[4].metric("Unresolved", q.get("unresolved_components", 0))
    st.caption("Status 'consistent with lockfiles' never means complete: only parsed ecosystems are compared.")

    t1, t2, t3, t_raw, t4 = st.tabs(["Components", "Quality assessment", "Validation & Syft", "View SBOM file", "Download"])
    with t1:
        a, b, d = st.columns(3)
        ecos = sorted({x["ecosystem"] or x["purl_type"] or "unknown" for x in comps})
        sel_e = a.multiselect("Ecosystem", ecos)
        svcs = sorted({x["service_dir"] or "." for x in comps})
        sel_s = b.multiselect("Service", svcs)
        text = d.text_input("Search name / PURL")
        rows = [x for x in comps if (not sel_e or (x["ecosystem"] or x["purl_type"] or "unknown") in sel_e) and (not sel_s or (x["service_dir"] or ".") in sel_s)
                and (not text or text.lower() in (x["name"] + (x["purl"] or "")).lower())]
        st.caption(f"{len(rows)} of {len(comps)} components")
        df([{"Name": x["name"], "Version": x["version"], "Ecosystem": x["ecosystem"] or x["purl_type"], "Service": x["service_dir"], "License": ", ".join(x["licenses"]),
             "Supplier": x["supplier"], "PURL": x["purl"], "Found by": x["found_by"]} for x in rows], height=420)
        st.bar_chart(q.get("components_by_ecosystem", {}))
        if rows:
            pick = st.selectbox("Component details", [f"{x['name']}@{x['version']}  [{x['bom_ref'][:60]}]" for x in rows[:500]])
            comp = rows[[f"{x['name']}@{x['version']}  [{x['bom_ref'][:60]}]" for x in rows[:500]].index(pick)]
            kv_table({k: v for k, v in comp.items() if k not in ("hashes",)})
    with t2:
        st.subheader("Missing metadata")
        mm = q.get("missing_metadata", {})
        st.bar_chart({k: v for k, v in mm.items()})
        st.caption("Missing fields are reported as-is; with 'Enrich missing metadata' enabled only registry-verified values are added, each with its source.")
        if r.get("enrichment"):
            st.write("Enrichment:", r["enrichment"])
        x, y = st.columns(2)
        with x:
            st.markdown(f"**Lockfile entries missing from the SBOM** ({q.get('lockfile_missing_from_sbom_count', 0)})")
            df(q.get("lockfile_missing_from_sbom", []), height=250)
        with y:
            st.markdown(f"**SBOM components absent from their lockfile scope** ({q.get('sbom_absent_from_lockfile_count', 0)})")
            df(q.get("sbom_absent_from_lockfile", []), height=250)
        st.markdown("**Relationships:** " + f"{q.get('relationship_edges', 0)} edges; {q.get('missing_relationships', 0)} components without any recorded relationship")
        st.markdown("**Duplicate/conflicting records**")
        df(q.get("duplicate_component_records", []))
        if q.get("multiple_versions_same_service"):
            with st.expander("Packages present in several versions in one service (informational)"):
                df(q["multiple_versions_same_service"])
        if q.get("lockfile_parse_errors"):
            st.error("Some files could not be parsed:")
            df(q["lockfile_parse_errors"])
        st.markdown("**Quality limitations**")
        for lim in q.get("limitations", []):
            st.markdown(f"- {lim}")
    with t3:
        v = r["sbom"]["validation"]
        st.write(f"CycloneDX spec version: **{r['sbom'].get('spec_version')}** · valid: **{v['valid']}** · components: {v['stats'].get('components')} · dependency records: {v['stats'].get('dependencies')}")
        for e in v["errors"]:
            st.error(e)
        for w in v["warnings"]:
            st.warning(w)
        st.caption("Validation checks the structural profile the scanner relies on plus bom-ref integrity; it is not a full official-schema validation.")
        if r.get("syft"):
            st.markdown("**Syft run**")
            kv_table({k: r["syft"].get(k) for k in ("version", "exit_code", "duration_s", "options", "error")} | {"command": " ".join(r["syft"].get("command", []))})
    with t_raw:
        raw = read_file(r.get("sbom_path"))
        if not raw:
            st.info("No Syft SBOM file is available for this scan.")
        else:
            import json as _json
            doc = _json.loads(raw)
            st.caption(f"{len(raw) / 1024:.0f} KB · CycloneDX {doc.get('specVersion')} · {len(doc.get('components', []))} components · {len(doc.get('dependencies', []))} dependency records")
            view = st.radio("View", ["Header (metadata, tools)", "Components", "Dependencies", "Full file"], horizontal=True)
            if view.startswith("Header"):
                st.json({k: v for k, v in doc.items() if k not in ("components", "dependencies")}, expanded=2)
            elif view == "Components":
                size, total = 25, len(doc.get("components", []))
                page = st.number_input("Page", 1, max(1, (total + size - 1) // size), 1)
                st.json(doc["components"][(page - 1) * size: page * size], expanded=1)
            elif view == "Dependencies":
                size, total = 40, len(doc.get("dependencies", []))
                page = st.number_input("Page", 1, max(1, (total + size - 1) // size), 1, key="dep_page")
                st.json(doc.get("dependencies", [])[(page - 1) * size: page * size], expanded=1)
            else:
                lines = raw.decode("utf-8", "replace").splitlines()
                st.caption(f"Showing the first {min(len(lines), 4000)} of {len(lines)} lines - use Download for the complete file.")
                st.code("\n".join(lines[:4000]), language="json", line_numbers=True)
    with t4:
        data = read_file(r.get("sbom_path"))
        if data:
            st.download_button("Download CycloneDX JSON (original Syft output)", data, file_name=f"{r['repo']['name']}-sbom.cdx.json", mime="application/json")
        else:
            st.info("No Syft SBOM file is available for this scan (or the artifact file was removed).")
        if r.get("enrichment_path") and (d2 := read_file(r["enrichment_path"])):
            st.download_button("Download enrichment overlay (derived, with provenance)", d2, file_name=f"{r['repo']['name']}-sbom-enrichment.json", mime="application/json")
