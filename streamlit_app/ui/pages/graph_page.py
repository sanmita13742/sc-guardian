"""Page 3: dependency graph - direct vs transitive views, severity alerts, and tracing to source packages."""
from __future__ import annotations

import networkx as nx
import streamlit as st

from graph.dependency_tracer import trace_component
from graph.graph_builder import roots_of
from graph.graph_exporter import graph_from_json, subgraph_for, to_cytoscape
from graph.impact_analyzer import impact_of
from ui.components.common import df, download_json, page_header, require_result
from ui.visualizations.cytoscape_view import render_cytoscape

SEV_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "UNKNOWN": 0}
SEV_ICON = {"CRITICAL": "🟥", "HIGH": "🟧", "MEDIUM": "🟨", "LOW": "🟦", "UNKNOWN": "🟪"}


@st.cache_data(show_spinner=False)
def _graph(scan_id: str, data: dict):
    return graph_from_json(data)


def _vuln_map(r: dict) -> dict[str, str]:
    m: dict[str, str] = {}
    for f in r.get("vulnerabilities", []):
        sev = f["severity"] or "UNKNOWN"
        for ref in f.get("component_refs") or [f["component_ref"]]:
            if SEV_RANK[sev] >= SEV_RANK.get(m.get(ref, "UNKNOWN"), -1):
                m[ref] = sev
    return m


def render() -> None:
    page_header("Dependency Graph", "Directed dependency topology, direct vs transitive classification, and transitive alerts.")
    r = require_result()
    if not r:
        return

    gd = r["graph"]
    g = _graph(r["repo"]["scan_id"], {k: gd[k] for k in ("nodes", "edges")})
    val, rel = gd.get("validation", {}), gd.get("relationships", {})
    vmap = _vuln_map(r)
    vulns = r.get("vulnerabilities", [])
    roots = roots_of(g)
    labels = {n: g.nodes[n].get("label", n) for n in g.nodes}
    comps = [n for n, a in g.nodes(data=True) if a.get("kind") == "component"]
    direct_nodes = {n for n, per in rel.items() if any(v.startswith("direct") for v in per.values())}
    trans_nodes = {n for n, per in rel.items() if any(v == "transitive" for v in per.values()) and n not in direct_nodes}

    # Transitive alert banner
    tv = [f for f in vulns if f["dependency_type"] == "transitive"]
    hi = [f for f in tv if f["severity"] in ("CRITICAL", "HIGH")]
    if hi:
        src = {p for f in hi for p in f["source_packages"]}
        st.error(f"🚨 **{len(hi)}** Critical/High vulnerabilities sit in **transitive** dependencies (introduced by **{len(src)}** direct dependencies).")
    elif tv:
        st.warning(f"{len(tv)} lower-severity vulnerabilities are in transitive dependencies.")

    c = st.columns(6)
    c[0].metric("Service Roots", len(roots))
    c[1].metric("Direct Deps", len(direct_nodes))
    c[2].metric("Transitive Deps", len(trans_nodes))
    c[3].metric("Vuln Direct", len({n for n in vmap if n in direct_nodes}))
    c[4].metric("Vuln Transitive", len({n for n in vmap if n in trans_nodes}))
    c[5].metric("Total Edges", g.number_of_edges())

    tab_graph, tab_alert, tab_src, tab_inspect, tab_tables = st.tabs(["Graph View", "Transitive Alerts", "Source Packages", "Package Tracer", "Tables"])

    with tab_graph:
        ctrl1, ctrl2 = st.columns([3, 1])
        mode = ctrl1.radio("Perspective", ["Direct only", "Transitive only", "Vulnerability paths", "Service subgraph", "Component neighborhood"], horizontal=True)
        max_nodes = ctrl2.slider("Max nodes", 30, 500, 200, 10)

        sub = None
        if mode.startswith("Direct"):
            only_vuln = st.checkbox("Only vulnerable direct dependencies", False)
            keep = set(roots)
            for n in direct_nodes:
                if not only_vuln or n in vmap:
                    keep.add(n)
            sub = g.subgraph(set(list(keep)[:max_nodes] if len(keep) > max_nodes else keep)).copy()
        elif mode.startswith("Transitive"):
            only_vuln = st.checkbox("Only vulnerable transitive packages", True)
            if only_vuln:
                focus = [n for n in vmap if n in trans_nodes]
                sub = subgraph_for(g, "vulnerable", focus=focus, max_nodes=max_nodes) if focus else None
                if not focus:
                    st.info("No vulnerable transitive dependencies.")
            else:
                keep = set(roots) | trans_nodes | {p for n in trans_nodes for p in g.predecessors(n) if p in direct_nodes}
                sub = g.subgraph(set(list(keep)[:max_nodes])).copy()
        elif mode.startswith("Vulnerability"):
            vf = sorted(vulns, key=lambda f: -SEV_RANK[f["severity"] or "UNKNOWN"])
            opts = {f["finding_id"]: f"{f['primary_id']} · {f['package_name']}@{f['installed_version']} ({f['dependency_type']})" for f in vf}
            sel = st.multiselect("Vulnerabilities to trace", list(opts), default=list(opts)[:3], format_func=lambda k: opts[k])
            focus = [ref for f in vf if f["finding_id"] in sel for ref in (f.get("component_refs") or [f["component_ref"]])]
            sub = subgraph_for(g, "vulnerable", focus=focus, max_nodes=max_nodes) if focus else None
        elif mode.startswith("Service"):
            root = st.selectbox("Service root", roots, format_func=lambda n: labels[n])
            sub = subgraph_for(g, "service", root=root, depth=2, max_nodes=max_nodes)
        else:
            q = st.text_input("Find package", placeholder="e.g. express")
            cands = [n for n in comps if q.lower() in labels[n].lower()][:200] if q else comps[:200]
            if cands:
                pick = st.selectbox("Package", cands, format_func=lambda n: labels[n])
                sub = subgraph_for(g, "neighborhood", focus=[pick], depth=2, max_nodes=max_nodes)

        if sub is not None and len(sub):
            render_cytoscape(to_cytoscape(sub, vmap, rel), 500)

    with tab_alert:
        rows = []
        for f in sorted(tv, key=lambda f: -SEV_RANK[f["severity"] or "UNKNOWN"]):
            e = next((x for x in f["exposures"] if x["relationship"] == "transitive"), f["exposures"][0] if f["exposures"] else None)
            path = e["paths"][0] if e and e["paths"] else []
            rows.append({
                "Severity": f"{SEV_ICON[f['severity'] or 'UNKNOWN']} {f['severity'] or 'n/a'}",
                "Vulnerability": f["primary_id"],
                "Package": f"{f['package_name']}@{f['installed_version']}",
                "Source (Direct)": ", ".join(f["source_packages"][:2]),
                "Depth": e["depth"] if e else "n/a",
                "Full Path": " → ".join(path[1:]) if path else "",
                "Fixed in": f["recommended_fix"] or "none",
            })
        st.caption(f"{len(rows)} transitive vulnerability alert(s)")
        df(rows, height=360)

    with tab_src:
        spv = r.get("source_package_view", [])
        df([{"Risk": x["worst_risk"], "Severity": x["worst_severity"] or "n/a", "Source Package": x["source_package"],
             "Itself Vulnerable": "Yes" if x["is_itself_vulnerable"] else "No",
             "Transitive CVEs": x["vulnerable_packages"], "Findings": x["findings"],
             "Suggested Fix": x["top_fix"] or ""} for x in spv], height=360)

    with tab_inspect:
        q2 = st.text_input("Search package to trace", placeholder="e.g. minimist")
        pool = [n for n in comps if q2.lower() in labels[n].lower()][:150] if q2 else list(vmap)[:150]
        if pool:
            target = st.selectbox("Select package", pool, format_func=lambda n: labels.get(n, n))
            t = trace_component(g, target, max_paths=15)
            imp = impact_of(g, target)
            st.markdown(f"**{t['label']}** — dependents: `{imp['dependents']}` · blast radius: `{imp['blast_radius_components']}` packages")
            for ro in t["roots"]:
                with st.expander(f"Path to Root: {ro['root_label']} ({ro['relationship']}, depth {ro['depth']})", expanded=True):
                    for p in ro["paths"][:4]:
                        st.code(" → ".join(p), language="text")

    with tab_tables:
        rows = [{"Package": labels[n], "Parents": g.in_degree(n), "Roots": len(per)}
                for n, per in rel.items() if n in g and (len(per) > 1 or g.in_degree(n) > 1)]
        df(sorted(rows, key=lambda x: -x["Parents"])[:200], height=300)

    download_json("Download Graph JSON", {**gd}, f"{r['repo']['name']}-graph.json", "dl_graph")
