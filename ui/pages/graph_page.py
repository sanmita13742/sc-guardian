"""Page 3: dependency graph exploration and path inspection."""
from __future__ import annotations

import streamlit as st

from graph.dependency_tracer import trace_component
from graph.graph_exporter import graph_from_json, subgraph_for, to_cytoscape
from graph.graph_builder import roots_of
from graph.impact_analyzer import impact_of
from ui.components.common import df, download_json, repo_caption, require_result
from ui.visualizations.cytoscape_view import render_cytoscape

SEV_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "UNKNOWN": 0}


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
    st.header("Dependency Graph")
    r = require_result()
    if not r:
        return
    repo_caption(r)
    gd = r["graph"]
    g = _graph(r["repo"]["scan_id"], {k: gd[k] for k in ("nodes", "edges")})
    val, rel = gd.get("validation", {}), gd.get("relationships", {})
    vmap = _vuln_map(r)
    roots = roots_of(g)
    comps = [n for n, a in g.nodes(data=True) if a.get("kind") == "component"]
    c = st.columns(5)
    c[0].metric("Roots / services", len(roots))
    c[1].metric("Packages", len(comps))
    c[2].metric("Relationships", g.number_of_edges())
    c[3].metric("Vulnerable nodes", len(vmap))
    c[4].metric("Acyclic", "yes" if val.get("is_acyclic") else "no (handled)")
    st.caption("Edge direction: parent → child (the parent depends on the child). Direct/transitive is always relative to a root.")
    for w in val.get("warnings", []):
        st.warning(w)

    mode = st.radio("View", ["Overview (roots + direct dependencies)", "Service subgraph", "Vulnerability paths", "Component neighbourhood"], horizontal=True)
    max_nodes = st.slider("Maximum nodes drawn", 30, 600, 250, 10, help="Large graphs are never drawn in full.")
    labels = {n: g.nodes[n].get("label", n) for n in g.nodes}
    sub = None
    if mode.startswith("Overview"):
        sub = subgraph_for(g, "overview", max_nodes=max_nodes)
    elif mode.startswith("Service"):
        a, b = st.columns(2)
        root = a.selectbox("Service root", roots, format_func=lambda n: labels[n])
        depth = b.slider("Depth", 1, 6, 2)
        sub = subgraph_for(g, "service", root=root, depth=depth, max_nodes=max_nodes)
    elif mode.startswith("Vulnerability"):
        vf = sorted(r.get("vulnerabilities", []), key=lambda f: -SEV_RANK[f["severity"] or "UNKNOWN"])
        opts = {f["finding_id"]: f"{f['finding_id']} · {f['primary_id']} · {f['package_name']}@{f['installed_version']} ({f['severity'] or 'n/a'})" for f in vf}
        sel = st.multiselect("Vulnerabilities to trace", list(opts), default=list(opts)[:3], format_func=lambda k: opts[k])
        focus = [ref for f in vf if f["finding_id"] in sel for ref in (f.get("component_refs") or [f["component_ref"]])]
        sub = subgraph_for(g, "vulnerable", focus=focus, max_nodes=max_nodes) if focus else None
        if not focus:
            st.info("Select at least one vulnerability.")
    else:
        q = st.text_input("Find a package (name contains)")
        cands = [n for n in comps if q.lower() in labels[n].lower()][:300] if q else comps[:300]
        if cands:
            pick = st.selectbox("Package", cands, format_func=lambda n: labels[n])
            depth = st.slider("Depth", 1, 5, 2)
            sub = subgraph_for(g, "neighborhood", focus=[pick], depth=depth, max_nodes=max_nodes)
    if sub is not None:
        if len(sub) >= max_nodes:
            st.caption(f"View capped at {max_nodes} nodes.")
        render_cytoscape(to_cytoscape(sub, vmap, rel), 520)

    st.subheader("Inspect a package")
    q2 = st.text_input("Search package to trace", key="trace_q", placeholder="e.g. minimist")
    pool = [n for n in comps if q2.lower() in labels[n].lower()][:200] if q2 else [f for f in vmap][:200]
    if pool:
        target = st.selectbox("Package", pool, format_func=lambda n: labels.get(n, n), key="trace_pick")
        t = trace_component(g, target, max_paths=25)
        imp = impact_of(g, target)
        st.write(f"**{t['label']}** — immediate parents: {', '.join(t['immediate_parents']) or 'none (root dependency)'} · "
                 f"dependents: {imp['dependents']} · transitive blast radius: {imp['blast_radius_components']} packages")
        if target in vmap:
            st.error(f"Vulnerable ({vmap[target]}) — see the Vulnerability Findings page.")
        for ro in t["roots"]:
            tag = {"direct": "DIRECT", "direct_inferred": "DIRECT (inferred)", "transitive": "TRANSITIVE"}[ro["relationship"]]
            with st.expander(f"Relative to **{ro['root_label']}**: {tag} (depth {ro['depth']}, {len(ro['paths'])} path(s){' — truncated' if ro['truncated'] else ''})", expanded=len(t["roots"]) == 1):
                for p in ro["paths"]:
                    st.code(" → ".join(p), language="text")
        if not t["roots"]:
            st.info("This package is not reachable from any service root.")
    else:
        st.caption("Type a name to search packages.")

    t1, t2 = st.tabs(["Direct dependencies per root", "Shared packages"])
    with t1:
        rows = []
        for n, per in rel.items():
            for root, kind in per.items():
                if kind.startswith("direct") and n in g:
                    rows.append({"Root": labels.get(root, root), "Package": labels[n], "Type": kind, "Vulnerable": vmap.get(n, "")})
        df(rows, height=300)
    with t2:
        rows = [{"Package": labels[n], "Parents": g.in_degree(n), "Roots": len(per), "Relationships": ", ".join(f"{labels.get(k, k)}: {v}" for k, v in per.items())}
                for n, per in rel.items() if n in g and (len(per) > 1 or g.in_degree(n) > 1)]
        st.caption(f"{len(rows)} packages are shared (several parents or roots).")
        df(sorted(rows, key=lambda x: -x["Parents"])[:300], height=300)
    with st.expander("Graph validation details"):
        st.json({k: v for k, v in val.items() if k not in ("unreachable_components",)})
    download_json("Download dependency graph JSON", {**gd}, f"{r['repo']['name']}-graph.json", "dl_graph")
