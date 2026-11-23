"""Page 3: dependency graph - direct vs transitive views, severity alerts, and tracing to source packages."""
from __future__ import annotations

import networkx as nx
import streamlit as st

from graph.dependency_tracer import trace_component
from graph.graph_builder import roots_of
from graph.graph_exporter import graph_from_json, subgraph_for, to_cytoscape
from graph.impact_analyzer import impact_of
from ui.components.common import df, download_json, repo_caption, require_result
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


def _worst(sevs) -> str:
    return max(sevs, key=lambda s: SEV_RANK.get(s or "UNKNOWN", 0)) or "UNKNOWN"


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
    vulns = r.get("vulnerabilities", [])
    roots = roots_of(g)
    labels = {n: g.nodes[n].get("label", n) for n in g.nodes}
    comps = [n for n, a in g.nodes(data=True) if a.get("kind") == "component"]
    direct_nodes = {n for n, per in rel.items() if any(v.startswith("direct") for v in per.values())}
    trans_nodes = {n for n, per in rel.items() if any(v == "transitive" for v in per.values()) and n not in direct_nodes}

    # ------------------------------------------------------------------ severity alert banner
    tv = [f for f in vulns if f["dependency_type"] == "transitive"]
    hi = [f for f in tv if f["severity"] in ("CRITICAL", "HIGH")]
    if hi:
        src = {p for f in hi for p in f["source_packages"]}
        st.error(f"🚨 {len(hi)} CRITICAL/HIGH vulnerabilit{'y' if len(hi) == 1 else 'ies'} sit in **transitive** dependencies, introduced by {len(src)} direct "
                 f"dependenc{'y' if len(src) == 1 else 'ies'}. You cannot see them in your manifest - see 'Transitive alerts' below.")
    elif tv:
        st.warning(f"{len(tv)} lower-severity vulnerabilities are in transitive dependencies.")
    elif vulns:
        st.info("All vulnerable packages are direct dependencies.")

    c = st.columns(6)
    c[0].metric("Service roots", len(roots))
    c[1].metric("Direct dependencies", len(direct_nodes))
    c[2].metric("Transitive-only", len(trans_nodes))
    c[3].metric("Vulnerable direct", len({n for n in vmap if n in direct_nodes}))
    c[4].metric("Vulnerable transitive", len({n for n in vmap if n in trans_nodes}))
    c[5].metric("Relationships", g.number_of_edges())
    st.caption("Edge direction: parent → child (the parent depends on the child). Direct/transitive is always relative to a root. Dashed yellow edges are inferred (no recorded parent).")
    for w in val.get("warnings", []):
        st.warning(w)

    tab_graph, tab_alert, tab_src, tab_inspect, tab_tables = st.tabs(["Graph", "🚨 Transitive alerts", "Source packages", "Trace a package", "Tables"])

    # ------------------------------------------------------------------ graph
    with tab_graph:
        mode = st.radio("View", ["Direct dependencies only", "Transitive dependencies only", "Vulnerability paths (root → … → vulnerable)", "Service subgraph",
                                 "Component neighbourhood"], horizontal=True)
        max_nodes = st.slider("Maximum nodes drawn", 30, 600, 250, 10, help="Large graphs are never drawn in full.")
        sub = None
        if mode.startswith("Direct"):
            only_vuln = st.checkbox("Only vulnerable direct dependencies", False)
            keep = set(roots)
            for n in direct_nodes:
                if not only_vuln or n in vmap:
                    keep.add(n)
            sub = g.subgraph(set(list(keep)[:max_nodes] if len(keep) > max_nodes else keep)).copy()
            st.caption("Roots and the packages they depend on directly.")
        elif mode.startswith("Transitive"):
            only_vuln = st.checkbox("Only transitive packages that are vulnerable (plus the path to them)", True)
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
            opts = {f["finding_id"]: f"{SEV_ICON[f['severity'] or 'UNKNOWN']} {f['finding_id']} · {f['primary_id']} · {f['package_name']}@{f['installed_version']} ({f['dependency_type']})" for f in vf}
            sel = st.multiselect("Vulnerabilities to trace", list(opts), default=list(opts)[:3], format_func=lambda k: opts[k])
            focus = [ref for f in vf if f["finding_id"] in sel for ref in (f.get("component_refs") or [f["component_ref"]])]
            sub = subgraph_for(g, "vulnerable", focus=focus, max_nodes=max_nodes) if focus else None
            if not focus:
                st.info("Select at least one vulnerability.")
        elif mode.startswith("Service"):
            a, b = st.columns(2)
            root = a.selectbox("Service root", roots, format_func=lambda n: labels[n])
            depth = b.slider("Depth", 1, 6, 2)
            sub = subgraph_for(g, "service", root=root, depth=depth, max_nodes=max_nodes)
        else:
            q = st.text_input("Find a package (name contains)")
            cands = [n for n in comps if q.lower() in labels[n].lower()][:300] if q else comps[:300]
            if cands:
                pick = st.selectbox("Package", cands, format_func=lambda n: labels[n])
                depth = st.slider("Depth", 1, 5, 2)
                sub = subgraph_for(g, "neighborhood", focus=[pick], depth=depth, max_nodes=max_nodes)
        if sub is not None and len(sub):
            if len(sub) >= max_nodes:
                st.caption(f"View capped at {max_nodes} nodes.")
            render_cytoscape(to_cytoscape(sub, vmap, rel), 520)
            st.caption("Node colour = worst vulnerability severity. Click a node to highlight its ancestors back to the service root.")

    # ------------------------------------------------------------------ transitive alerts
    with tab_alert:
        st.markdown("Every vulnerable **transitive** dependency, with the direct dependency that is responsible for pulling it in.")
        rows = []
        for f in sorted(tv, key=lambda f: -SEV_RANK[f["severity"] or "UNKNOWN"]):
            e = next((x for x in f["exposures"] if x["relationship"] == "transitive"), f["exposures"][0] if f["exposures"] else None)
            path = e["paths"][0] if e and e["paths"] else []
            rows.append({"Severity": f"{SEV_ICON[f['severity'] or 'UNKNOWN']} {f['severity'] or 'n/a'}", "Vulnerability": f["primary_id"],
                         "Vulnerable package": f"{f['package_name']}@{f['installed_version']}", "Source (direct) package": ", ".join(f["source_packages"][:3]),
                         "Immediate parent": ", ".join(f["immediate_parents"][:2]), "Depth": e["depth"] if e else None,
                         "Full path": " → ".join(path[1:]) if path else "", "Fixed in": f["recommended_fix"] or "none recorded", "Root": f["root_component"]})
        st.caption(f"{len(rows)} transitive vulnerability alerts")
        df(rows, height=420)
        if rows:
            pick = st.selectbox("Open a chain", [f"{x['Vulnerability']} · {x['Vulnerable package']}" for x in rows])
            x = rows[[f"{y['Vulnerability']} · {y['Vulnerable package']}" for y in rows].index(pick)]
            st.code(f"{x['Root']}\n  └─ {x['Full path'].replace(' → ', chr(10) + '       └─ ')}", language="text")
            st.caption(f"Fix: upgrade {x['Vulnerable package'].split('@')[0]} to {x['Fixed in']}, or update the source package '{x['Source (direct) package']}' to a release that depends on a patched version.")

    # ------------------------------------------------------------------ source packages
    with tab_src:
        st.markdown("**Which direct dependency is responsible?** Findings grouped by the first dependency after the root - fixing one source package can clear many vulnerable packages.")
        spv = r.get("source_package_view", [])
        df([{"Risk": x["worst_risk"], "CVSS sev.": x["worst_severity"] or "n/a", "Root": x["root"], "Source package": x["source_package"],
             "Itself vulnerable": "yes" if x["is_itself_vulnerable"] else "no", "Vulnerable packages": x["vulnerable_packages"], "Findings": x["findings"],
             "Suggested fix": x["top_fix"] or "", "Packages": ", ".join(x["packages"][:5])} for x in spv], height=420)

    # ------------------------------------------------------------------ trace a package
    with tab_inspect:
        q2 = st.text_input("Search package to trace", key="trace_q", placeholder="e.g. minimist")
        pool = [n for n in comps if q2.lower() in labels[n].lower()][:200] if q2 else list(vmap)[:200]
        if pool:
            target = st.selectbox("Package", pool, format_func=lambda n: labels.get(n, n), key="trace_pick")
            t = trace_component(g, target, max_paths=25)
            imp = impact_of(g, target)
            st.write(f"**{t['label']}** — immediate parents: {', '.join(t['immediate_parents']) or 'none (root dependency)'} · dependents: {imp['dependents']} · "
                     f"transitive blast radius: {imp['blast_radius_components']} packages")
            if target in vmap:
                st.error(f"Vulnerable ({vmap[target]}) — details on the Vulnerability Findings page.")
            for ro in t["roots"]:
                tag = {"direct": "DIRECT", "direct_inferred": "DIRECT (inferred)", "transitive": "TRANSITIVE"}[ro["relationship"]]
                with st.expander(f"Relative to **{ro['root_label']}**: {tag} (depth {ro['depth']}, {len(ro['paths'])} path(s){' — truncated' if ro['truncated'] else ''})", expanded=len(t["roots"]) == 1):
                    for p in ro["paths"]:
                        st.code(" → ".join(p), language="text")
            if not t["roots"]:
                st.info("This package is not reachable from any service root.")
        else:
            st.caption("Type a name to search packages.")

    with tab_tables:
        t1, t2 = st.tabs(["Direct dependencies per root", "Shared packages"])
        with t1:
            rows = [{"Root": labels.get(root, root), "Package": labels[n], "Type": kind, "Vulnerable": vmap.get(n, "")}
                    for n, per in rel.items() for root, kind in per.items() if kind.startswith("direct") and n in g]
            df(rows, height=300)
        with t2:
            rows = [{"Package": labels[n], "Parents": g.in_degree(n), "Roots": len(per), "Relationships": ", ".join(f"{labels.get(k, k)}: {v}" for k, v in per.items())}
                    for n, per in rel.items() if n in g and (len(per) > 1 or g.in_degree(n) > 1)]
            st.caption(f"{len(rows)} packages are shared (several parents or roots).")
            df(sorted(rows, key=lambda x: -x["Parents"])[:300], height=300)
        with st.expander("Graph validation details"):
            st.json({k: v for k, v in val.items() if k not in ("unreachable_components",)})
    download_json("Download dependency graph JSON", {**gd}, f"{r['repo']['name']}-graph.json", "dl_graph")
