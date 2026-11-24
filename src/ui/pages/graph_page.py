"""Page 3: dependency graph - direct vs transitive views, severity alerts, and tracing to source packages."""
from __future__ import annotations

import networkx as nx
import streamlit as st

from graph.dependency_tracer import trace_component
from graph.graph_builder import roots_of
from graph.graph_exporter import dependency_payload, graph_from_json
from graph.impact_analyzer import impact_of
from graph.tree_view import build_reverse_tree, build_tree, graph_stats, tree_html, vulnerable_ancestors
from ui.components.common import df, download_json, page_header, require_result
from ui.visualizations.graphs import render_dependency_graph

SEV_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "UNKNOWN": 0}
SEV_ICON = {"CRITICAL": "🟥", "HIGH": "🟧", "MEDIUM": "🟨", "LOW": "🟦", "UNKNOWN": "🟪"}


@st.cache_data(show_spinner=False)
def _graph(scan_id: str, data: dict):
    return graph_from_json(data)


@st.cache_data(show_spinner=False)
def _cached_dependency_payload(scan_id: str, _g: nx.DiGraph, rel: dict, vmap: dict, advisories: dict, info: dict, fixes: dict) -> dict:
    return dependency_payload(_g, rel, vmap, advisories, info, fixes)


def _vuln_map(r: dict) -> dict[str, str]:
    m: dict[str, str] = {}
    for f in r.get("vulnerabilities", []):
        sev = f["severity"] or "UNKNOWN"
        for ref in f.get("component_refs") or [f["component_ref"]]:
            if SEV_RANK[sev] >= SEV_RANK.get(m.get(ref, "UNKNOWN"), -1):
                m[ref] = sev
    return m


def _changes_since_previous(r: dict) -> None:
    """Graph diff against the previous scan of the same repository (read from the persisted graph tables)."""
    from config.settings import get_settings
    from graph.graph_diff import diff_graphs
    from storage.database import Database
    try:
        db = Database(get_settings().db_path)
        prev = db.previous_scan(r["repo"]["url"], r["repo"]["scan_id"])
        old, new = (db.load_graph(prev) if prev else None), db.load_graph(r["repo"]["scan_id"])
    except Exception:
        return
    if not (prev and old and new):
        return
    d = diff_graphs(old, new)
    with st.expander("Changes since the previous scan" + (" - identical" if d["identical"] else f" - {len(d['added_components'])} added, {len(d['removed_components'])} removed, {len(d['version_changes'])} version change(s)")):
        if d["identical"]:
            st.caption("The dependency graph is identical to the previous scan.")
            return
        st.caption(f"Components {d['totals']['before']['components']} -> {d['totals']['after']['components']}; edges +{d['added_edges']} / -{d['removed_edges']}")
        for label, items in (("Added", d["added_components"]), ("Removed", d["removed_components"]), ("Version changes", d["version_changes"])):
            if items:
                st.markdown(f"**{label}**")
                for x in items[:30]:
                    st.markdown(f"- `{x}`")
                if len(items) > 30:
                    st.caption(f"... {len(items) - 30} more")


def render() -> None:
    page_header("Dependency Graph", "Directed dependency topology, direct vs transitive classification, and transitive alerts.")
    r = require_result()
    if not r:
        return

    _changes_since_previous(r)
    gd = r["graph"]
    g = _graph(r["repo"]["scan_id"], {k: gd[k] for k in ("nodes", "edges")})
    val, rel = gd.get("validation", {}), gd.get("relationships", {})
    vmap = _vuln_map(r)
    vulns = r.get("vulnerabilities", [])
    roots = roots_of(g)
    if not roots or not any(a.get("kind") == "component" for _, a in g.nodes(data=True)):
        st.info("This repository has no package dependencies to graph (no lockfile/manifest packages were found). "
                "Container images and CI actions are listed on the Pipeline & Containers page.")
        return
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
    c[3].metric("Vulnerable direct pkgs", len({n for n in vmap if n in direct_nodes}))
    c[4].metric("Vulnerable transitive pkgs", len({n for n in vmap if n in trans_nodes}))
    c[5].metric("Total Edges", g.number_of_edges())

    info = {}
    for cmp_ in r.get("components", []):
        info[cmp_["bom_ref"]] = {"scope": cmp_.get("scope"), "license": ", ".join(cmp_.get("licenses") or []), "install_script": cmp_.get("install_script"),
                                 "resolution": cmp_.get("resolution"), "deprecated": cmp_.get("deprecated"), "integrity": (cmp_.get("integrity") or {}).get("status")}

    tab_graph, tab_tree, tab_alert, tab_inspect = st.tabs(["Interactive Graph", "Dependency Tree", "Alerts & Source Packages", "Package Tracer"])

    with tab_tree:
        stats = graph_stats(g, vmap)
        s1, s2 = st.columns([1, 1])
        with s1:
            st.markdown("**How deep does the dependency chain go?**")
            st.caption("Packages per depth (shortest distance from the service root: 1 = direct, 2+ = transitive)")
            st.bar_chart({f"depth {k}": v for k, v in stats["depth_histogram"].items()})
            if stats["vulnerable_by_depth"]:
                st.caption("Vulnerable packages per depth: " + ", ".join(f"depth {k}: {v}" for k, v in stats["vulnerable_by_depth"].items()))
        with s2:
            st.markdown("**Longest chain** (" + str(max(len(stats["longest_chain"]) - 1, 0)) + " hops)")
            st.code(" -> ".join(stats["longest_chain"][:14]) + (" -> ..." if len(stats["longest_chain"]) > 14 else ""), language="text")
            if stats["most_shared"]:
                st.markdown("**Most shared** (many parents; upgrading one affects them all)")
                df([{"Package": n, "Parents": k} for n, k in stats["most_shared"][:6]], height="content")
            if stats["has_cycles"]:
                st.caption("The graph contains dependency cycles; each package is expanded once.")

        mode = st.radio("Direction", ["Top-down: what a service brings in", "Bottom-up: who pulls a package in"], horizontal=True, key="tree_dir")
        if mode.startswith("Top"):
            c1, c2, c3, c4 = st.columns([2, 1, 1, 1])
            root = c1.selectbox("Service root", roots, format_func=lambda n: labels[n], key="tree_root")
            depth = c2.slider("Max depth", 1, 15, 6, key="tree_depth")
            only_vuln = c3.checkbox("Only vulnerable branches", False, key="tree_vuln")
            hide_dev = c4.checkbox("Hide dev deps", False, key="tree_dev")
            only = vulnerable_ancestors(g, vmap) | {root} if only_vuln else None
            t = build_tree(g, root, vmap, info, max_depth=depth, only=only, hide_dev=hide_dev)
            top = t["tree"]
            st.caption(f"{top['descendants']} unique packages below this root · {top['vuln_below']} vulnerable · showing {t['shown']} rows"
                       + (" · output truncated, narrow with the filters" if t["truncated"] else "") + " · '↪ shown above' marks a package already expanded elsewhere")
            st.html(tree_html(top, open_levels=1))
        else:
            q = st.text_input("Find package", placeholder="e.g. minimist", key="tree_q")
            pool = [n for n in comps if (q.lower() in labels[n].lower())][:300] if q else sorted(vmap, key=lambda n: -SEV_RANK.get(vmap[n], 0))[:300] or comps[:300]
            if pool:
                pick = st.selectbox("Package", pool, format_func=lambda n: labels[n], key="tree_pick")
                rt_ = build_reverse_tree(g, pick, vmap, info)
                st.caption(f"{rt_['tree']['descendants']} package(s)/roots above it. Read upward: each level is a package that depends on the one beneath.")
                st.html(tree_html(rt_["tree"], open_levels=6, reverse=True))
            else:
                st.info("No packages match.")

    with tab_graph:
        advisories: dict[str, list[str]] = {}
        fixes: dict[str, str] = {}
        for f in vulns:
            for ref in f.get("component_refs") or [f["component_ref"]]:
                advisories.setdefault(ref, []).append(f["primary_id"])
                if f.get("recommended_fix"):
                    fixes.setdefault(ref, f["recommended_fix"])
        payload = _cached_dependency_payload(r["repo"]["scan_id"], g, rel, vmap, advisories, info, fixes)
        render_dependency_graph(payload, 620)

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
        st.markdown(f"**{len(rows)} transitive vulnerability alert(s)**")
        df(rows, height=320)
        st.markdown("**Source packages** (the direct dependencies that bring in the risk)")
        spv = r.get("source_package_view", [])
        df([{"Risk": x["worst_risk"], "Severity": x["worst_severity"] or "n/a", "Source Package": x["source_package"],
             "Itself Vulnerable": "Yes" if x["is_itself_vulnerable"] else "No",
             "Vulnerable packages": x["vulnerable_packages"], "Findings": x["findings"],
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

    download_json("Download Graph JSON", {**gd}, f"{r['repo']['name']}-graph.json", "dl_graph")
