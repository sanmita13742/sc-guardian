from pathlib import Path

import networkx as nx
import pytest

from core.models import Component, LockDependency
from graph.dependency_tracer import classify_all, trace_component
from graph.graph_builder import build_graph, root_id
from graph.graph_exporter import graph_to_json, subgraph_for, to_cytoscape
from graph.graph_validator import validate_graph
from graph.impact_analyzer import impact_of


def C(ref, name, svc, ver="1.0.0"):
    return Component(bom_ref=ref, name=name, version=ver, ecosystem="npm", purl=f"pkg:npm/{name}@{ver}", service_dir=svc)


def L(name, svc, direct, ver="1.0.0", requires=()):
    return LockDependency(name=name, version=ver, ecosystem="npm", direct=direct, lockfile=f"{svc}/package-lock.json",
                          service_dir=svc, requires=list(requires))


def scenario():
    """svcA: app -> A -> B(vuln);  svcB: app -> B (direct) and app -> A2 -> B2 -> B (diamond)."""
    comps = [C("A", "pkga", "svcA"), C("B", "pkgb", "svcA"), C("B_b", "pkgb", "svcB"), C("X", "pkgx", "svcB"),
             C("Y", "pkgy", "svcB")]
    sbom = {"metadata": {"component": {"bom-ref": "meta"}}, "dependencies": [
        {"ref": "A", "dependsOn": ["B"]},
        {"ref": "X", "dependsOn": ["B_b", "Y"]},
        {"ref": "Y", "dependsOn": ["B_b"]},
    ]}
    locks = [L("pkga", "svcA", True), L("pkgb", "svcA", False), L("pkgb", "svcB", True), L("pkgx", "svcB", True),
             L("pkgy", "svcB", False)]
    return comps, sbom, locks


def test_roots_directness_and_paths():
    comps, sbom, locks = scenario()
    g, info = build_graph(sbom, comps, locks, ["svcA", "svcB"])
    assert root_id("svcA") in g and root_id("svcB") in g
    cls = classify_all(g)
    assert cls["A"] == {root_id("svcA"): "direct"}
    assert cls["B"] == {root_id("svcA"): "transitive"}
    # B_b is a direct dep of svcB AND reachable transitively through X and Y: per-root answer is 'direct'
    assert cls["B_b"] == {root_id("svcB"): "direct"}
    t = trace_component(g, "B_b")
    assert len(t["roots"]) == 1 and t["roots"][0]["relationship"] == "direct"
    paths = t["roots"][0]["paths"]
    assert len(paths) == 3  # direct, via X, via X->Y (multiple dependency paths preserved)
    assert paths[0][-1].startswith("pkgb")
    assert sorted(t["immediate_parents"]) == ["pkgx@1.0.0", "pkgy@1.0.0"]
    tb = trace_component(g, "B")
    assert tb["roots"][0]["paths"] == [["svcA (service)", "pkga@1.0.0", "pkgb@1.0.0"]]
    assert tb["roots"][0]["immediate_parents"] == ["pkga@1.0.0"]


def test_same_package_direct_in_one_root_transitive_in_another():
    """A shared bom-ref required directly by one root and transitively by another is reported per root."""
    comps = [C("S", "shared", "."), C("P", "parent", "."), C("Q", "other", "pkgs/q")]
    sbom = {"dependencies": [{"ref": "P", "dependsOn": ["S"]}]}
    locks = [L("shared", ".", True), L("parent", ".", True)]
    g, _ = build_graph(sbom, comps, locks, [".", "pkgs/q"])
    g.add_edge(root_id("pkgs/q"), "P", provenance="lockfile-direct")  # second root also depends on P
    t = trace_component(g, "S")
    rels = {r["root"]: r["relationship"] for r in t["roots"]}
    assert rels[root_id(".")] == "direct"
    assert rels[root_id("pkgs/q")] == "transitive"
    imp = impact_of(g, "S")
    assert imp["root_count"] == 2 and len(imp["direct_roots"]) == 1 and len(imp["transitive_roots"]) == 1


def test_inferred_edges_flagged():
    comps = [C("A", "a", "."), C("B", "b", ".")]
    g, info = build_graph({"dependencies": []}, comps, [], ["."])
    assert info["inferred_edges"] == 2
    assert classify_all(g)["A"][root_id(".")] == "direct_inferred"
    v = validate_graph(g, info)
    assert any("inferred" in w for w in v["warnings"])


def test_lockfile_edges_fill_missing_sbom_relationships():
    comps = [C("A", "a", "."), C("B", "b", ".")]
    locks = [L("a", ".", True, requires=["b"]), L("b", ".", False)]
    g, info = build_graph({"dependencies": []}, comps, locks, ["."])
    assert g.edges["A", "B"]["provenance"].startswith("lockfile:")
    assert classify_all(g)["B"][root_id(".")] == "transitive"
    assert info["lockfile_edges"] == 1


def test_malformed_dangling_cycle_and_duplicates_handled():
    comps = [C("A", "a", "."), C("B", "b", "."), C("A", "a-dup", ".")]
    sbom = {"dependencies": [
        {"ref": "A", "dependsOn": ["B", "ghost", 7]},
        {"ref": "B", "dependsOn": ["A", "B"]},
        {"ref": "nobody", "dependsOn": ["A"]},
        "garbage", {"ref": 5}, {"ref": "A", "dependsOn": "notalist"},
    ]}
    g, info = build_graph(sbom, comps, [L("a", ".", True)], ["."])
    v = validate_graph(g, info)
    assert "ghost" in v["dangling_refs"] and "nobody" in v["dangling_refs"]
    assert v["duplicate_refs"] == ["A"] and v["self_loops"] == ["B"]
    assert len(v["malformed"]) >= 3
    assert not v["is_acyclic"] and v["cycle_groups"]
    # tracing in a cyclic graph terminates
    t = trace_component(g, "B")
    assert t["roots"] and t["roots"][0]["depth"] >= 1


def test_trace_unknown_and_path_cap():
    g = nx.DiGraph()
    g.add_node("root:.", kind="root", label="r")
    for i in range(6):
        g.add_node(f"m{i}", kind="component", label=f"m{i}")
        g.add_edge("root:.", f"m{i}")
        g.add_edge(f"m{i}", "t")
    g.add_node("t", kind="component", label="t")
    assert trace_component(g, "zzz")["found"] is False
    t = trace_component(g, "t", max_paths=3)
    assert len(t["roots"][0]["paths"]) == 3 and t["roots"][0]["truncated"] is True


def test_export_and_views():
    comps, sbom, locks = scenario()
    g, info = build_graph(sbom, comps, locks, ["svcA", "svcB"])
    j = graph_to_json(g, validate_graph(g, info))
    assert j["directed"] and j["edges"] and j["nodes"][0]["id"]
    ov = subgraph_for(g, "overview")
    assert "B" not in ov  # overview shows roots + direct deps only
    vs = subgraph_for(g, "vulnerable", focus=["B"])
    assert {"B", "A", root_id("svcA")} <= set(vs.nodes)
    capped = subgraph_for(g, "neighborhood", focus=["B_b"], depth=3, max_nodes=3)
    assert len(capped) <= 3
    els = to_cytoscape(g, {"B": "HIGH"}, classify_all(g))
    assert any(e["data"].get("vuln") == "HIGH" for e in els)


@pytest.mark.syft
def test_real_syft_graph_for_monorepo(tmp_path):
    from core.repository_inspector import inspect_repository
    from sbom.cyclonedx_validator import load_sbom, normalize_components
    from sbom.lockfile_analyzer import analyze_repository
    from sbom.syft_runner import resolve_syft, run_syft
    if not resolve_syft():
        pytest.skip("syft missing")
    root = Path(__file__).resolve().parent.parent / "fixtures" / "monorepo"
    r = run_syft(root, tmp_path / "s.json")
    assert r.ok, r.error
    insp = inspect_repository(root)
    svcs = [s["dir"] for s in insp.services]
    doc = load_sbom(r.sbom_path)
    comps = normalize_components(doc, root, svcs)
    deps, _ = analyze_repository(root, insp)
    g, info = build_graph(doc, comps, deps, svcs, "monorepo")
    cls = classify_all(g)
    ref = next(n for n, a in g.nodes(data=True) if a.get("name") == "minimist")
    assert cls[ref] == {root_id("frontend"): "transitive"}
    t = trace_component(g, ref)
    assert t["roots"][0]["paths"][0] == ["frontend (service)", "mkdirp@0.5.1", "minimist@0.0.8"]
    flask = next(n for n, a in g.nodes(data=True) if a.get("name") == "flask")
    assert cls[flask][root_id("backend")].startswith("direct")
    assert [r["root"] for r in trace_component(g, flask)["roots"]] == [root_id("backend")]  # no frontend<->backend edges
