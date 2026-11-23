import json
from pathlib import Path

from app.graph_builder import GRAPH_FORMAT, build_graph


FIXTURE = Path(__file__).parent / "fixtures" / "tiny-sbom.json"


def load_fixture():
    return json.loads(FIXTURE.read_text(encoding="utf-8"))


def test_counts_deduplication_and_distinct_refs():
    graph, validation = build_graph(load_fixture())
    ids = {node["id"] for node in graph["nodes"]}
    assert graph["format"] == GRAPH_FORMAT
    assert {"same-name-instance-1", "same-name-instance-2"} <= ids
    assert graph["stats"]["duplicate_edge_count"] == 1
    assert graph["stats"]["total_edges"] == 7
    assert graph["stats"]["total_edges"] == sum(
        graph["stats"][key]
        for key in ("direct_connections", "transitive_connections", "other_connections")
    )
    assert validation["edge_invariant"] is True


def test_classification_root_leaf_hub_and_unreachable():
    graph, _ = build_graph(load_fixture())
    nodes = {node["id"]: node for node in graph["nodes"]}
    assert graph["root"] == "app@1.0.0"
    assert nodes["direct-a@1"]["direct"] is True
    assert nodes["hub@1"]["transitive"] is True
    assert nodes["hub@1"]["sharedHub"] is True
    assert nodes["same-name-instance-2"]["leaf"] is True
    assert nodes["orphan@1"]["unreachable"] is True
    assert nodes["orphan-leaf@1"]["unreachable"] is True


def test_missing_metadata_preserved_and_unicode_roundtrip(tmp_path):
    graph, reconciliation = build_graph(load_fixture())
    nodes = {node["id"]: node for node in graph["nodes"]}
    assert nodes["missing@3"]["hasComponent"] is False
    assert nodes["missing@3"]["leaf"] is True
    assert nodes["orphan-leaf@1"]["hasComponent"] is False
    assert "missing@3" in reconciliation["unresolved_refs"]
    target = tmp_path / "graph.json"
    target.write_text(json.dumps(graph, ensure_ascii=False), encoding="utf-8")
    assert "Åpp" in target.read_text(encoding="utf-8")


def test_duplicate_component_refs_reported_without_merging_distinct_ids():
    bom = load_fixture()
    bom["components"].append(dict(bom["components"][0]))
    graph, _ = build_graph(bom)
    assert graph["stats"]["duplicate_ref_count"] == 1

