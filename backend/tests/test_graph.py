import pytest
from pathlib import Path
from app.discovery.dependency_extractor import DependencyExtractor
from app.graph.dependency_graph import DependencyGraphBuilder

REPO_PATH = Path(__file__).resolve().parent.parent.parent / "nodegoat"


def test_dependency_graph_builder():
    extractor = DependencyExtractor(REPO_PATH)
    inventory = extractor.extract()

    builder = DependencyGraphBuilder(REPO_PATH)
    graph_data = builder.build_graph(inventory)

    assert graph_data.repository == "nodegoat"
    # Root node + 1091 components = 1092 nodes
    assert graph_data.summary["total_nodes"] == 1092
    assert graph_data.summary["total_edges"] > 1000
    assert graph_data.summary["direct_dependencies_count"] == 36
    assert graph_data.summary["shared_dependencies_count"] > 0
    assert graph_data.summary["max_depth"] >= 2

    # Check root node presence
    node_ids = {n.id for n in graph_data.nodes}
    assert "root" in node_ids

    # Check that root has direct edges
    root_edges = [e for e in graph_data.edges if e.source == "root"]
    assert len(root_edges) == 36


def test_shared_transitive_dependencies():
    extractor = DependencyExtractor(REPO_PATH)
    inventory = extractor.extract()

    builder = DependencyGraphBuilder(REPO_PATH)
    graph_data = builder.build_graph(inventory)

    # In-degree > 1 means multiple packages depend on this component
    shared_nodes = [n for n in graph_data.nodes if n.in_degree > 1 and n.id != "root"]
    assert len(shared_nodes) > 100
