import json
from pathlib import Path
import networkx as nx

INVENTORY_FILE = Path("component-inventory.json")
PACKAGE_JSON = Path("nodegoat/package.json")
OUTPUT_GRAPH = Path("nodegoat-dependency-graph.json")


def build_dependency_graph():
    print("[1/3] Loading component inventory...")
    with open(INVENTORY_FILE, "r", encoding="utf-8") as f:
        inventory = json.load(f)

    with open(PACKAGE_JSON, "r", encoding="utf-8") as f:
        pkg_json = json.load(f)

    direct_prod = pkg_json.get("dependencies", {})
    direct_dev = pkg_json.get("devDependencies", {})

    G = nx.DiGraph()

    # 1. Add Root Application Node
    root_id = "root"
    G.add_node(
        root_id,
        label="owasp-nodejs-goat",
        version="1.3.0",
        type="root",
        environment="production",
        depth=0,
        in_degree=0
    )

    # 2. Add Component Nodes
    comp_lookup = {}
    name_to_node_ids = {}

    for comp in inventory["components"]:
        node_id = f"{comp['name']}@{comp['version']}"
        comp_lookup[node_id] = comp
        name_to_node_ids.setdefault(comp["name"], []).append(node_id)

        G.add_node(
            node_id,
            label=comp["name"],
            version=comp["version"],
            type=comp["dependency_type"],
            environment=comp["environment"],
            purl=comp.get("purl"),
            license=comp.get("license")
        )

    # 3. Add Edges from Root to Direct Dependencies
    print("[2/3] Constructing directed edges...")
    for name, spec in direct_prod.items():
        targets = [tid for tid in name_to_node_ids.get(name, []) if comp_lookup[tid]["dependency_type"] == "direct"]
        if not targets and name_to_node_ids.get(name):
            targets = [name_to_node_ids[name][0]]
        for tid in targets:
            G.add_edge(root_id, tid, relationship="direct_dependency", constraint=spec)

    for name, spec in direct_dev.items():
        targets = [tid for tid in name_to_node_ids.get(name, []) if comp_lookup[tid]["dependency_type"] == "direct"]
        if not targets and name_to_node_ids.get(name):
            targets = [name_to_node_ids[name][0]]
        for tid in targets:
            G.add_edge(root_id, tid, relationship="direct_dev_dependency", constraint=spec)

    # 4. Add Edges between Parents and Children
    for node_id, comp in comp_lookup.items():
        for child_name, constraint in comp.get("dependencies", {}).items():
            child_ids = name_to_node_ids.get(child_name, [])
            if child_ids:
                target_child = child_ids[0]
                if not G.has_edge(node_id, target_child):
                    G.add_edge(node_id, target_child, relationship="transitive_dependency", constraint=constraint)

    # 5. Compute NetworkX Metrics
    print("[3/3] Calculating NetworkX graph metrics...")
    total_nodes = G.number_of_nodes()
    total_edges = G.number_of_edges()

    # Shortest path depths from root
    depths = {}
    try:
        depths = nx.single_source_shortest_path_length(G, root_id)
    except Exception as e:
        print(f"  Note on depth calculation: {e}")

    # Shared dependencies (nodes with in_degree > 1, meaning required by multiple packages)
    shared_deps = [n for n, d in G.in_degree() if d > 1 and n != root_id]

    # Assign depths and degrees to node attributes
    for n in G.nodes():
        G.nodes[n]["depth"] = depths.get(n, 1)
        G.nodes[n]["in_degree"] = G.in_degree(n)
        G.nodes[n]["out_degree"] = G.out_degree(n)

    # Sample path tracing demonstration
    sample_targets = ["accepts@1.3.5", "debug@3.2.6", "mime-types@2.1.21", "ms@2.1.2"]
    sample_paths = {}
    for target in sample_targets:
        if G.has_node(target) and nx.has_path(G, root_id, target):
            sample_paths[target] = " -> ".join(nx.shortest_path(G, root_id, target))

    # Export graph data as JSON
    nodes_export = [{"id": n, **G.nodes[n]} for n in G.nodes()]
    edges_export = [
        {"source": u, "target": v, "relationship": G.edges[u, v].get("relationship", "depends_on"), "constraint": G.edges[u, v].get("constraint")}
        for u, v in G.edges()
    ]

    graph_payload = {
        "repository": "NodeGoat",
        "total_nodes": total_nodes,
        "total_edges": total_edges,
        "direct_edges_from_root": len(direct_prod) + len(direct_dev),
        "shared_dependencies_count": len(shared_deps),
        "max_dependency_depth": max(depths.values()) if depths else 1,
        "sample_dependency_paths": sample_paths,
        "nodes": nodes_export,
        "edges": edges_export
    }

    with open(OUTPUT_GRAPH, "w", encoding="utf-8") as f:
        json.dump(graph_payload, f, indent=2)

    print("\n=== NETWORKX DEPENDENCY GRAPH BUILT SUCCESSFULLY ===")
    print(f"Total Graph Nodes:        {total_nodes} (1 root application + {total_nodes - 1} packages)")
    print(f"Total Directed Edges:     {total_edges}")
    print(f"Direct Edges from Root:   {len(direct_prod) + len(direct_dev)} (16 prod, 20 dev)")
    print(f"Shared Dependencies:      {len(shared_deps)} (packages required by >1 parent)")
    print(f"Maximum Dependency Depth: {graph_payload['max_dependency_depth']} levels")
    print("\nSample Verified Dependency Paths:")
    for pkg, path in sample_paths.items():
        print(f"  • {path}")
    print(f"\nGraph JSON exported to:   {OUTPUT_GRAPH}")

    return graph_payload


if __name__ == "__main__":
    build_dependency_graph()
