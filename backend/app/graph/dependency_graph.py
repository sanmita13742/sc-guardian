import json
from pathlib import Path
from typing import Dict, Any, List, Set, Optional
import networkx as nx

from app.models.schemas import ComponentInventory, DependencyGraphData, GraphNode, GraphEdge
from app.discovery.manifest_parser import ManifestParser
from app.core.config import GRAPHS_DIR
from app.core.logging import logger


class DependencyGraphBuilder:
    """
    Constructs a directed dependency graph using NetworkX based on actual lockfile
    and manifest relationships, computes graph metrics, and exports React Flow compatible JSON.
    """

    def __init__(self, repo_path: Path):
        self.repo_path = repo_path.resolve()
        self.package_json_path = self.repo_path / "package.json"
        self.package_lock_path = self.repo_path / "package-lock.json"

    def build_graph(self, inventory: ComponentInventory) -> DependencyGraphData:
        """
        Builds directed graph G from inventory and lockfile dependency declarations.
        """
        G = nx.DiGraph()

        root_id = "root"
        root_label = inventory.repository or "NodeGoat"
        G.add_node(
            root_id,
            label=root_label,
            version=inventory.repository_metadata.get("commit_hash", "1.3.0")[:7] if inventory.repository_metadata.get("commit_hash") else "1.3.0",
            dependency_type="root",
            environment="production",
            ecosystem="npm",
            depth=0,
            metadata={"description": "Target Application Root"}
        )

        # Map component by name -> best matching node_id
        # Also map by exact name@version
        name_to_node_ids: Dict[str, List[str]] = {}
        comp_lookup: Dict[str, Any] = {}

        for comp in inventory.components:
            node_id = f"{comp.name}@{comp.version}"
            comp_lookup[node_id] = comp
            name_to_node_ids.setdefault(comp.name, []).append(node_id)

            G.add_node(
                node_id,
                label=comp.name,
                version=comp.version,
                dependency_type=comp.dependency_type,
                environment=comp.environment,
                ecosystem=comp.ecosystem,
                depth=comp.depth,
                metadata={
                    "purl": comp.purl,
                    "license": comp.license,
                    "declared_version": comp.declared_version,
                    "resolved_version": comp.resolved_version,
                    "source": comp.source
                }
            )

        # Connect root to direct dependencies (connecting only to the direct component instances)
        pkg_json = ManifestParser.parse_package_json(self.package_json_path)
        direct_prod = pkg_json.get("dependencies", {})
        direct_dev = pkg_json.get("devDependencies", {})

        for name, constraint in direct_prod.items():
            targets = [tid for tid in name_to_node_ids.get(name, []) if comp_lookup.get(tid) and comp_lookup[tid].dependency_type == "direct"]
            if not targets and name_to_node_ids.get(name):
                targets = [name_to_node_ids[name][0]]
            for target_id in targets:
                edge_id = f"{root_id}->{target_id}"
                G.add_edge(root_id, target_id, id=edge_id, relationship="direct_dependency", version_constraint=constraint)

        for name, constraint in direct_dev.items():
            targets = [tid for tid in name_to_node_ids.get(name, []) if comp_lookup.get(tid) and comp_lookup[tid].dependency_type == "direct"]
            if not targets and name_to_node_ids.get(name):
                targets = [name_to_node_ids[name][0]]
            for target_id in targets:
                edge_id = f"{root_id}->{target_id}"
                G.add_edge(root_id, target_id, id=edge_id, relationship="direct_dev_dependency", version_constraint=constraint)

        # Connect parent packages to child dependencies
        for node_id, comp in comp_lookup.items():
            for child_name, constraint in comp.dependencies.items():
                child_node_ids = name_to_node_ids.get(child_name, [])
                if child_node_ids:
                    # Pick matching child
                    target_child = child_node_ids[0]
                    edge_id = f"{node_id}->{target_child}"
                    if not G.has_edge(node_id, target_child):
                        G.add_edge(
                            node_id,
                            target_child,
                            id=edge_id,
                            relationship="transitive_dependency",
                            version_constraint=constraint
                        )

        # Compute graph metrics
        shared_dependencies = [n for n, in_deg in G.in_degree() if in_deg > 1 and n != root_id]

        # Calculate distances from root
        depths = {}
        try:
            depths = nx.single_source_shortest_path_length(G, root_id)
        except Exception as e:
            logger.debug(f"Path length computation note: {e}")

        nodes_list: List[GraphNode] = []
        for n, attrs in G.nodes(data=True):
            depth_val = depths.get(n, attrs.get("depth", 1))
            in_deg = G.in_degree(n)
            out_deg = G.out_degree(n)

            nodes_list.append(GraphNode(
                id=n,
                label=attrs.get("label", n),
                version=attrs.get("version", ""),
                dependency_type=attrs.get("dependency_type", "transitive"),
                environment=attrs.get("environment", "production"),
                ecosystem=attrs.get("ecosystem", "npm"),
                in_degree=in_deg,
                out_degree=out_deg,
                depth=depth_val,
                metadata=attrs.get("metadata", {})
            ))

        edges_list: List[GraphEdge] = []
        for u, v, data in G.edges(data=True):
            edges_list.append(GraphEdge(
                id=data.get("id", f"{u}->{v}"),
                source=u,
                target=v,
                relationship=data.get("relationship", "depends_on"),
                version_constraint=data.get("version_constraint")
            ))

        summary = {
            "total_nodes": G.number_of_nodes(),
            "total_edges": G.number_of_edges(),
            "direct_dependencies_count": len(direct_prod) + len(direct_dev),
            "shared_dependencies_count": len(shared_dependencies),
            "max_depth": max(depths.values()) if depths else 1,
            "root_id": root_id
        }

        graph_data = DependencyGraphData(
            repository=inventory.repository,
            nodes=nodes_list,
            edges=edges_list,
            summary=summary
        )

        output_file = GRAPHS_DIR / "nodegoat-dependency-graph.json"
        with open(output_file, "w", encoding="utf-8") as f:
            f.write(graph_data.model_dump_json(indent=2))

        logger.info(
            f"Dependency graph built: Nodes={summary['total_nodes']}, Edges={summary['total_edges']}, "
            f"Shared dependencies={summary['shared_dependencies_count']}, Max depth={summary['max_depth']}"
        )
        return graph_data
