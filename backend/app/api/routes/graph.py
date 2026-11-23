import json
from fastapi import APIRouter, HTTPException
from pathlib import Path

from app.models.schemas import DependencyGraphData
from app.graph.dependency_graph import DependencyGraphBuilder
from app.api.routes.discovery import resolve_repo, get_dependencies
from app.core.config import GRAPHS_DIR
from app.core.logging import logger

router = APIRouter(prefix="/api/graph", tags=["Dependency Graph"])


@router.get("/{repo_id}", response_model=DependencyGraphData)
def get_graph(repo_id: str):
    """
    Retrieves or constructs the directed dependency graph.
    """
    repo_path = resolve_repo(repo_id)
    graph_file = GRAPHS_DIR / "nodegoat-dependency-graph.json"

    if graph_file.exists():
        try:
            with open(graph_file, "r", encoding="utf-8") as f:
                data = json.load(f)
            return DependencyGraphData(**data)
        except Exception as e:
            logger.warning(f"Failed to read cached graph: {e}")

    # Generate graph
    try:
        inventory = get_dependencies(repo_id)
        builder = DependencyGraphBuilder(repo_path)
        graph_data = builder.build_graph(inventory)
        return graph_data
    except Exception as e:
        logger.error(f"Graph construction error: {e}")
        raise HTTPException(status_code=500, detail=str(e))
