import json
from fastapi import APIRouter, HTTPException
from pathlib import Path

from app.models.schemas import ComponentInventory
from app.discovery.repository_loader import RepositoryLoader
from app.discovery.dependency_extractor import DependencyExtractor
from app.core.config import TARGET_REPO_DEFAULT, DISCOVERY_DIR, BASE_DIR
from app.core.logging import logger

router = APIRouter(tags=["Discovery & Dependencies"])


def resolve_repo(repo_id: str) -> Path:
    if repo_id.lower() in ("nodegoat", "owasp-nodejs-goat", "default"):
        return TARGET_REPO_DEFAULT
    custom_path = BASE_DIR / repo_id
    if custom_path.exists():
        return custom_path
    raise HTTPException(status_code=404, detail=f"Repository '{repo_id}' not found.")


@router.post("/api/discovery/{repo_id}", response_model=ComponentInventory)
def discover_dependencies(repo_id: str):
    """
    Executes repository inspection and dependency extraction.
    """
    repo_path = resolve_repo(repo_id)
    try:
        metadata = RepositoryLoader.inspect(repo_path)
        extractor = DependencyExtractor(repo_path)
        inventory = extractor.extract(metadata)
        return inventory
    except Exception as e:
        logger.error(f"Discovery error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/api/dependencies/{repo_id}", response_model=ComponentInventory)
def get_dependencies(repo_id: str):
    """
    Retrieves the extracted component inventory.
    """
    output_file = DISCOVERY_DIR / "component-inventory.json"
    if output_file.exists():
        try:
            with open(output_file, "r", encoding="utf-8") as f:
                data = json.load(f)
            return ComponentInventory(**data)
        except Exception as e:
            logger.error(f"Failed to read inventory cache: {e}")

    # Fallback to computing on the fly
    return discover_dependencies(repo_id)
