from fastapi import APIRouter, HTTPException, UploadFile, File
from pathlib import Path
from typing import List, Dict, Any

from app.models.schemas import RepositoryMetadata
from app.discovery.repository_loader import RepositoryLoader
from app.core.config import TARGET_REPO_DEFAULT, BASE_DIR
from app.core.logging import logger

router = APIRouter(prefix="/api/repositories", tags=["Repositories"])


@router.get("", response_model=List[RepositoryMetadata])
def list_repositories():
    """
    Lists known target repositories.
    """
    repos = []
    # Check default nodegoat
    if TARGET_REPO_DEFAULT.exists():
        try:
            meta = RepositoryLoader.inspect(TARGET_REPO_DEFAULT)
            repos.append(meta)
        except Exception as e:
            logger.error(f"Failed to inspect default target: {e}")

    return repos


@router.post("", response_model=RepositoryMetadata)
def register_repository(payload: Dict[str, str]):
    """
    Registers a local repository path for analysis.
    """
    repo_path_str = payload.get("path")
    if not repo_path_str:
        raise HTTPException(status_code=400, detail="Missing 'path' parameter.")

    p = Path(repo_path_str)
    if not p.is_absolute():
        p = BASE_DIR / p

    if not p.exists() or not p.is_dir():
        raise HTTPException(status_code=404, detail=f"Directory not found: {p}")

    meta = RepositoryLoader.inspect(p)
    return meta
