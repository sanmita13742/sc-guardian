import json
from fastapi import APIRouter, HTTPException, Query
from fastapi.responses import JSONResponse
from pathlib import Path
from typing import Optional

from app.models.schemas import SBOMComparison
from app.sbom.sbom_generator import SBOMGenerator
from app.sbom.sbom_parser import SBOMParser
from app.api.routes.discovery import resolve_repo, get_dependencies
from app.core.config import SBOM_DIR
from app.core.logging import logger

router = APIRouter(prefix="/api/sbom", tags=["SBOM"])


@router.post("/{repo_id}")
def generate_sbom(repo_id: str):
    """
    Generates CycloneDX SBOM with Syft and computes comparison with inventory.
    """
    repo_path = resolve_repo(repo_id)
    try:
        inventory = get_dependencies(repo_id)
        generator = SBOMGenerator()
        output_path, sbom_data = generator.generate(repo_path)
        comparison = SBOMParser.compare_with_inventory(
            sbom_data,
            inventory,
            syft_version=generator.get_syft_version()
        )
        return {
            "status": "success",
            "sbom_path": str(output_path),
            "comparison": comparison
        }
    except Exception as e:
        logger.error(f"SBOM generation error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/{repo_id}")
def get_sbom(repo_id: str, format: Optional[str] = Query("raw", description="raw or comparison")):
    """
    Retrieves the CycloneDX SBOM or comparison analysis.
    """
    if format == "comparison":
        comp_file = SBOM_DIR / "nodegoat-sbom-comparison.json"
        if comp_file.exists():
            with open(comp_file, "r", encoding="utf-8") as f:
                return json.load(f)
        raise HTTPException(status_code=404, detail="SBOM comparison report not found. Run POST /api/sbom/{repo_id} first.")

    sbom_file = SBOM_DIR / "nodegoat-sbom.json"
    if sbom_file.exists():
        with open(sbom_file, "r", encoding="utf-8") as f:
            return json.load(f)

    # Generate if not exists
    res = generate_sbom(repo_id)
    with open(sbom_file, "r", encoding="utf-8") as f:
        return json.load(f)
