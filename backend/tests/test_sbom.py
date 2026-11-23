import pytest
from pathlib import Path
from app.discovery.dependency_extractor import DependencyExtractor
from app.sbom.sbom_generator import SBOMGenerator
from app.sbom.sbom_parser import SBOMParser

REPO_PATH = Path(__file__).resolve().parent.parent.parent / "nodegoat"


def test_sbom_generation_and_validation():
    generator = SBOMGenerator()
    sbom_path, sbom_data = generator.generate(REPO_PATH, output_filename="test-nodegoat-sbom.json")

    assert sbom_path.exists()
    assert sbom_path.stat().st_size > 0

    # Validate CycloneDX structure
    is_valid, msg = SBOMParser.validate_cyclonedx(sbom_data)
    assert is_valid, f"CycloneDX validation failed: {msg}"
    assert sbom_data.get("bomFormat") == "CycloneDX"
    assert len(sbom_data.get("components", [])) > 0


def test_sbom_comparison():
    extractor = DependencyExtractor(REPO_PATH)
    inventory = extractor.extract()

    generator = SBOMGenerator()
    _, sbom_data = generator.generate(REPO_PATH, output_filename="test-nodegoat-sbom.json")

    comparison = SBOMParser.compare_with_inventory(
        sbom_data,
        inventory,
        syft_version=generator.get_syft_version()
    )

    assert comparison.matched_components > 0
    assert comparison.total_sbom_components > 0
    assert comparison.total_inventory_components == inventory.total_components
    assert comparison.validation_status.startswith("valid")
