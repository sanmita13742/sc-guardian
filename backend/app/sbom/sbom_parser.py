import json
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple

from app.models.schemas import ComponentInventory, SBOMComparison
from app.core.config import SBOM_DIR
from app.core.logging import logger


class SBOMParser:
    """
    Parses and validates CycloneDX SBOM JSON and cross-references its components
    against the normalized ComponentInventory to surface discrepancies.
    """

    @staticmethod
    def validate_cyclonedx(sbom_data: Dict[str, Any]) -> Tuple[bool, str]:
        """
        Validates basic CycloneDX structural requirements.
        """
        bom_format = sbom_data.get("bomFormat")
        spec_version = sbom_data.get("specVersion")

        if bom_format != "CycloneDX":
            return False, f"Invalid bomFormat: expected 'CycloneDX', got '{bom_format}'"

        if not spec_version:
            return False, "Missing specVersion in CycloneDX SBOM"

        if "components" not in sbom_data and "metadata" not in sbom_data:
            return False, "Malformed CycloneDX: neither 'components' nor 'metadata' present"

        return True, "Valid CycloneDX structure"

    @classmethod
    def compare_with_inventory(
        cls,
        sbom_data: Dict[str, Any],
        inventory: ComponentInventory,
        syft_version: Optional[str] = None
    ) -> SBOMComparison:
        """
        Cross-validates Syft CycloneDX components against ComponentInventory.
        """
        is_valid, validation_msg = cls.validate_cyclonedx(sbom_data)
        if not is_valid:
            return SBOMComparison(
                sbom_format=str(sbom_data.get("bomFormat")),
                syft_version=syft_version,
                generated_timestamp=sbom_data.get("metadata", {}).get("timestamp", ""),
                total_sbom_components=0,
                total_inventory_components=inventory.total_components,
                matched_components=0,
                validation_status=f"invalid: {validation_msg}"
            )

        sbom_components = sbom_data.get("components", [])
        sbom_map: Dict[str, str] = {}
        for c in sbom_components:
            name = c.get("name")
            ver = c.get("version", "")
            if name:
                sbom_map[name] = ver

        inv_map: Dict[str, str] = {c.name: c.version for c in inventory.components}

        common_names = set(sbom_map.keys()) & set(inv_map.keys())
        only_sbom = sorted(list(set(sbom_map.keys()) - set(inv_map.keys())))
        only_inv = sorted(list(set(inv_map.keys()) - set(sbom_map.keys())))

        version_mismatches = []
        for name in common_names:
            if sbom_map[name] != inv_map[name]:
                version_mismatches.append({
                    "package": name,
                    "sbom_version": sbom_map[name],
                    "inventory_version": inv_map[name]
                })

        comparison = SBOMComparison(
            sbom_format=f"CycloneDX {sbom_data.get('specVersion')}",
            syft_version=syft_version,
            generated_timestamp=sbom_data.get("metadata", {}).get("timestamp", ""),
            total_sbom_components=len(sbom_components),
            total_inventory_components=inventory.total_components,
            matched_components=len(common_names),
            only_in_sbom=only_sbom,
            only_in_inventory=only_inv,
            version_mismatches=version_mismatches,
            validation_status="valid_with_discrepancies" if (only_sbom or only_inv) else "valid"
        )

        comparison_file = SBOM_DIR / "nodegoat-sbom-comparison.json"
        with open(comparison_file, "w", encoding="utf-8") as f:
            f.write(comparison.model_dump_json(indent=2))

        logger.info(
            f"SBOM comparison saved to {comparison_file}: "
            f"SBOM count={len(sbom_components)}, Inventory count={inventory.total_components}, "
            f"Matched={len(common_names)}, OnlyInSBOM={len(only_sbom)}, OnlyInInv={len(only_inv)}"
        )
        return comparison


