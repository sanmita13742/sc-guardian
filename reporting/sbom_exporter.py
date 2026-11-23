"""SBOM artifacts: the original Syft CycloneDX file is preserved byte-for-byte; enrichment is a separate derived file."""
from __future__ import annotations

import json
import shutil
from pathlib import Path
from typing import Optional


def preserve_original(src: str | Path, dest_dir: Path, name: str) -> Path:
    dest_dir.mkdir(parents=True, exist_ok=True)
    dest = dest_dir / name
    if Path(src).resolve() != dest.resolve():
        shutil.copyfile(src, dest)
    return dest


def derived_enriched_sbom(original: dict, components: list[dict]) -> dict:
    """Overlay of enriched fields (license/supplier) with provenance. The original document is NOT modified."""
    enriched = {c["bom_ref"]: c["enriched"] for c in components if c.get("enriched")}
    return {"derivedFrom": "original Syft CycloneDX SBOM (unmodified copy stored alongside)",
            "note": "Only fields that were empty in the original were filled; each entry records its source URL.",
            "enrichedComponents": [{"bom-ref": r, "fields": f} for r, f in enriched.items()]}


def read_text(path: Optional[str]) -> Optional[str]:
    if not path or not Path(path).exists():
        return None
    return Path(path).read_text(encoding="utf-8")
