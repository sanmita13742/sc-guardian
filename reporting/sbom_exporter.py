"""SBOM artifact helpers: raw scanner files are preserved byte-for-byte; the fused document is a separate file."""
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


def read_text(path: Optional[str]) -> Optional[str]:
    if not path or not Path(path).exists():
        return None
    return Path(path).read_text(encoding="utf-8")
