import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent.parent.parent
TARGET_REPO_DEFAULT = BASE_DIR / "nodegoat"
ARTIFACTS_DIR = BASE_DIR / "artifacts"
SBOM_DIR = ARTIFACTS_DIR / "sbom"
DISCOVERY_DIR = ARTIFACTS_DIR / "discovery"
GRAPHS_DIR = ARTIFACTS_DIR / "graphs"
SCANS_DIR = ARTIFACTS_DIR / "scans"
REPORTS_DIR = ARTIFACTS_DIR / "reports"

for dir_path in [ARTIFACTS_DIR, SBOM_DIR, DISCOVERY_DIR, GRAPHS_DIR, SCANS_DIR, REPORTS_DIR]:
    dir_path.mkdir(parents=True, exist_ok=True)
