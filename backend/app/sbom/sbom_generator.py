import datetime
import json
import os
import shutil
import subprocess
from pathlib import Path
from typing import Dict, Any, Optional, Tuple

from app.core.config import SBOM_DIR
from app.core.logging import logger

SYFT_DEFAULT_PATH = r"C:\Users\yeshx\AppData\Local\Microsoft\WinGet\Packages\Anchore.Syft_Microsoft.Winget.Source_8wekyb3d8bbwe\syft.exe"


class SBOMGenerator:
    """
    Executes Syft to generate a standardized CycloneDX JSON SBOM.
    """

    def __init__(self, syft_bin: Optional[str] = None):
        self.syft_bin = syft_bin or shutil.which("syft") or (SYFT_DEFAULT_PATH if Path(SYFT_DEFAULT_PATH).exists() else "syft")

    def get_syft_version(self) -> Optional[str]:
        """
        Retrieves the installed Syft version.
        """
        try:
            res = subprocess.run(
                [self.syft_bin, "version"],
                capture_output=True,
                text=True,
                check=False
            )
            if res.returncode == 0:
                for line in res.stdout.splitlines():
                    if "Version:" in line:
                        return line.split("Version:")[-1].strip()
                return res.stdout.strip()
        except Exception as e:
            logger.warning(f"Failed to get Syft version: {e}")
        return None

    def generate(self, repo_path: Path, output_filename: str = "nodegoat-sbom.json") -> Tuple[Path, Dict[str, Any]]:
        """
        Runs Syft against the target directory and outputs CycloneDX JSON.
        """
        repo_path = repo_path.resolve()
        output_path = SBOM_DIR / output_filename

        syft_version = self.get_syft_version()
        logger.info(f"Generating SBOM using Syft (version: {syft_version}) for {repo_path}")

        cmd = [
            self.syft_bin,
            "scan",
            f"dir:{repo_path}",
            "-o",
            f"cyclonedx-json={output_path}"
        ]

        try:
            res = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                check=False
            )
            if res.returncode != 0:
                logger.error(f"Syft execution failed (code {res.returncode}): {res.stderr}")
                raise RuntimeError(f"Syft failed: {res.stderr}")

            if not output_path.exists() or output_path.stat().st_size == 0:
                raise RuntimeError("Syft completed but SBOM output file is missing or empty.")

            with open(output_path, "r", encoding="utf-8") as f:
                sbom_data = json.load(f)

            logger.info(f"Successfully generated CycloneDX SBOM at {output_path} ({len(sbom_data.get('components', []))} components)")
            return output_path, sbom_data
        except Exception as e:
            logger.error(f"Error during SBOM generation: {e}")
            raise
