import json
from pathlib import Path
from typing import Dict, Any, Optional

from app.core.logging import logger


class ManifestParser:
    """
    Parses manifest files (package.json) and lockfiles (package-lock.json).
    """

    @staticmethod
    def parse_package_json(file_path: Path) -> Dict[str, Any]:
        """
        Parses package.json and extracts declared metadata, dependencies, scripts.
        """
        if not file_path.exists():
            raise FileNotFoundError(f"Manifest not found: {file_path}")

        try:
            with open(file_path, "r", encoding="utf-8") as f:
                data = json.load(f)

            return {
                "name": data.get("name", "unknown"),
                "version": data.get("version", "0.0.0"),
                "description": data.get("description", ""),
                "main": data.get("main", ""),
                "dependencies": data.get("dependencies", {}),
                "devDependencies": data.get("devDependencies", {}),
                "optionalDependencies": data.get("optionalDependencies", {}),
                "peerDependencies": data.get("peerDependencies", {}),
                "scripts": data.get("scripts", {}),
                "license": data.get("license", ""),
                "raw": data
            }
        except json.JSONDecodeError as e:
            logger.error(f"Failed to decode JSON from {file_path}: {e}")
            raise ValueError(f"Invalid package.json format: {e}")

    @staticmethod
    def parse_package_lock_json(file_path: Path) -> Dict[str, Any]:
        """
        Parses package-lock.json and normalizes lockfile format (v1, v2, v3).
        """
        if not file_path.exists():
            raise FileNotFoundError(f"Lockfile not found: {file_path}")

        try:
            with open(file_path, "r", encoding="utf-8") as f:
                data = json.load(f)

            lockfile_version = data.get("lockfileVersion", 1)
            return {
                "name": data.get("name", "unknown"),
                "version": data.get("version", "0.0.0"),
                "lockfileVersion": lockfile_version,
                "packages": data.get("packages", {}),
                "dependencies": data.get("dependencies", {}),
                "raw": data
            }
        except json.JSONDecodeError as e:
            logger.error(f"Failed to decode JSON from {file_path}: {e}")
            raise ValueError(f"Invalid package-lock.json format: {e}")
