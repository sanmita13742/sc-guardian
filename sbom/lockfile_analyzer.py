"""Dispatch manifest/lockfile text to ecosystem parsers. Parser failures are recorded, never raised."""
from __future__ import annotations

import os
from pathlib import Path
from typing import Callable, Optional

from core.models import InspectionResult, LockDependency
from core.repository_inspector import safe_read_text
from sbom.package_extractors import npm, others, python

SIBLINGS = {
    "package-lock.json": {"package_json": "package.json"},
    "npm-shrinkwrap.json": {"package_json": "package.json"},
    "yarn.lock": {"package_json": "package.json"},
    "pnpm-lock.yaml": {"package_json": "package.json"},
    "poetry.lock": {"pyproject": "pyproject.toml"},
    "composer.lock": {"composer_json": "composer.json"},
}

PARSERS: dict[str, Callable] = {
    "package-lock.json": npm.parse_package_lock,
    "npm-shrinkwrap.json": npm.parse_package_lock,
    "yarn.lock": npm.parse_yarn_lock,
    "pnpm-lock.yaml": npm.parse_pnpm_lock,
    "poetry.lock": python.parse_poetry_lock,
    "uv.lock": python.parse_uv_lock,
    "Pipfile.lock": python.parse_pipfile_lock,
    "go.mod": others.parse_go_mod,
    "go.sum": others.parse_go_sum,
    "Cargo.lock": others.parse_cargo_lock,
    "composer.lock": others.parse_composer_lock,
    "packages.lock.json": others.parse_nuget_lock,
    "pom.xml": others.parse_pom,
    "build.gradle": others.parse_gradle,
    "build.gradle.kts": others.parse_gradle,
    "gradle.lockfile": others.parse_gradle_lockfile,
}


def parser_for(name: str) -> Optional[Callable]:
    if name in PARSERS:
        return PARSERS[name]
    if name.startswith("requirements") and name.endswith(".txt"):
        return python.parse_requirements
    if name.endswith((".csproj", ".fsproj", ".vbproj")):
        return others.parse_csproj
    return None


def supported_files() -> list[str]:
    return sorted(PARSERS) + ["requirements*.txt", "*.csproj"]


def parse_text(name: str, text: str, path: str, service_dir: str,
               sibling_texts: Optional[dict[str, Optional[str]]] = None) -> list[LockDependency]:
    fn = parser_for(name)
    if fn is None:
        return []
    return fn(text, path, service_dir, **(sibling_texts or {}))


def analyze_repository(root: Path, inspection: InspectionResult) -> tuple[list[LockDependency], list[dict]]:
    """Parse every discovered manifest/lockfile. Returns (dependencies, errors)."""
    deps: list[LockDependency] = []
    errors: list[dict] = []
    for mf in inspection.manifests:
        fn = parser_for(mf.name)
        if fn is None:
            if mf.name not in ("package.json", "pyproject.toml", "Cargo.toml", "composer.json", "setup.py", "Pipfile", "Gemfile", "Gemfile.lock"):
                errors.append({"file": mf.path, "error": "no parser available for this file type"})
            continue
        text = safe_read_text(root, mf.path)
        if text is None:
            errors.append({"file": mf.path, "error": "file unreadable, a symlink or over the size limit"})
            continue
        sib = {}
        for kw, sib_name in SIBLINGS.get(mf.name, {}).items():
            rel = mf.path.rsplit("/", 1)[0] + "/" + sib_name if "/" in mf.path else sib_name
            sib[kw] = safe_read_text(root, rel)
        try:
            deps.extend(fn(text, mf.path, mf.service_dir, **sib))
        except Exception as e:  # malformed file must never crash the scan
            errors.append({"file": mf.path, "error": f"{type(e).__name__}: {str(e)[:200]}"})
    return deps, errors
