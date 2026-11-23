import pytest
from pathlib import Path
from app.discovery.repository_loader import RepositoryLoader
from app.discovery.manifest_parser import ManifestParser
from app.discovery.dependency_extractor import DependencyExtractor

REPO_PATH = Path(__file__).resolve().parent.parent.parent / "nodegoat"


def test_repository_loader_metadata():
    assert REPO_PATH.exists(), f"Target repo not found at {REPO_PATH}"
    meta = RepositoryLoader.inspect(REPO_PATH)

    assert meta.repository == "nodegoat"
    assert "JavaScript" in meta.languages
    assert "npm" in meta.package_managers
    assert "package.json" in meta.manifests
    assert "package-lock.json" in meta.lockfiles
    assert any("Dockerfile" in d for d in meta.dockerfiles)
    assert any("docker-compose" in c for c in meta.docker_compose_files)
    assert len(meta.cicd_files) > 0


def test_manifest_parser_package_json():
    pkg_file = REPO_PATH / "package.json"
    parsed = ManifestParser.parse_package_json(pkg_file)

    assert parsed["name"] == "owasp-nodejs-goat"
    assert parsed["version"] == "1.3.0"
    assert len(parsed["dependencies"]) == 16
    assert len(parsed["devDependencies"]) == 20
    assert "express" in parsed["dependencies"]
    assert "grunt" in parsed["devDependencies"]


def test_manifest_parser_package_lock_json():
    lock_file = REPO_PATH / "package-lock.json"
    parsed = ManifestParser.parse_package_lock_json(lock_file)

    assert parsed["lockfileVersion"] == 2
    assert len(parsed["packages"]) > 1000


def test_dependency_extractor():
    extractor = DependencyExtractor(REPO_PATH)
    inventory = extractor.extract()

    assert inventory.repository == "nodegoat"
    assert inventory.ecosystem == "npm"
    assert inventory.total_components == 1091
    assert inventory.direct_dependencies == 36
    assert inventory.transitive_dependencies == 1055
    assert inventory.production_dependencies == 509
    assert inventory.development_dependencies == 537

    # Check key direct production dependencies
    comp_map = {c.name: c for c in inventory.components}
    assert "express" in comp_map
    assert comp_map["express"].dependency_type == "direct"
    assert comp_map["express"].environment == "production"
    assert comp_map["express"].purl.startswith("pkg:npm/express@")

    # Check key direct dev dependencies
    assert "grunt" in comp_map
    assert comp_map["grunt"].dependency_type == "direct"
    assert comp_map["grunt"].environment == "development"

    # Check transitive dependency
    assert "accepts" in comp_map
    assert comp_map["accepts"].dependency_type == "transitive"
