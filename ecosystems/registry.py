"""Ecosystem plugin registry: what the Guardian can do for each ecosystem, declared in one place.

A capability that is not declared is simply not offered for that ecosystem (and the UI says so) - nothing is silently assumed.
Adding an ecosystem = one ``register(Ecosystem(...))`` call plus the capability modules it points to. Existing parsers/clients are wrapped,
not duplicated: ``parser_files`` are resolved against ``sbom.lockfile_analyzer.PARSERS`` and ``registry`` against ``sbom.fusion.registries``.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, Optional


@dataclass
class Ecosystem:
    key: str  # OSV ecosystem name (npm, PyPI, Maven, Go, crates.io, Packagist, NuGet, RubyGems) or pseudo ecosystem (Docker, GitHub Actions, ...)
    label: str
    kind: str  # package | container | pipeline
    purl_type: Optional[str] = None
    manifests: tuple[str, ...] = ()  # file names / suffixes that declare dependencies
    lockfiles: tuple[str, ...] = ()  # files that pin exact versions
    source_globs: tuple[str, ...] = ()  # application source files (for reachability)
    registry: bool = False  # metadata/digest client available (sbom.fusion.registries)
    resolver: bool = False  # transitive resolution for manifest-only services (deps.dev)
    osv: bool = True  # advisories available from OSV
    reachability: Optional[Callable] = None  # (repo_dir, package) -> evidence (filled by reachability.scanners)
    patcher: Optional[Callable] = None  # (manifest text, change) -> new text (filled by remediation.patchers)
    pipeline_rules: Optional[Callable] = None  # (file text, path) -> findings (filled by pipeline_analysis)
    notes: str = ""


ECOSYSTEMS: dict[str, Ecosystem] = {}


def register(e: Ecosystem) -> Ecosystem:
    ECOSYSTEMS[e.key] = e
    return e


def get(key: Optional[str]) -> Optional[Ecosystem]:
    return ECOSYSTEMS.get(key or "")


def packages() -> list[Ecosystem]:
    return [e for e in ECOSYSTEMS.values() if e.kind == "package"]


def capability_matrix() -> list[dict]:
    """Rows for docs/UI: which capability exists for which ecosystem (computed, never hand-written)."""
    rows = []
    for e in ECOSYSTEMS.values():
        rows.append({"ecosystem": e.label, "kind": e.kind, "lockfile parsing": bool(e.lockfiles), "manifest parsing": bool(e.manifests), "registry metadata": e.registry,
                     "transitive resolution": e.resolver, "OSV advisories": e.osv, "reachability": e.reachability is not None, "patch generation": e.patcher is not None,
                     "pipeline rules": e.pipeline_rules is not None})
    return rows


register(Ecosystem("npm", "Node.js / npm", "package", "npm", ("package.json",), ("package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml"),
                   (".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx"), registry=True, resolver=True))
register(Ecosystem("PyPI", "Python / PyPI", "package", "pypi", ("pyproject.toml", "setup.py", "Pipfile", "requirements*.txt"), ("poetry.lock", "uv.lock", "Pipfile.lock", "requirements*.txt"),
                   (".py",), registry=True, resolver=True))
register(Ecosystem("Maven", "Java / Maven & Gradle", "package", "maven", ("pom.xml", "build.gradle", "build.gradle.kts"), ("gradle.lockfile",), (".java", ".kt", ".scala"), registry=True, resolver=True))
register(Ecosystem("Go", "Go modules", "package", "golang", ("go.mod",), ("go.sum",), (".go",), registry=True))
register(Ecosystem("crates.io", "Rust / Cargo", "package", "cargo", ("Cargo.toml",), ("Cargo.lock",), (".rs",), registry=True, resolver=True))
register(Ecosystem("Packagist", "PHP / Composer", "package", "composer", ("composer.json",), ("composer.lock",), (".php",), registry=True))
register(Ecosystem("NuGet", ".NET / NuGet", "package", "nuget", (".csproj", ".fsproj", ".vbproj"), ("packages.lock.json",), (".cs", ".fs", ".vb"), registry=True, resolver=True))
register(Ecosystem("RubyGems", "Ruby / Bundler", "package", "gem", ("Gemfile",), ("Gemfile.lock",), (".rb",), registry=True, notes="inventory via Syft/Trivy"))
register(Ecosystem("Docker", "Docker / OCI images", "container", "docker", ("Dockerfile", "*.dockerfile", "docker-compose*.yml", "compose*.yml"), (), (), registry=False, osv=False,
                   notes="base-image hygiene rules; images are SBOM components"))
register(Ecosystem("GitHub Actions", "GitHub Actions", "pipeline", "github", (".github/workflows/*.yml", ".github/workflows/*.yaml"), (), (), registry=False, osv=True,
                   notes="workflow rules; actions are SBOM components, advisories via OSV 'GitHub Actions'"))
register(Ecosystem("CI (generic)", "GitLab CI / Jenkins / CircleCI / Azure Pipelines", "pipeline", None, (".gitlab-ci.yml", "Jenkinsfile", ".circleci/config.yml", "azure-pipelines.yml"), (), (), osv=False,
                   notes="generic script-level rules"))
