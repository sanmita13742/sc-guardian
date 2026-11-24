"""Production Context Analysis for Contextual Risk Scoring v2.0.

Evaluates Dimension P (Production Code Reachability):
    Confirmed production execution path: 100
    Strong production indicators: 70
    Production inclusion without verified execution: 40
    Dev/Test-only: 0
    Unknown: None (preserved for missing-evidence policy)
"""
from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Optional

from reachability.scanners import SourceIndex, Usage, _matches
from risk_analysis.contextual_scorer import DimensionScore

# Patterns identifying core production service entry points
PROD_ENTRY_PATTERNS = (
    "main.py", "app.py", "server.py", "wsgi.py", "asgi.py", "manage.py",
    "index.js", "server.js", "app.js", "main.ts", "server.ts", "index.ts",
    "main.go", "server.go", "Application.java", "App.java"
)

# Route and handler definition keywords
SERVER_ROUTE_PATTERNS = (
    "@app.get", "@app.post", "@app.put", "@app.delete", "@app.route",
    "@router.get", "@router.post", "Blueprint(", "Flask(", "FastAPI(",
    "app.get(", "app.post(", "app.use(", "router.get(", "router.post(",
    "http.HandleFunc", "r.GET(", "r.POST(", "gin.Default()",
    "@RestController", "@GetMapping", "@PostMapping", "@RequestMapping"
)

# Worker and background daemon keywords
WORKER_PATTERNS = (
    "@app.task", "@shared_task", "celery", "kafka", "rabbitmq", "consumer",
    "background_tasks", "threading.Thread", "multiprocessing.Process"
)


class ProductionContextAnalyzer:
    """Analyzes whether a package participates in production execution paths."""

    def __init__(self, repo_dir: Optional[Path] = None):
        self.repo_dir = Path(repo_dir) if repo_dir else None
        self._cached_entry_points: Optional[list[str]] = None
        self._cached_has_dockerfile: Optional[bool] = None
        self._cached_ci_deploy_signals: Optional[list[str]] = None

    def _discover_entry_points(self) -> list[str]:
        if self._cached_entry_points is not None:
            return self._cached_entry_points
        if not self.repo_dir or not self.repo_dir.exists():
            self._cached_entry_points = []
            return []

        entries = []
        for root, _, files in os.walk(self.repo_dir):
            rel_dir = os.path.relpath(root, self.repo_dir).replace("\\", "/")
            if any(p in rel_dir.lower() for p in ("test", "spec", ".git", "node_modules", "vendor", "dist", "build")):
                continue
            for f in files:
                if f in PROD_ENTRY_PATTERNS or f.endswith(("Handler.java", "Controller.java", "routes.py", "api.py")):
                    entries.append(os.path.join(rel_dir, f).replace("\\", "/").lstrip("./"))
        self._cached_entry_points = entries
        return entries

    def _check_dockerfile(self) -> bool:
        if self._cached_has_dockerfile is not None:
            return self._cached_has_dockerfile
        if not self.repo_dir or not self.repo_dir.exists():
            self._cached_has_dockerfile = False
            return False

        has_df = any((self.repo_dir / f).exists() for f in ("Dockerfile", "docker-compose.yml", "Containerfile"))
        self._cached_has_dockerfile = has_df
        return has_df

    def evaluate_production_reachability(
        self,
        package_name: str,
        ecosystem: str,
        source_index: Optional[SourceIndex],
        is_dev: bool = False,
        asset_type: str = "source_dependency",
        dependency_type: str = "direct",
        pipeline_findings: Optional[list[dict]] = None,
        container_details: Optional[dict[str, Any]] = None,
    ) -> DimensionScore:
        """Evaluate Dimension P (Production Code Reachability) on a 0-100 scale."""
        dim_name = "Production Code Reachability"
        weight = 0.35

        # 1. Dev / Test-only exclusion
        if is_dev:
            return DimensionScore(
                dimension="P",
                name=dim_name,
                weight=weight,
                raw_value="dev_dependency",
                normalized_score=0.0,
                status="dev_only",
                weighted_contribution=0.0,
                evidence=["Explicitly marked as development-only dependency in manifest/lockfile"],
                confidence="high",
            )

        # 2. Container image asset type
        if asset_type == "container_image":
            image_name = (container_details or {}).get("image_name", "container image")
            return DimensionScore(
                dimension="P",
                name=dim_name,
                weight=weight,
                raw_value="container_image_asset",
                normalized_score=100.0,
                status="confirmed_production_container",
                weighted_contribution=round(weight * 100.0, 2),
                evidence=[
                    f"Confirmed production asset: package is bundled in container image '{image_name}'",
                    "OS/runtime packages inside deployed images directly expose container execution surface",
                ],
                confidence="high",
            )

        if not source_index or not self.repo_dir:
            return DimensionScore(
                dimension="P",
                name=dim_name,
                weight=weight,
                raw_value="unindexed_repository",
                normalized_score=None,
                status="unknown",
                weighted_contribution=0.0,
                evidence=["Repository source or production manifests were not accessible for production verification"],
                confidence="none",
            )

        entry_files = set(self._discover_entry_points())
        has_docker = self._check_dockerfile()

        # Find matching usages
        lang = next((l for l, e in {"py": "PyPI", "js": "npm", "java": "Maven", "go": "Go"}.items() if e == ecosystem), None)
        app_usages: list[Usage] = []
        test_usages: list[Usage] = []
        if lang and source_index.by_lang.get(lang):
            usages = [u for u in source_index.by_lang.get(lang, []) if _matches(ecosystem, package_name, u.module)]
            app_usages = [u for u in usages if not u.test]
            test_usages = [u for u in usages if u.test]

        # If exclusively used in test code
        if not app_usages and test_usages:
            return DimensionScore(
                dimension="P",
                name=dim_name,
                weight=weight,
                raw_value="test_files_only",
                normalized_score=0.0,
                status="test_only",
                weighted_contribution=0.0,
                evidence=[
                    f"Excluded from production: imported only in {len(test_usages)} test file(s)",
                    "Never executed during standard application runtime",
                ],
                confidence="high",
            )

        # Check if imported in a verified production entry point or route
        entry_imports = [u for u in app_usages if u.path in entry_files or any(u.path.endswith(ep) for ep in PROD_ENTRY_PATTERNS)]
        if entry_imports:
            entry_paths = sorted({u.path for u in entry_imports})
            return DimensionScore(
                dimension="P",
                name=dim_name,
                weight=weight,
                raw_value={"entry_imports": entry_paths},
                normalized_score=100.0,
                status="confirmed_production_execution",
                weighted_contribution=round(weight * 100.0, 2),
                evidence=[
                    f"Confirmed production path: imported directly in application entry point(s): {', '.join(entry_paths[:3])}",
                    "Executes in the core application runtime lifecycle",
                ],
                confidence="high",
            )

        # Strong production indicators: application code usage + container/service inclusion
        if app_usages:
            app_paths = sorted({u.path for u in app_usages})
            if has_docker:
                return DimensionScore(
                    dimension="P",
                    name=dim_name,
                    weight=weight,
                    raw_value={"app_files": len(app_paths), "docker": True},
                    normalized_score=70.0,
                    status="strong_production_indicators",
                    weighted_contribution=round(weight * 70.0, 2),
                    evidence=[
                        f"Strong production indicators: imported in {len(app_paths)} app files and containerized via Dockerfile",
                        f"Files: {', '.join(app_paths[:3])}",
                    ],
                    confidence="high",
                )
            return DimensionScore(
                dimension="P",
                name=dim_name,
                weight=weight,
                raw_value={"app_files": len(app_paths)},
                normalized_score=70.0,
                status="strong_production_indicators",
                weighted_contribution=round(weight * 70.0, 2),
                evidence=[
                    f"Strong production indicators: active in {len(app_paths)} application non-test source files",
                    f"Files: {', '.join(app_paths[:3])}",
                ],
                confidence="medium",
            )

        # Not directly imported, but a non-dev dependency
        if dependency_type == "direct":
            return DimensionScore(
                dimension="P",
                name=dim_name,
                weight=weight,
                raw_value="production_manifest_inclusion",
                normalized_score=40.0,
                status="production_inclusion_unverified_execution",
                weighted_contribution=round(weight * 40.0, 2),
                evidence=[
                    "Included as direct non-dev dependency in production manifest",
                    "Static import in primary entrypoints was not identified, but package is shipped with application",
                ],
                confidence="medium",
            )

        # Transitive or unimported
        return DimensionScore(
            dimension="P",
            name=dim_name,
            weight=weight,
            raw_value="unimported_or_transitive",
            normalized_score=20.0 if dependency_type == "transitive" else 0.0,
            status="minimal_production_evidence",
            weighted_contribution=round(weight * (20.0 if dependency_type == "transitive" else 0.0), 2),
            evidence=[
                "No direct production entry point imports detected",
                "Transitive dependency shipped in lockfile" if dependency_type == "transitive" else "No production runtime evidence",
            ],
            confidence="medium",
        )
