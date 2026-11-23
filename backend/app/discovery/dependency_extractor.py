import datetime
import json
import urllib.parse
from pathlib import Path
from typing import Dict, Any, List, Set, Tuple, Optional

from app.models.schemas import Component, ComponentInventory, RepositoryMetadata
from app.discovery.manifest_parser import ManifestParser
from app.core.logging import logger
from app.core.config import DISCOVERY_DIR


def generate_purl(name: str, version: str) -> str:
    """
    Generates standard Package URL (PURL) for npm package.
    e.g. pkg:npm/%40cypress/xvfb@1.2.3 or pkg:npm/express@4.13.4
    """
    if name.startswith("@"):
        scope, pkg = name.split("/", 1)
        encoded_scope = urllib.parse.quote(scope)
        return f"pkg:npm/{encoded_scope}/{pkg}@{version}"
    return f"pkg:npm/{name}@{version}"


def parse_package_name_from_path(node_modules_path: str) -> str:
    """
    Extracts the package name from a node_modules path.
    e.g. 'node_modules/@cypress/xvfb' -> '@cypress/xvfb'
         'node_modules/express/node_modules/accepts' -> 'accepts'
    """
    parts = node_modules_path.split("node_modules/")
    last_part = parts[-1]
    return last_part


class DependencyExtractor:
    """
    Extracts direct and transitive dependencies from package.json and package-lock.json,
    resolves versions, determines parent-child relationships, classifies production vs dev,
    and builds the normalized component inventory.
    """

    def __init__(self, repo_path: Path):
        self.repo_path = repo_path.resolve()
        self.package_json_path = self.repo_path / "package.json"
        self.package_lock_path = self.repo_path / "package-lock.json"

    def extract(self, metadata: Optional[RepositoryMetadata] = None) -> ComponentInventory:
        """
        Main extraction method.
        """
        if not self.package_json_path.exists():
            raise FileNotFoundError(f"Missing package.json in {self.repo_path}")

        pkg_json = ManifestParser.parse_package_json(self.package_json_path)
        has_lockfile = self.package_lock_path.exists()

        direct_prod_declared = pkg_json.get("dependencies", {})
        direct_dev_declared = pkg_json.get("devDependencies", {})
        direct_opt_declared = pkg_json.get("optionalDependencies", {})
        direct_peer_declared = pkg_json.get("peerDependencies", {})

        all_direct_names = set(direct_prod_declared.keys()) | set(direct_dev_declared.keys())

        components_by_id: Dict[str, Component] = {}
        # adjacency: parent_path -> list of (child_name, child_version_spec)
        parent_child_links: List[Tuple[str, str, str]] = []

        unresolved_deps = []

        if has_lockfile:
            lock_data = ManifestParser.parse_package_lock_json(self.package_lock_path)
            lock_version = lock_data.get("lockfileVersion", 1)

            if lock_version >= 2 and lock_data.get("packages"):
                self._extract_v2(
                    lock_data["packages"],
                    direct_prod_declared,
                    direct_dev_declared,
                    direct_opt_declared,
                    direct_peer_declared,
                    components_by_id,
                    parent_child_links,
                    unresolved_deps
                )
            else:
                self._extract_v1(
                    lock_data.get("dependencies", {}),
                    direct_prod_declared,
                    direct_dev_declared,
                    components_by_id,
                    parent_child_links,
                    unresolved_deps
                )
        else:
            logger.warning("No package-lock.json found; resolving declared dependencies without lockfile.")
            for name, ver in direct_prod_declared.items():
                comp_id = f"{name}@{ver}"
                components_by_id[comp_id] = Component(
                    name=name,
                    version=ver,
                    ecosystem="npm",
                    type="library",
                    dependency_type="direct",
                    environment="production",
                    declared_version=ver,
                    resolved_version=None,
                    source="package.json",
                    purl=generate_purl(name, ver)
                )
            for name, ver in direct_dev_declared.items():
                comp_id = f"{name}@{ver}"
                components_by_id[comp_id] = Component(
                    name=name,
                    version=ver,
                    ecosystem="npm",
                    type="library",
                    dependency_type="direct",
                    environment="development",
                    declared_version=ver,
                    resolved_version=None,
                    source="package.json",
                    purl=generate_purl(name, ver)
                )

        # Propagate production vs development reachability
        self._propagate_environments(components_by_id, parent_child_links, direct_prod_declared)

        # Count metrics
        components_list = list(components_by_id.values())
        direct_count = sum(1 for c in components_list if c.dependency_type == "direct")
        transitive_count = sum(1 for c in components_list if c.dependency_type == "transitive")
        prod_count = sum(1 for c in components_list if c.environment == "production")
        dev_count = sum(1 for c in components_list if c.environment == "development")

        inventory = ComponentInventory(
            repository=self.repo_path.name,
            ecosystem="npm",
            scan_timestamp=datetime.datetime.now(datetime.timezone.utc).isoformat(),
            total_components=len(components_list),
            direct_dependencies=direct_count,
            transitive_dependencies=transitive_count,
            production_dependencies=prod_count,
            development_dependencies=dev_count,
            manifests=[str(self.package_json_path.name)] if self.package_json_path.exists() else [],
            lockfiles=[str(self.package_lock_path.name)] if self.package_lock_path.exists() else [],
            unresolved_dependencies=unresolved_deps,
            repository_metadata=metadata.model_dump() if metadata else {},
            components=components_list
        )

        # Save to artifacts/discovery/component-inventory.json
        output_file = DISCOVERY_DIR / "component-inventory.json"
        with open(output_file, "w", encoding="utf-8") as f:
            f.write(inventory.model_dump_json(indent=2))

        logger.info(
            f"Component inventory saved to {output_file}: "
            f"Total={inventory.total_components}, Direct={direct_count}, Transitive={transitive_count}, "
            f"Prod={prod_count}, Dev={dev_count}"
        )
        return inventory

    def _extract_v2(
        self,
        packages: Dict[str, Any],
        direct_prod_declared: Dict[str, str],
        direct_dev_declared: Dict[str, str],
        direct_opt_declared: Dict[str, str],
        direct_peer_declared: Dict[str, str],
        components_by_id: Dict[str, Component],
        parent_child_links: List[Tuple[str, str, str]],
        unresolved_deps: List[str]
    ):
        """
        Parses lockfileVersion 2 & 3 'packages' mapping.
        """
        root_data = packages.get("", {})
        root_deps = root_data.get("dependencies", {})
        root_dev_deps = root_data.get("devDependencies", {})

        for pkg_path, pkg_info in packages.items():
            if not pkg_path:
                # Root package
                continue

            pkg_name = parse_package_name_from_path(pkg_path)
            version = pkg_info.get("version", "0.0.0")
            integrity = pkg_info.get("integrity")
            license_str = pkg_info.get("license")
            dependencies = pkg_info.get("dependencies", {})

            # Is it direct or transitive?
            # A direct dependency is at 'node_modules/<name>' AND present in root dependencies/devDependencies
            is_hoisted_direct = (pkg_path == f"node_modules/{pkg_name}") and (
                pkg_name in direct_prod_declared or pkg_name in direct_dev_declared
            )

            dep_type = "direct" if is_hoisted_direct else "transitive"

            # Determine initial environment
            is_dev = pkg_info.get("dev", False)
            is_optional = pkg_info.get("optional", False)
            is_peer = pkg_info.get("peer", False)

            if is_hoisted_direct:
                if pkg_name in direct_prod_declared:
                    env = "production"
                    declared_ver = direct_prod_declared[pkg_name]
                elif pkg_name in direct_dev_declared:
                    env = "development"
                    declared_ver = direct_dev_declared[pkg_name]
                elif pkg_name in direct_opt_declared:
                    env = "optional"
                    declared_ver = direct_opt_declared[pkg_name]
                elif pkg_name in direct_peer_declared:
                    env = "peer"
                    declared_ver = direct_peer_declared[pkg_name]
                else:
                    env = "development" if is_dev else "production"
                    declared_ver = None
            else:
                declared_ver = None
                if is_optional:
                    env = "optional"
                elif is_peer:
                    env = "peer"
                elif is_dev:
                    env = "development"
                else:
                    env = "production"

            comp_id = f"{pkg_name}@{version}"

            # Capture parent-child relations
            for child_name, child_spec in dependencies.items():
                parent_child_links.append((pkg_name, child_name, child_spec))

            if comp_id in components_by_id:
                # Merge if existing, prioritizing production environment over development
                existing = components_by_id[comp_id]
                if dep_type == "direct":
                    existing.dependency_type = "direct"
                if env == "production":
                    existing.environment = "production"
                if not existing.declared_version and declared_ver:
                    existing.declared_version = declared_ver
                existing.dependencies.update(dependencies)
            else:
                components_by_id[comp_id] = Component(
                    name=pkg_name,
                    version=version,
                    ecosystem="npm",
                    type="library",
                    dependency_type=dep_type,
                    environment=env,
                    parent=None,
                    purl=generate_purl(pkg_name, version),
                    source="package-lock.json",
                    declared_version=declared_ver,
                    resolved_version=version,
                    license=license_str,
                    integrity=integrity,
                    dependencies=dependencies,
                    depth=1 if dep_type == "direct" else 2
                )

    def _extract_v1(
        self,
        dependencies_tree: Dict[str, Any],
        direct_prod_declared: Dict[str, str],
        direct_dev_declared: Dict[str, str],
        components_by_id: Dict[str, Component],
        parent_child_links: List[Tuple[str, str, str]],
        unresolved_deps: List[str]
    ):
        """
        Recursive extractor for lockfileVersion 1 tree.
        """
        def recurse(node_name: str, node_data: Dict[str, Any], parent: Optional[str] = None, depth: int = 1):
            ver = node_data.get("version", "0.0.0")
            is_dev = node_data.get("dev", False)
            is_opt = node_data.get("optional", False)
            requires = node_data.get("requires", {})
            nested = node_data.get("dependencies", {})

            is_direct = (parent is None) and (node_name in direct_prod_declared or node_name in direct_dev_declared)
            dep_type = "direct" if is_direct else "transitive"

            if is_direct:
                env = "production" if node_name in direct_prod_declared else "development"
                declared_ver = direct_prod_declared.get(node_name) or direct_dev_declared.get(node_name)
            else:
                declared_ver = None
                env = "optional" if is_opt else ("development" if is_dev else "production")

            comp_id = f"{node_name}@{ver}"
            for req_name, req_spec in requires.items():
                parent_child_links.append((node_name, req_name, req_spec))

            if comp_id in components_by_id:
                existing = components_by_id[comp_id]
                if dep_type == "direct":
                    existing.dependency_type = "direct"
                if env == "production":
                    existing.environment = "production"
                existing.dependencies.update(requires)
            else:
                components_by_id[comp_id] = Component(
                    name=node_name,
                    version=ver,
                    ecosystem="npm",
                    type="library",
                    dependency_type=dep_type,
                    environment=env,
                    parent=parent,
                    purl=generate_purl(node_name, ver),
                    source="package-lock.json",
                    declared_version=declared_ver,
                    resolved_version=ver,
                    dependencies=requires,
                    depth=depth
                )

            for child_name, child_data in nested.items():
                recurse(child_name, child_data, parent=node_name, depth=depth + 1)

        for dep_name, dep_data in dependencies_tree.items():
            recurse(dep_name, dep_data, parent=None, depth=1)

    def _propagate_environments(
        self,
        components_by_id: Dict[str, Component],
        parent_child_links: List[Tuple[str, str, str]],
        direct_prod_declared: Dict[str, str]
    ):
        """
        Ensures any dependency reachable from production direct dependencies
        is marked as production.
        """
        # Map pkg_name -> list of component keys
        name_to_keys: Dict[str, List[str]] = {}
        for key, comp in components_by_id.items():
            name_to_keys.setdefault(comp.name, []).append(key)

        # BFS from production roots
        queue: List[str] = [name for name in direct_prod_declared.keys()]
        visited_prod: Set[str] = set(queue)

        # Build adjacency graph
        adj: Dict[str, Set[str]] = {}
        for parent, child, _ in parent_child_links:
            adj.setdefault(parent, set()).add(child)

        while queue:
            curr = queue.pop(0)
            for child in adj.get(curr, []):
                if child not in visited_prod:
                    visited_prod.add(child)
                    queue.append(child)

        # Any component whose name is in visited_prod is production!
        for pkg_name in visited_prod:
            for key in name_to_keys.get(pkg_name, []):
                components_by_id[key].environment = "production"
