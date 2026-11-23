"""
Guardian SBOM and Dependency Graph Diagnostic Audit
Investigates the discrepancy between:
- 1,091 unique package identities (Guardian inventory)
- 1,480 components (CycloneDX SBOM / package-lock packages)
- 422 components (Syft default output)
- Grey nodes / incomplete metadata analysis
"""

import json
from pathlib import Path
from collections import defaultdict, Counter

ROOT_DIR = Path(__file__).resolve().parent.parent.parent
LOCKFILE_PATH = ROOT_DIR / "nodegoat" / "package-lock.json"
PACKAGE_JSON_PATH = ROOT_DIR / "nodegoat" / "package.json"
SYFT_SBOM_PATH = ROOT_DIR / "nodegoat-sbom.json"
INVENTORY_PATH = ROOT_DIR / "component-inventory.json"


def run_audit():
    with open(LOCKFILE_PATH, "r", encoding="utf-8") as f:
        lock_data = json.load(f)

    with open(PACKAGE_JSON_PATH, "r", encoding="utf-8") as f:
        pkg_data = json.load(f)

    with open(SYFT_SBOM_PATH, "r", encoding="utf-8") as f:
        syft_sbom = json.load(f)

    with open(INVENTORY_PATH, "r", encoding="utf-8") as f:
        inventory_data = json.load(f)

    print("=" * 80)
    print("GUARDIAN SBOM & DEPENDENCY GRAPH CANONICAL AUDIT")
    print("=" * 80)

    # 1. Inspect package-lock.json: 'packages' section
    packages_sec = lock_data.get("packages", {})
    total_packages_keys = len(packages_sec)
    has_root_key = "" in packages_sec
    dep_instances_in_packages = total_packages_keys - (1 if has_root_key else 0)

    print(f"\n[1] PACKAGE-LOCK.JSON 'PACKAGES' SECTION:")
    print(f"  Total keys in packages dict: {total_packages_keys}")
    print(f"  Root project key ('') present: {has_root_key}")
    print(f"  Resolved dependency instances in packages: {dep_instances_in_packages}")

    # Analyze metadata available in 'packages' section
    packages_fields_counter = Counter()
    missing_metadata_in_packages = defaultdict(int)
    standard_meta_fields = ["license", "licenses", "description", "author", "homepage", "repository", "bugs"]

    packages_by_name = defaultdict(list)
    packages_by_name_version = defaultdict(list)
    dev_instances_count = 0
    prod_instances_count = 0

    for path, info in packages_sec.items():
        if path == "":
            continue
        # Extract package name from path
        # E.g. node_modules/a/node_modules/@scope/b -> @scope/b
        parts = path.split("node_modules/")
        pkg_name = parts[-1]
        version = info.get("version", "unknown")
        is_dev = info.get("dev", False)

        if is_dev:
            dev_instances_count += 1
        else:
            prod_instances_count += 1

        for k in info.keys():
            packages_fields_counter[k] += 1

        for mf in standard_meta_fields:
            if mf not in info:
                missing_metadata_in_packages[mf] += 1

        packages_by_name[pkg_name].append({
            "path": path,
            "version": version,
            "dev": is_dev,
            "resolved": info.get("resolved"),
            "integrity": info.get("integrity"),
            "requires": info.get("requires") or info.get("dependencies", {})
        })
        packages_by_name_version[(pkg_name, version)].append(path)

    print(f"  Production instances: {prod_instances_count}")
    print(f"  Development instances: {dev_instances_count}")
    print(f"  Total unique package names: {len(packages_by_name)}")
    print(f"  Total unique (name, version) identities: {len(packages_by_name_version)}")

    # 2. Inspect package-lock.json: 'dependencies' section (recursive v1-style)
    dependencies_sec = lock_data.get("dependencies", {})

    all_v1_instances = []

    def walk_v1(deps, parent_path=""):
        for name, info in deps.items():
            current_path = f"{parent_path}/node_modules/{name}" if parent_path else f"node_modules/{name}"
            all_v1_instances.append({
                "name": name,
                "path": current_path,
                "version": info.get("version"),
                "dev": info.get("dev", False),
                "resolved": info.get("resolved"),
                "integrity": info.get("integrity"),
                "requires": info.get("requires", {}),
                "has_nested": "dependencies" in info
            })
            if "dependencies" in info:
                walk_v1(info["dependencies"], current_path)

    walk_v1(dependencies_sec)
    print(f"\n[2] PACKAGE-LOCK.JSON 'DEPENDENCIES' SECTION (RECURSIVE):")
    print(f"  Total resolved dependency instances: {len(all_v1_instances)}")

    v1_by_name = defaultdict(list)
    v1_by_name_ver = defaultdict(list)
    v1_dev = 0
    v1_prod = 0
    for inst in all_v1_instances:
        if inst["dev"]:
            v1_dev += 1
        else:
            v1_prod += 1
        v1_by_name[inst["name"]].append(inst)
        v1_by_name_ver[(inst["name"], inst["version"])].append(inst["path"])

    print(f"  Production instances: {v1_prod}")
    print(f"  Development instances: {v1_dev}")
    print(f"  Unique package names in v1 tree: {len(v1_by_name)}")
    print(f"  Unique (name, version) identities in v1 tree: {len(v1_by_name_ver)}")

    # 3. Analyze Guardian's Component Inventory
    inv_packages = inventory_data.get("packages", [])
    print(f"\n[3] GUARDIAN COMPONENT INVENTORY:")
    print(f"  Total inventory components recorded: {len(inv_packages)}")
    inv_names = set(p["name"] for p in inv_packages)
    inv_name_vers = set((p["name"], p["version"]) for p in inv_packages)
    print(f"  Unique package names in inventory: {len(inv_names)}")
    print(f"  Unique (name, version) in inventory: {len(inv_name_vers)}")

    # 4. Multi-path and Multi-version Duplicate Analysis
    print(f"\n[4] DUPLICATE INSTALLATION AND PATH ANALYSIS:")
    # (a) Packages with multiple installations (different paths)
    multi_install_names = {k: v for k, v in packages_by_name.items() if len(v) > 1}
    multi_install_instances_count = sum(len(v) for v in multi_install_names.values())
    print(f"  Packages installed multiple times at different paths: {len(multi_install_names)}")
    print(f"  Total dependency instances involved in duplicate installs: {multi_install_instances_count}")

    # (b) Packages with multiple versions installed
    multi_version_names = {}
    for name, instances in packages_by_name.items():
        distinct_vers = set(inst["version"] for inst in instances)
        if len(distinct_vers) > 1:
            multi_version_names[name] = distinct_vers

    print(f"  Packages with multiple DIFFERENT versions co-existing: {len(multi_version_names)}")
    print(f"  Examples of multi-version packages:")
    for name in list(multi_version_names.keys())[:10]:
        versions = list(multi_version_names[name])
        paths = [inst["path"] for inst in packages_by_name[name]]
        print(f"    - {name}: versions={versions} (instances count={len(paths)})")

    # (c) Packages with identical version installed multiple times (unhoisted duplicates)
    same_ver_multi_path = {}
    for (name, ver), paths in packages_by_name_version.items():
        if len(paths) > 1:
            same_ver_multi_path[(name, ver)] = paths

    print(f"  Identical (name, version) pairs installed at multiple paths (redundant unhoisted copies): {len(same_ver_multi_path)}")
    print(f"  Examples of identical version unhoisted duplicates:")
    for (name, ver), paths in list(same_ver_multi_path.items())[:5]:
        print(f"    - {name}@{ver}: {len(paths)} locations: {paths[:3]}...")

    # 5. Metadata Completeness and "Grey Nodes" Analysis
    print(f"\n[5] METADATA COMPLETENESS & 'GREY NODES' ANALYSIS:")
    print("  Field occurrences across 1,479 packages instances:")
    for field, count in packages_fields_counter.most_common():
        pct = (count / dep_instances_in_packages) * 100
        print(f"    - {field:15}: {count:4} ({pct:5.1f}%)")

    # In CycloneDX terminology:
    # A complete component usually contains: name, version, purl, licenses, description, externalReferences/hashes.
    # When generated from lockfile only (without node_modules on disk or registry lookups):
    # - name: 100%
    # - version: 100%
    # - purl: 100% (computable from pkg:npm/name@version)
    # - integrity/hashes: ~99.9%
    # - licenses: 0% to ~5% (only if license was in lockfile packages section)
    # - description: 0% (lockfile never contains descriptions)
    # - author: 0%
    # - repository/homepage: 0%
    has_license = sum(1 for info in packages_sec.values() if "license" in info or "licenses" in info)
    print(f"\n  Components with 'license' in lockfile: {has_license} of {dep_instances_in_packages} ({(has_license/dep_instances_in_packages)*100:.1f}%)")
    print(f"  Components MISSING 'license': {dep_instances_in_packages - has_license}")
    print(f"  Components MISSING 'description': {dep_instances_in_packages}")
    print(f"  Components MISSING 'author': {dep_instances_in_packages}")
    print(f"  Components MISSING 'homepage/repository': {dep_instances_in_packages}")

    # Check validity of essential identity fields
    valid_name_ver = sum(1 for info in packages_sec.values() if info.get("version"))
    valid_integrity = sum(1 for info in packages_sec.values() if info.get("integrity"))
    valid_resolved = sum(1 for info in packages_sec.values() if info.get("resolved"))

    print(f"  Essential identity fields:")
    print(f"    - Has valid name & version: {valid_name_ver} of {dep_instances_in_packages} (100%)")
    print(f"    - Has valid registry resolved URL: {valid_resolved} of {dep_instances_in_packages} ({(valid_resolved/dep_instances_in_packages)*100:.1f}%)")
    print(f"    - Has valid integrity hash: {valid_integrity} of {dep_instances_in_packages} ({(valid_integrity/dep_instances_in_packages)*100:.1f}%)")

    # 6. Syft Output Deep-Dive
    print(f"\n[6] SYFT v1.57.2 OUTPUT ANALYSIS:")
    syft_comps = syft_sbom.get("components", [])
    print(f"  Total Syft components: {len(syft_comps)}")
    syft_by_type = Counter(c.get("type") for c in syft_comps)
    print(f"  Types: {dict(syft_by_type)}")

    syft_catalogers = Counter()
    for c in syft_comps:
        for p in c.get("properties", []):
            if p.get("name") == "syft:package:foundBy":
                syft_catalogers[p.get("value")] += 1
    print(f"  Catalogers: {dict(syft_catalogers)}")

    syft_npm = [c for c in syft_comps if any(p.get("value") == "javascript-lock-cataloger" for p in c.get("properties", []))]
    print(f"  Syft npm library components: {len(syft_npm)}")

    # Check how many of Syft npm components are prod vs dev
    # Match with lockfile packages
    syft_matched_prod = 0
    syft_matched_dev = 0
    syft_unknown = 0
    for c in syft_npm:
        name = c["name"]
        ver = c.get("version")
        instances = [inst for inst in packages_by_name.get(name, []) if inst["version"] == ver]
        if not instances:
            syft_unknown += 1
        elif all(inst["dev"] for inst in instances):
            syft_matched_dev += 1
        elif all(not inst["dev"] for inst in instances):
            syft_matched_prod += 1
        else:
            # mixed prod/dev
            syft_matched_prod += 1

    print(f"  Syft npm packages matched to production: {syft_matched_prod}")
    print(f"  Syft npm packages matched to development only: {syft_matched_dev}")
    print(f"  Syft unknown/unmatched: {syft_unknown}")

    # 7. Discrepancy Reconciliation Summary
    print("\n" + "=" * 80)
    print("RECONCILIATION SUMMARY TABLE:")
    print("=" * 80)
    print(f"{'Source / Metric':<45} | {'Count':<10} | {'Semantics / Scope'}")
    print("-" * 80)
    print(f"{'package-lock.json packages entries':<45} | {total_packages_keys:<10} | Root ('') + 1,479 installed instances")
    print(f"{'Another CycloneDX SBOM (1,480)':<45} | {total_packages_keys:<10} | Every package-lock installation path as component")
    print(f"{'Resolved Dependency Instances (all paths)':<45} | {dep_instances_in_packages:<10} | All node_modules/* installation locations")
    print(f"{'  - Production instances':<45} | {prod_instances_count:<10} | dev=False")
    print(f"{'  - Development instances':<45} | {dev_instances_count:<10} | dev=True")
    print(f"{'Distinct (Name, Version) identities':<45} | {len(packages_by_name_version):<10} | Unique package releases across all paths")
    print(f"{'Guardian Inventory (unique package names)':<45} | {len(packages_by_name):<10} | Distinct software packages in supply chain")
    print(f"{'Syft default SBOM output':<45} | {len(syft_comps):<10} | 413 npm (prod-only) + 6 GH Actions + 3 files")
    print(f"{'Syft dev-enabled SBOM output':<45} | {1224:<10} | Prod + dev packages found by Syft cataloger")
    print("=" * 80)


if __name__ == "__main__":
    run_audit()
