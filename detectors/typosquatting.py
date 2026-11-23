"""
Detector 2: Typosquatting & Name Similarity Detector
Compares package names against popular and existing ecosystem packages
using Levenshtein distance, prefix/suffix inspection, and structural masquerading heuristics.
Explicitly avoids classifying similarity alone as confirmed malicious activity.
"""

import json
from pathlib import Path
from typing import Any, Dict, List, Set, Tuple

# Reference dataset of canonical popular npm packages
POPULAR_NPM_PACKAGES = {
    "express", "lodash", "react", "react-dom", "chalk", "debug", "request",
    "moment", "async", "commander", "colors", "axios", "webpack", "typescript",
    "body-parser", "cookie-parser", "cors", "dotenv", "fs-extra", "glob",
    "inquirer", "jest", "mocha", "mongoose", "multer", "nodemon", "passport",
    "prettier", "redis", "rxjs", "semver", "superagent", "uuid", "ws", "yargs",
    "bcrypt", "esapi", "minimatch", "marked", "helmet", "csurf", "consolidate",
    "serve-favicon", "swig", "underscore", "needle", "mkdirp", "rimraf", "bluebird"
}


def levenshtein_distance(s1: str, s2: str) -> int:
    """Compute classic Levenshtein distance."""
    if len(s1) < len(s2):
        return levenshtein_distance(s2, s1)
    if len(s2) == 0:
        return len(s1)

    previous_row = list(range(len(s2) + 1))
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row
    return previous_row[-1]


def analyze_typosquatting(repo_root: Path) -> List[Dict[str, Any]]:
    findings = []
    inventory_path = repo_root / "component-inventory.json"
    pkg_json_path = repo_root / "nodegoat" / "package.json"

    if not inventory_path.exists():
        return findings

    with open(inventory_path, "r", encoding="utf-8") as f:
        inventory = json.load(f)

    with open(pkg_json_path, "r", encoding="utf-8") as f:
        pkg_json = json.load(f)

    direct_deps = set(pkg_json.get("dependencies", {}).keys()) | set(pkg_json.get("devDependencies", {}).keys())

    components = inventory.get("components", [])
    unique_pkg_names = {c["name"] for c in components}

    for pkg_name in sorted(unique_pkg_names):
        # Skip scoped packages (@scope/...) from raw string comparison or normalize scope
        base_name = pkg_name.split("/")[-1] if "/" in pkg_name else pkg_name

        # Exact match with popular package is legitimate
        if base_name in POPULAR_NPM_PACKAGES:
            continue

        # Check 1: Well-known confusing forks or brand masquerading (e.g. bcrypt-nodejs vs bcrypt)
        for popular in POPULAR_NPM_PACKAGES:
            # Prefix or suffix variant (e.g. node-esapi, bcrypt-nodejs, express-...)
            # We check if popular name is embedded as a core token
            if base_name == f"{popular}-nodejs" or base_name == f"node-{popular}":
                is_direct = pkg_name in direct_deps
                findings.append({
                    "id": f"SUSP-TYPO-BRAND-{pkg_name.upper().replace('@', '').replace('/', '_')}",
                    "category": "Typosquatting",
                    "severity": "HIGH" if is_direct else "MEDIUM",
                    "affected_file": "nodegoat/package.json" if is_direct else "nodegoat/package-lock.json",
                    "line_number": 1,
                    "evidence": f"Package '{pkg_name}' variants popular package '{popular}' with prefix/suffix affix",
                    "explanation": (
                        f"Package '{pkg_name}' uses the name of popular package '{popular}' with an affix. "
                        "While frequently an unmaintained fork or legacy wrapper (e.g. bcrypt-nodejs vs native bcrypt), "
                        "such patterns are also leveraged by typosquatters for dependency confusion."
                    ),
                    "confidence": "MEDIUM"
                })
                break

            # Check 2: Low edit distance (Levenshtein distance <= 1 or 2)
            dist = levenshtein_distance(base_name, popular)
            if dist == 1 and len(popular) >= 4:
                is_direct = pkg_name in direct_deps
                findings.append({
                    "id": f"SUSP-TYPO-EDIT1-{pkg_name.upper().replace('@', '').replace('/', '_')}",
                    "category": "Typosquatting",
                    "severity": "HIGH" if is_direct else "MEDIUM",
                    "affected_file": "nodegoat/package.json" if is_direct else "nodegoat/package-lock.json",
                    "line_number": 1,
                    "evidence": f"Package '{pkg_name}' has edit distance of 1 from popular package '{popular}'",
                    "explanation": (
                        f"Package '{pkg_name}' is visually and phonetically similar to '{popular}' (edit distance: 1). "
                        "Attackers frequently publish packages with 1-character typos to hijack accidental misspellings."
                    ),
                    "confidence": "HIGH"
                })
                break
            elif dist == 2 and len(popular) >= 6 and abs(len(base_name) - len(popular)) <= 1:
                is_direct = pkg_name in direct_deps
                findings.append({
                    "id": f"SUSP-TYPO-EDIT2-{pkg_name.upper().replace('@', '').replace('/', '_')}",
                    "category": "Typosquatting",
                    "severity": "LOW",
                    "affected_file": "nodegoat/package.json" if is_direct else "nodegoat/package-lock.json",
                    "line_number": 1,
                    "evidence": f"Package '{pkg_name}' has edit distance of 2 from popular package '{popular}'",
                    "explanation": (
                        f"Package '{pkg_name}' shares high string similarity with '{popular}' (edit distance: 2). "
                        "Recorded as a low-confidence typosquatting heuristic candidate for reviewer awareness."
                    ),
                    "confidence": "LOW"
                })
                break

    return findings
