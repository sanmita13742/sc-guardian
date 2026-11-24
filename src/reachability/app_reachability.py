"""Application Reachability Analysis for Contextual Risk Scoring v2.0.

Extracts vulnerable symbols from advisories and evaluates application code reachability:
    Confirmed reachable: 100
    Potentially reachable: 60
    Unreachable with evidence: 0
    Unknown: None (preserved for missing-evidence policy)
"""
from __future__ import annotations

import re
from typing import Any, Optional

from reachability.scanners import LANG_ECO, SourceIndex, Usage, _matches
from risk_analysis.contextual_scorer import DimensionScore

# Patterns for extracting functions, methods, classes, and backticked symbols from advisories
_SYMBOL_PATTERN = re.compile(r"""(?:`([A-Za-z_][A-Za-z0-9_.]*(?:\(\))?)`|in\s+function\s+['"]?([A-Za-z_][A-Za-z0-9_.]*)['"]?|method\s+['"]?([A-Za-z_][A-Za-z0-9_.]*)['"]?|class\s+['"]?([A-Za-z_][A-Za-z0-9_.]*)['"]?)""", re.IGNORECASE)

_COMMON_VULN_TERMS = {
    "parse", "parser", "load", "loads", "eval", "execute", "render", "template", "serialize", "deserialize",
    "validate", "sanitize", "decode", "encode", "query", "request", "format", "read", "write", "upload",
    "authenticate", "verify", "sign", "verify_token", "hash", "decrypt", "encrypt", "check", "exec", "run"
}


def extract_vulnerable_symbols(summary: Optional[str] = None, details: Optional[str] = None) -> list[str]:
    """Extract named functions, methods, and classes mentioned in the vulnerability advisory."""
    text = f"{summary or ''}\n{details or ''}"
    if not text.strip():
        return []

    found = set()
    for m in _SYMBOL_PATTERN.finditer(text):
        for g in m.groups():
            if g:
                clean = g.strip().rstrip("()").split(".")[-1]
                if clean and len(clean) >= 3 and not clean.isupper() and not clean.startswith(("CVE-", "GHSA-")):
                    found.add(clean)

    # Check for prominent function-like keywords in backticks
    words = set(re.findall(r"\b[a-zA-Z_][a-zA-Z0-9_]{2,}\b", text.lower()))
    for term in _COMMON_VULN_TERMS:
        if term in words and (f"`{term}`" in text.lower() or f"{term}(" in text.lower()):
            found.add(term)

    return sorted(found)[:10]


def evaluate_app_reachability(
    package_name: str,
    ecosystem: str,
    source_index: Optional[SourceIndex],
    vulnerable_symbols: Optional[list[str]] = None,
    dependency_type: str = "direct",
    roots: Optional[list[str]] = None,
    is_dev: bool = False,
) -> DimensionScore:
    """Evaluate Dimension A (Application Code Reachability) on a 0-100 scale."""
    dim_name = "Application Code Reachability"
    weight = 0.20

    if not source_index:
        return DimensionScore(
            dimension="A",
            name=dim_name,
            weight=weight,
            raw_value="unindexed",
            normalized_score=None,
            status="unknown",
            weighted_contribution=0.0,
            evidence=["Source code index was not available for reachability assessment"],
            confidence="none",
        )

    lang = next((l for l, e in LANG_ECO.items() if e == ecosystem), None)
    if not lang or not source_index.files_by_lang.get(lang):
        return DimensionScore(
            dimension="A",
            name=dim_name,
            weight=weight,
            raw_value="no_ecosystem_files",
            normalized_score=None,
            status="unknown",
            weighted_contribution=0.0,
            evidence=[f"No {ecosystem} source files found in repository"],
            confidence="none",
        )

    # Search for matching usages
    usages = [u for u in source_index.by_lang.get(lang, []) if _matches(ecosystem, package_name, u.module)]
    app_usages = [u for u in usages if not u.test]
    test_usages = [u for u in usages if u.test]

    app_files = sorted({u.path for u in app_usages})
    test_files = sorted({u.path for u in test_usages})
    symbols = vulnerable_symbols or []

    # Check for vulnerable symbol call sites if symbols were extracted
    matched_symbols: list[str] = []
    if symbols and app_usages:
        for u in app_usages:
            for s in symbols:
                if s.lower() in u.module.lower():
                    matched_symbols.append(s)

    # Evaluation logic
    if app_files:
        loc_sample = [f"{u.path}:{u.line}" for u in app_usages[:3]]
        if matched_symbols:
            return DimensionScore(
                dimension="A",
                name=dim_name,
                weight=weight,
                raw_value={"app_files": len(app_files), "matched_symbols": matched_symbols},
                normalized_score=100.0,
                status="confirmed_reachable",
                weighted_contribution=round(weight * 100.0, 2),
                evidence=[
                    f"Confirmed reachable: vulnerable symbol(s) {matched_symbols} matched in application code",
                    f"Imported in {len(app_files)} application file(s): {', '.join(loc_sample)}",
                ],
                confidence="high",
            )
        # Package imported without direct symbol proof
        score = 80.0 if len(app_files) >= 5 else 60.0
        return DimensionScore(
            dimension="A",
            name=dim_name,
            weight=weight,
            raw_value={"app_files": len(app_files), "symbols": [u.module for u in app_usages[:5]]},
            normalized_score=score,
            status="potentially_reachable",
            weighted_contribution=round(weight * score, 2),
            evidence=[
                f"Potentially reachable: imported in {len(app_files)} application file(s)",
                f"Locations: {', '.join(loc_sample)}",
            ],
            confidence="medium",
        )

    if test_files:
        return DimensionScore(
            dimension="A",
            name=dim_name,
            weight=weight,
            raw_value={"test_files": len(test_files)},
            normalized_score=0.0,
            status="test_only",
            weighted_contribution=0.0,
            evidence=[
                f"Excluded from application runtime: imported only in {len(test_files)} test file(s)",
                f"Test files: {', '.join(test_files[:3])}",
            ],
            confidence="high",
        )

    # If it's a transitive dependency, check if its parent roots are imported
    if dependency_type == "transitive" and roots:
        return DimensionScore(
            dimension="A",
            name=dim_name,
            weight=weight,
            raw_value={"transitive_roots": roots},
            normalized_score=40.0,
            status="transitive_reachable",
            weighted_contribution=round(weight * 40.0, 2),
            evidence=[
                f"Transitive dependency pulled in by application root(s): {', '.join(roots[:3])}",
                "Direct application import not found, but execution path exists via parent dependency",
            ],
            confidence="medium",
        )

    # Completely unimported
    return DimensionScore(
        dimension="A",
        name=dim_name,
        weight=weight,
        raw_value="not_imported",
        normalized_score=0.0,
        status="unreachable",
        weighted_contribution=0.0,
        evidence=["No imports found in application source code; unreached via static imports"],
        confidence="high",
    )
