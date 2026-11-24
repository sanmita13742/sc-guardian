"""Code reachability impact evaluation for remediation library versions.

Analyzes how upgrading a dependency from version A to B affects the application's
active import paths, submodules, and call surface.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, Optional

from reachability.scanners import LANG_ECO, SourceIndex, Usage, _matches
from remediation.versions import change_kind


@dataclass
class CodeReachabilityImpact:
    source_package: str
    from_version: str
    to_version: str
    semver_change: str  # "patch", "minor", "major", "pin", "none", "unknown"
    status: str  # "safe_preserved", "potential_api_shift", "major_breaking_risk", "isolated_unused", "unknown"
    app_files_affected: list[str] = field(default_factory=list)
    test_files_affected: list[str] = field(default_factory=list)
    imported_symbols: list[str] = field(default_factory=list)
    reachability_preservation_score: int = 100  # 0 to 100
    impact_summary: str = ""
    recommendation: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def evaluate_reachability_impact(
    idx: Optional[SourceIndex],
    eco: str,
    package_name: str,
    from_version: str,
    to_version: str,
    semver_delta: Optional[str] = None,
) -> CodeReachabilityImpact:
    """Evaluate how far upgrading ``package_name`` from ``from_version`` to ``to_version`` affects application imports."""
    semver = semver_delta or change_kind(from_version, to_version)

    if not idx:
        return CodeReachabilityImpact(
            source_package=package_name,
            from_version=from_version,
            to_version=to_version,
            semver_change=semver,
            status="unknown",
            impact_summary="Source code index was not available; reachability impact could not be evaluated statically.",
            recommendation="Review package release notes before deploying.",
            reachability_preservation_score=80,
        )

    lang = next((l for l, e in LANG_ECO.items() if e == eco), None)
    if not lang or not idx.files_by_lang.get(lang):
        return CodeReachabilityImpact(
            source_package=package_name,
            from_version=from_version,
            to_version=to_version,
            semver_change=semver,
            status="unknown",
            impact_summary=f"No {eco} source files analyzed in this project.",
            recommendation="Verify import compatibility manually.",
            reachability_preservation_score=85,
        )

    usages = [u for u in idx.by_lang.get(lang, []) if _matches(eco, package_name, u.module)]
    app_usages = [u for u in usages if not u.test]
    test_usages = [u for u in usages if u.test]

    app_files = sorted({u.path for u in app_usages})
    test_files = sorted({u.path for u in test_usages})
    symbols = sorted({u.module for u in (app_usages + test_usages)})[:15]

    app_count = len(app_files)

    if app_count == 0:
        if len(test_files) > 0:
            status = "isolated_test_only"
            score = 98
            summary = (
                f"{package_name} is only imported in {len(test_files)} test file(s); "
                f"the upgrade from {from_version} to {to_version} ({semver}) has zero production runtime exposure."
            )
            rec = "Run automated test suite after upgrading to ensure test helpers remain compatible."
        else:
            status = "isolated_unused"
            score = 100
            summary = (
                f"No static imports of {package_name} were found in the codebase. "
                f"Upgrading from {from_version} to {to_version} carries zero direct import breakage risk."
            )
            rec = "Clean upgrade or consider removing the dependency if completely unused."
    elif semver in ("patch", "pin", "none"):
        status = "safe_preserved"
        score = 98
        summary = (
            f"All {app_count} application file(s) importing {package_name} use standard module paths. "
            f"Patch upgrade ({from_version} -> {to_version}) preserves API signatures and call surfaces."
        )
        rec = "Safe to apply with standard automated verification."
    elif semver == "minor":
        status = "safe_preserved"
        score = 92
        summary = (
            f"Minor version upgrade ({from_version} -> {to_version}) across {app_count} application file(s). "
            f"Backward compatibility is typically maintained according to SemVer."
        )
        rec = "Apply and review lockfile diff; verify unit test execution."
    elif semver == "major":
        if app_count >= 5:
            status = "major_breaking_risk"
            score = 65
            summary = (
                f"Major version upgrade ({from_version} -> {to_version}) with HEAVY application usage "
                f"across {app_count} files ({', '.join(symbols[:3])}). High probability of breaking API changes or removed methods."
            )
            rec = "Review migration guide and breaking changes before committing; execute sandbox integration tests."
        else:
            status = "potential_api_shift"
            score = 75
            summary = (
                f"Major version upgrade ({from_version} -> {to_version}) affecting {app_count} file(s). "
                f"Imported symbols ({', '.join(symbols[:4])}) may require migration if APIs were deprecated."
            )
            rec = "Inspect imported call sites and run tests before deployment."
    else:
        status = "potential_api_shift"
        score = 80
        summary = f"Version change ({from_version} -> {to_version}) across {app_count} application file(s)."
        rec = "Perform standard verification."

    return CodeReachabilityImpact(
        source_package=package_name,
        from_version=from_version,
        to_version=to_version,
        semver_change=semver,
        status=status,
        app_files_affected=app_files,
        test_files_affected=test_files,
        imported_symbols=symbols,
        reachability_preservation_score=score,
        impact_summary=summary,
        recommendation=rec,
    )
