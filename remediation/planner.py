"""Remediation planning: choose the *smallest safe change* per source package and prove it with a static what-if.

For each group of findings introduced by one direct dependency (``source_package_view``):

1. Direct package itself vulnerable   -> candidate upgrade >= the highest fixed version, same major first.
2. Only transitive children vulnerable -> **parent-upgrade search**: walk newer versions of the direct dependency, resolve each one's dependency tree
   (deps.dev) and re-match advisories on every node; take the first version whose tree clears the findings without introducing new HIGH/CRITICAL ones.
3. No parent version helps             -> pin the vulnerable child (npm overrides, pip constraint, Maven dependencyManagement, ...).
4. No fix exists at all               -> mitigate / block / escalate (never an invented version).

Nothing is applied: the output is a proposal (diff + rationale + rollback + measured effect) that requires human approval.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

from core.http import HttpClient
from core.repository_inspector import safe_read_text
from remediation import patchers
from remediation.versions import candidates, change_kind, list_versions
from remediation.whatif import SEV_RANK, check_nodes
from sbom.fusion.registries import DEPSDEV_SYSTEM
from sbom.fusion.resolver import _fetch
from sbom.package_extractors.common import normalize_name
from vulnerability.osv_client import OsvClient
from vulnerability.remediation_engine import OVERRIDE_HINTS
from vulnerability.version_matcher import VersionError, compare

LOCK_REGEN = {"npm": "npm install --package-lock-only   (yarn: `yarn install`, pnpm: `pnpm install --lockfile-only`)", "PyPI": "regenerate the lock: `uv lock` / `poetry lock` / `pip-compile`",
              "Maven": "no lockfile; run `mvn -q dependency:tree` to confirm the resolved versions", "Go": "go mod tidy", "crates.io": "cargo update -p <crate>",
              "Packagist": "composer update <vendor/package>", "NuGet": "dotnet restore --force-evaluate"}
ACTION_ORDER = {"upgrade": 0, "pin": 1, "remove": 2, "replace": 3, "mitigate": 4, "block": 5, "escalate": 6}


@dataclass
class PlanContext:
    repo_dir: Path
    http: HttpClient
    cache: Any
    osv: OsvClient
    vulns: list[dict]
    manifests_index: list[Any]  # core.models.ManifestFile
    components: list[Any]
    max_candidates: int = 10
    texts: dict[str, Optional[str]] = field(default_factory=dict)
    originals: dict[str, str] = field(default_factory=dict)

    def text(self, path: str) -> Optional[str]:
        if path not in self.texts:
            self.texts[path] = safe_read_text(self.repo_dir, path, max_bytes=500_000)
        return self.texts[path]


def split_label(label: str) -> tuple[str, str]:
    name, _, ver = label.rpartition("@") if "@" in label[1:] else (label, "", "")
    return (name or label), ver


def manifest_for(ctx: PlanContext, eco: str, service: str, package: str) -> Optional[tuple[str, str]]:
    """Return (manifest path, lock hint) in the service directory that can carry a change for ``package``."""
    svc = service if service not in (None, ".") else ""
    here = [m for m in ctx.manifests_index if (m.service_dir if m.service_dir != "." else "") == svc]
    names = {m.name: m.path for m in here}
    lock_hint = " ".join(m.name for m in here if m.kind == "lockfile")
    if eco == "npm" and "package.json" in names:
        return names["package.json"], lock_hint
    if eco == "PyPI":
        for m in here:
            if m.name.startswith("requirements") and m.name.endswith(".txt"):
                t = ctx.text(m.path) or ""
                if re.search(r"(?im)^\s*" + re.escape(package).replace(r"\-", "[-_.]") + r"\b", t):
                    return m.path, lock_hint
        reqs = [m.path for m in here if m.name.startswith("requirements") and m.name.endswith(".txt")]
        if reqs:
            return reqs[0], lock_hint
        if "pyproject.toml" in names:
            return names["pyproject.toml"], lock_hint
    if eco == "Maven" and "pom.xml" in names:
        return names["pom.xml"], lock_hint
    if eco == "Go" and "go.mod" in names:
        return names["go.mod"], lock_hint
    if eco == "crates.io" and "Cargo.toml" in names:
        return names["Cargo.toml"], lock_hint
    if eco == "Packagist" and "composer.json" in names:
        return names["composer.json"], lock_hint
    if eco == "NuGet":
        for m in here:
            if m.name.endswith("proj"):
                return m.path, lock_hint
    return None


def _apply(ctx: PlanContext, eco: str, service: str, changes: list[dict]) -> Optional[dict]:
    """Apply a list of {package, to, kind} to the service's manifest text; returns {path, diff, original} or None if any change cannot be expressed."""
    if not changes:
        return None
    mp = manifest_for(ctx, eco, service, changes[0]["package"])
    if not mp:
        return None
    path, hint = mp
    original = ctx.text(path)
    if original is None:
        return None
    cur = original
    for ch in changes:
        res = patchers.patch_for(eco, path, cur, ch["package"], ch["to"], ch["kind"], hint)
        if not res:
            return None
        cur = res["new_text"]
    if cur == original:
        return None
    ctx.originals[path] = original
    return {"path": path, "diff": patchers.unified_diff(path, original, cur), "new_text": cur}


def _tree_nodes(ctx: PlanContext, eco: str, name: str, ver: str) -> list[tuple[str, str, str]]:
    """(eco, name, version) of every node of the registry-resolved tree of name@ver (falls back to the package itself)."""
    if eco in DEPSDEV_SYSTEM:
        try:
            t = _fetch(ctx.http, ctx.cache, eco, name, ver)
        except Exception:
            t = None
        if t:
            return [(n.get("eco") or eco, n["name"], n["version"]) for n in t["nodes"] if n.get("version")]
    return [(eco, name, ver)]


def _ids(findings: list[dict]) -> set[str]:
    return {i for f in findings for i in (f.get("vulnerability_ids") or [f.get("primary_id")])}


def _min_fix(eco: str, findings: list[dict]) -> Optional[str]:
    fixes = [f["recommended_fix"] for f in findings if f.get("recommended_fix")]
    best: Optional[str] = None
    for v in fixes:
        try:
            if best is None or compare(eco, v, best) > 0:
                best = v
        except VersionError:
            continue
    return best


def search_upgrade(ctx: PlanContext, eco: str, name: str, cur: str, group_findings: list[dict], itself: list[dict]) -> Optional[dict]:
    """Parent-upgrade search. Returns {version, nodes, after, remaining_ids, tried} for the best candidate, or None."""
    target_ids = _ids(group_findings)
    min_version = _min_fix(eco, itself) if itself else None
    vs = list_versions(ctx.http, ctx.cache, eco, name)
    cands = candidates(eco, cur, vs, min_version=min_version)[:ctx.max_candidates]
    best = None
    tried = []
    for cand in cands:
        nodes = _tree_nodes(ctx, eco, name, cand)
        try:
            after = check_nodes(ctx.osv, nodes)
        except RuntimeError:
            return best
        remaining = {i for f in after for i in f["ids"] + [f["id"]]} & target_ids
        newhigh = [f for f in after if SEV_RANK.get(f["severity"], 0) >= 3 and not ({*f["ids"], f["id"]} & target_ids)
                   and not any(normalize_name(eco, f["package"]) == normalize_name(eco, g["package_name"]) for g in ctx.vulns)]
        tried.append({"version": cand, "remaining": len(remaining), "new_high": len(newhigh)})
        score = (len(remaining), len(newhigh))
        if best is None or score < best["score"]:
            best = {"version": cand, "nodes": nodes, "after": after, "remaining_ids": sorted(remaining), "score": score, "tried": tried}
        if not remaining and not newhigh:
            break
    if best:
        best["tried"] = tried
    return best


def plan_pins(ctx: PlanContext, eco: str, children: list[dict]) -> Optional[dict]:
    """Pin each vulnerable child to the smallest version that clears its advisories (verified against OSV)."""
    by_pkg: dict[str, list[dict]] = {}
    for f in children:
        by_pkg.setdefault(f["package_name"], []).append(f)
    pins, nodes, after_all = [], [], []
    for pkg, fs in by_pkg.items():
        cur = fs[0]["installed_version"]
        mf = _min_fix(eco, fs)
        if not mf:
            return None
        vs = list_versions(ctx.http, ctx.cache, eco, pkg)
        cands = [mf] + [v for v in candidates(eco, cur, vs, min_version=mf, same_major=4, other_major=2) if v != mf]
        ok = None
        for cand in cands[:5]:
            try:
                after = check_nodes(ctx.osv, [(eco, pkg, cand)])
            except RuntimeError:
                return None
            if not ({i for f in after for i in f["ids"] + [f["id"]]} & _ids(fs)):
                ok = (cand, after)
                break
        if not ok:
            return None
        pins.append({"package": pkg, "from": cur, "to": ok[0], "kind": "pin"})
        nodes.append((eco, pkg, ok[0]))
        after_all += ok[1]
    return {"pins": pins, "nodes": nodes, "after": after_all}


def rollback_text(eco: str, path: str, changes: list[dict]) -> list[str]:
    steps = [f"Revert the change: `git revert <commit>` or `git checkout -- {path}`.", "Restore the previous versions: " + "; ".join(f"{c['package']} {c.get('from', '?')}" for c in changes) + "."]
    if eco in LOCK_REGEN:
        steps.append("Regenerate/refresh the lockfile after reverting: " + LOCK_REGEN[eco] + ".")
    steps.append("Re-run the test suite and the Guardian scan to confirm the previous state.")
    return steps


def best_risk(findings: list[dict], risks: dict[str, dict]) -> tuple[str, str]:
    order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"]
    labs = [(risks.get(f["finding_id"]) or {}).get("label", "INFORMATIONAL") for f in findings]
    lab = min(labs, key=order.index) if labs else "INFORMATIONAL"
    pr = [(risks.get(f["finding_id"]) or {}).get("priority", "P3") for f in findings]
    return lab, min(pr) if pr else "P3"


def plan_group(ctx: PlanContext, g: dict, risks: dict[str, dict], rid: int) -> dict[str, Any]:
    fids = set(g["finding_ids"])
    findings = [f for f in ctx.vulns if f["finding_id"] in fids]
    src_name, src_ver = split_label(g["source_package"])
    eco = findings[0]["ecosystem"]
    service = next((f.get("service_dir") for f in findings if f.get("service_dir")), ".") or "."
    itself = [f for f in findings if normalize_name(eco, f["package_name"]) == normalize_name(eco, src_name)]
    children = [f for f in findings if f not in itself]
    label, priority = best_risk(findings, risks)
    fixable = [f for f in findings if f.get("fixed_versions")]
    rem: dict[str, Any] = {"id": f"REM-{rid:03d}", "source_package": g["source_package"], "root": g["root"], "ecosystem": eco, "service": service, "finding_ids": sorted(fids), "priority": priority, "risk_label": label,
                           "packages": g.get("packages", [])[:8], "alternatives": [], "sim": None}
    verdicts = {f.get("verdict") for f in findings}
    kev = any(f.get("kev") for f in findings)
    if not fixable:
        rem.update(action="block" if kev else "mitigate", title=f"No fixed version exists for {len(findings)} finding(s) in {g['source_package']}: " + ("block and escalate" if kev else "mitigate and monitor"),
                   target={"package": src_name, "from": src_ver, "to": None}, patch=None, changes=[],
                   rationale="The advisories record no fixed release. " + ("At least one finding is actively exploited (CISA KEV), so the component should be blocked until a fix exists. " if kev else "")
                             + "Options: replace the library with a maintained alternative, remove the vulnerable code path/feature, or apply the advisory's mitigation; escalate for security review.",
                   confidence="medium", rollback=["Nothing is changed by this recommendation."])
        return rem
    changes: list[dict] = []
    sim = None
    if itself or children:
        found = search_upgrade(ctx, eco, src_name, src_ver, findings, itself) if src_ver else None
        if found and not found["remaining_ids"]:
            changes = [{"package": src_name, "from": src_ver, "to": found["version"], "kind": "bump"}]
            sim = {"nodes": found["nodes"], "after": found["after"], "search": found["tried"], "mode": "upgrade"}
            rem["action"] = "upgrade"
        elif children and not itself:
            pins = plan_pins(ctx, eco, children)
            if pins:
                changes = pins["pins"]
                sim = {"nodes": pins["nodes"], "after": pins["after"], "search": found["tried"] if found else [], "mode": "pin"}
                rem["action"] = "pin"
            elif found:
                changes = [{"package": src_name, "from": src_ver, "to": found["version"], "kind": "bump"}]
                sim = {"nodes": found["nodes"], "after": found["after"], "search": found["tried"], "mode": "upgrade"}
                rem["action"] = "upgrade"
        elif found:
            changes = [{"package": src_name, "from": src_ver, "to": found["version"], "kind": "bump"}]
            sim = {"nodes": found["nodes"], "after": found["after"], "search": found["tried"], "mode": "upgrade"}
            rem["action"] = "upgrade"
    if not changes:
        rem.update(action="escalate", title=f"No safe automatic change found for {g['source_package']}", target={"package": src_name, "from": src_ver, "to": None}, patch=None, changes=[],
                   rationale="No newer version of the direct dependency clears the findings without leaving some behind, and a verified pin was not possible. Review manually.", confidence="low",
                   rollback=["Nothing is changed by this recommendation."])
        return rem
    ch0 = changes[0]
    kind = change_kind(ch0.get("from", ""), ch0["to"])
    patch = _apply(ctx, eco, service, changes)
    first = "pin" if rem["action"] == "pin" else "bump"
    rem.update(title=(f"Upgrade {src_name} {src_ver} -> {ch0['to']}" if rem["action"] == "upgrade" else f"Pin {', '.join(c['package'] + ' to ' + c['to'] for c in changes[:3])}" + (" ..." if len(changes) > 3 else "")),
               target={"package": ch0["package"], "from": ch0.get("from"), "to": ch0["to"], "ecosystem": eco}, changes=changes, sim=sim, patch=patch,
               compatibility={"semver_change": kind, "breaking_risk": "high" if kind == "major" else "medium" if kind == "minor" else "low" if kind == "patch" else "unknown",
                              "note": ("Major version change: read the release notes and run the full test suite." if kind == "major" else "Compatibility within the same major line is expected but not verified by this scan.") if first == "bump"
                              else "A pin forces a version the parent did not declare compatibility with; run the tests."},
               rollback=rollback_text(eco, patch["path"] if patch else "the manifest", changes),
               lock_note=LOCK_REGEN.get(eco), confidence="high" if patch and sim and not sim["after"] else "medium" if patch else "low")
    reach = {(f.get("reachability") or {}).get("status") for f in findings}
    if reach <= {"not_imported", "used_in_tests_only", None} and verdicts <= {"no_import_evidence", "test_only"}:
        rem["alternatives"].append({"action": "remove", "note": f"No application import of {src_name} (or its children) was found; if it is an unused or dev-only tool, removing it eliminates all {len(findings)} finding(s) with no upgrade risk."})
    if eco in OVERRIDE_HINTS:
        rem["alternatives"].append({"action": "manual", "note": OVERRIDE_HINTS[eco]})
    return rem
