"""Modified-lockfile detector based on real Git history.

For each analysed commit the lockfiles changed against a baseline (the commit's parent by default, or an explicit
baseline ref) are parsed with the ecosystem parsers on both sides and diffed per package. Every change is classified:

* ``normal_update``          version/membership change consistent with a manifest change or a dependency cascade
* ``unexplained_change``     lockfile change that the same commit does not explain (verify; common with `npm update`)
* ``potentially_suspicious`` integrity/source anomalies (hash changed for the same version, non-registry source, ...)
* ``insufficient_baseline``  no parent / shallow boundary / baseline not found -> nothing is invented

A lockfile change is never reported as "malicious".
"""
from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any, Optional

from config.constants import MANIFEST_FILES, MANIFEST_SUFFIXES
from core import git_manager as gm
from core.models import LockDependency
from sbom.lockfile_analyzer import SIBLINGS, parse_text, parser_for
from sbom.package_extractors.common import host_of, normalize_name
from suspicious_changes.suspicious_models import LockfileChange
from vulnerability.version_matcher import VersionError, compare

# files whose diffs we treat as *lockfiles* (resolved state). pom.xml / package.json are *manifests*.
LOCKFILE_NAMES = {n for n, (k, _) in MANIFEST_FILES.items() if k == "lockfile" and n not in ("go.mod",)}
MANIFEST_NAMES = {n for n, (k, _) in MANIFEST_FILES.items() if k == "manifest"}
MAX_CHANGES_PER_FILE = 300


def _is_lockfile(name: str) -> bool:
    if name in LOCKFILE_NAMES or (name.startswith("requirements") and name.endswith(".txt")):
        return True
    return False


def _is_manifest(name: str) -> bool:
    return name in MANIFEST_NAMES or os.path.splitext(name)[1].lower() in MANIFEST_SUFFIXES


def _index(deps: list[LockDependency]) -> dict[tuple[str, str], list[LockDependency]]:
    idx: dict[tuple[str, str], list[LockDependency]] = {}
    for d in deps:
        idx.setdefault((d.ecosystem, normalize_name(d.ecosystem, d.name)), []).append(d)
    return idx


def _snap(d: Optional[LockDependency]) -> dict[str, Any]:
    if d is None:
        return {}
    return {"version": d.version, "integrity": d.integrity, "resolved": d.resolved, "source_type": d.source_type,
            "direct": d.direct, "record": d.record}


def _sibling_texts(repo: Path, sha: str, path: str) -> dict[str, Optional[str]]:
    name = path.rsplit("/", 1)[-1]
    sib = {}
    for kw, sib_name in SIBLINGS.get(name, {}).items():
        rel = path.rsplit("/", 1)[0] + "/" + sib_name if "/" in path else sib_name
        sib[kw] = gm.show_file(repo, sha, rel)
    return sib


def _diff_excerpt(repo: Path, base: str, head: str, path: str, needles: list[str], limit: int = 12) -> list[str]:
    """Changed (+/-) lines of every diff hunk in which the package name appears (context lines count for the match)."""
    text = gm.diff_text(repo, base, head, path, context=4)
    needles = [n for n in needles if n]
    out: list[str] = []
    for hunk in re.split(r"(?m)^@@.*@@.*$", text)[1:]:
        lines = hunk.splitlines()
        if not any(n in ln for ln in lines for n in needles):
            continue
        for ln in lines:
            if ln[:1] in ("+", "-") and not ln.startswith(("+++", "---")):
                out.append(ln[:220])
                if len(out) >= limit:
                    return out
    return out


def _cmp(eco: str, a: Optional[str], b: Optional[str]) -> Optional[int]:
    if not a or not b:
        return None
    try:
        return compare(eco, a, b)
    except VersionError:
        return None


def detect_lockfile_changes(repo: Path, head: str = "HEAD", baseline: str | None = None, commits: int = 1,
                            scan_timestamp: str = "") -> dict[str, Any]:
    """Analyse ``commits`` most recent commits ending at ``head``. ``baseline`` applies to the first commit only."""
    repo = Path(repo)
    result: dict[str, Any] = {"changes": [], "findings": [], "comparisons": [], "limitations": [], "head": None,
                              "shallow": False, "files_examined": 0}
    try:
        head_sha = gm.run_git(["rev-parse", "--verify", head + "^{commit}"], cwd=repo).stdout.strip()
    except gm.GitError as e:
        result["limitations"].append(f"Selected revision could not be resolved: {e}")
        return result
    result["head"] = head_sha
    result["shallow"] = gm.is_shallow(repo)
    shas = gm.recent_commits(repo, max(1, commits), head_sha)
    all_changes: list[LockfileChange] = []
    for i, sha in enumerate(shas):
        explicit = baseline if (i == 0 and baseline) else None
        if explicit:
            try:
                base = gm.run_git(["rev-parse", "--verify", explicit + "^{commit}"], cwd=repo).stdout.strip()
                mode = "explicit"
            except gm.GitError:
                result["limitations"].append(f"Baseline '{explicit}' was not found in the available history.")
                all_changes.append(_insufficient(sha, explicit, "explicit", repo, f"baseline '{explicit}' not found in the available (possibly shallow) history", scan_timestamp))
                result["comparisons"].append({"commit": sha, "baseline": None, "mode": "explicit", "status": "insufficient_baseline"})
                continue
        else:
            base, mode = gm.parent_sha(repo, sha), "parent"
        if not base:
            why = ("shallow clone boundary: the parent commit is not available locally" if result["shallow"]
                   else "root commit has no parent to compare against")
            result["limitations"].append(f"Commit {sha[:10]}: {why}.")
            all_changes.append(_insufficient(sha, "(none)", "parent", repo, why, scan_timestamp))
            result["comparisons"].append({"commit": sha, "baseline": None, "mode": mode, "status": "insufficient_baseline", "reason": why})
            continue
        all_changes.extend(_compare_commits(repo, base, sha, mode, scan_timestamp, result))
    result["changes"] = [c.model_dump() for c in all_changes]
    flagged = [c for c in all_changes if c.classification != "normal_update"]
    for n, c in enumerate(flagged, 1):
        c.finding_id = f"LOCK-{n:03d}"
    for n, c in enumerate(all_changes, 1):
        if not c.finding_id:
            c.finding_id = f"CHG-{n:03d}"
    result["changes"] = [c.model_dump() for c in all_changes]
    result["findings"] = [c.model_dump() for c in flagged]
    result["summary"] = {
        "commits_analysed": len(shas), "total_changes": len(all_changes),
        "normal_update": sum(c.classification == "normal_update" for c in all_changes),
        "unexplained_change": sum(c.classification == "unexplained_change" for c in all_changes),
        "potentially_suspicious": sum(c.classification == "potentially_suspicious" for c in all_changes),
        "insufficient_baseline": sum(c.classification == "insufficient_baseline" for c in all_changes),
    }
    return result


def _insufficient(sha, base, mode, repo, why, ts) -> LockfileChange:
    return LockfileChange(commit=sha, baseline=base, baseline_mode=mode, commit_info=gm.commit_info(repo, sha), file="(n/a)",
                          ecosystem="n/a", package_name="(no comparison possible)", change_type="unparseable",
                          classification="insufficient_baseline", reasons=[f"No valid comparison baseline: {why}. No result was inferred."],
                          scan_timestamp=ts)


def _compare_commits(repo: Path, base: str, sha: str, mode: str, ts: str, result: dict) -> list[LockfileChange]:
    changed = gm.changed_files(repo, base, sha)
    info = gm.commit_info(repo, sha)
    lock_changes = [(st, p) for st, p in changed if _is_lockfile(p.rsplit("/", 1)[-1])]
    manifest_changed = [p for st, p in changed if _is_manifest(p.rsplit("/", 1)[-1])]
    result["files_examined"] += len(lock_changes)
    result["comparisons"].append({"commit": sha, "baseline": base, "mode": mode, "status": "compared",
                                  "lockfiles_changed": [p for _, p in lock_changes], "manifests_changed": manifest_changed,
                                  "commit_info": info})
    out: list[LockfileChange] = []

    def mk(**kw) -> LockfileChange:
        return LockfileChange(commit=sha, baseline=base, baseline_mode=mode, commit_info=info, scan_timestamp=ts, **kw)

    for status, path in lock_changes:
        name = path.rsplit("/", 1)[-1]
        folder = path.rsplit("/", 1)[0] if "/" in path else "."
        eco = (MANIFEST_FILES.get(name) or ("", "PyPI" if name.startswith("requirements") else "unknown"))[1]
        same_dir_manifests = [m for m in manifest_changed if (m.rsplit("/", 1)[0] if "/" in m else ".") == folder]
        if parser_for(name) is None:
            continue
        if status == "D":
            out.append(mk(file=path, ecosystem=eco, package_name="(entire lockfile)", change_type="lockfile_removed",
                          classification="unexplained_change", signals=["lockfile_removed"], manifest_changed=bool(same_dir_manifests),
                          manifest_files_changed=same_dir_manifests,
                          reasons=["The lockfile was deleted. Without it, resolved versions and integrity hashes are no longer pinned; "
                                   "this can be intentional (tooling change) but should be confirmed."], evidence_strength="medium"))
            continue
        new_txt = gm.show_file(repo, sha, path)
        old_txt = gm.show_file(repo, base, path) if status != "A" else None
        try:
            new = parse_text(name, new_txt or "", path, folder, _sibling_texts(repo, sha, path)) if new_txt is not None else []
            old = parse_text(name, old_txt, path, folder, _sibling_texts(repo, base, path)) if old_txt is not None else []
        except Exception as e:
            out.append(mk(file=path, ecosystem=eco, package_name="(lockfile)", change_type="unparseable",
                          classification="insufficient_baseline", reasons=[f"Lockfile could not be parsed on one side of the comparison ({type(e).__name__}); no result inferred."]))
            continue
        if status == "A":
            out.append(mk(file=path, ecosystem=eco, package_name="(entire lockfile)", change_type="lockfile_added",
                          classification="normal_update", signals=["lockfile_added"], manifest_changed=bool(same_dir_manifests),
                          manifest_files_changed=same_dir_manifests,
                          reasons=[f"A new lockfile with {len(new)} entries was added; entries are checked below for non-registry sources."]))
        oi, ni = _index(old), _index(new)
        if status == "A":  # a brand-new lockfile: only report entries with non-registry sources, not every package
            ni = {k: v for k, v in ni.items() if any(d.source_type in ("git", "url", "path") for d in v)}
        changed_names: set[str] = set()
        records: list[dict] = []
        for key in sorted(set(oi) | set(ni)):
            o_list, n_list = oi.get(key, []), ni.get(key, [])
            o_vers = {d.version for d in o_list}
            n_vers = {d.version for d in n_list}
            if o_list and n_list and o_vers == n_vers:
                # same versions: look at integrity / source drift
                for nd in n_list:
                    od = next((d for d in o_list if d.version == nd.version), None)
                    if not od:
                        continue
                    if od.integrity and nd.integrity and od.integrity != nd.integrity:
                        records.append({"key": key, "type": "integrity_changed", "old": od, "new": nd})
                    elif od.integrity and not nd.integrity:
                        records.append({"key": key, "type": "integrity_removed", "old": od, "new": nd})
                    elif (od.source_type, host_of(od.resolved)) != (nd.source_type, host_of(nd.resolved)) and (od.resolved or nd.resolved):
                        records.append({"key": key, "type": "source_changed", "old": od, "new": nd})
                continue
            if not o_list:
                records.append({"key": key, "type": "added", "old": None, "new": n_list[0], "all_new": n_list})
            elif not n_list:
                records.append({"key": key, "type": "removed", "old": o_list[0], "new": None})
            else:
                records.append({"key": key, "type": "version_changed", "old": o_list[0], "new": n_list[0],
                                "old_versions": sorted(v or "" for v in o_vers), "new_versions": sorted(v or "" for v in n_vers)})
            changed_names.add(key[1])
        # packages that gained/changed entries -> candidates for "explained by cascade"
        cascade_requires = {r for d in new if normalize_name(d.ecosystem, d.name) in changed_names for r in d.requires}
        direct_changed = [r for r in records if r["new"] is not None and r["new"].direct and r["type"] in ("added", "version_changed")]
        for r in records[:MAX_CHANGES_PER_FILE]:
            eco_k, nm = r["key"]
            od, nd = r["old"], r["new"]
            display = (nd or od).name
            signals: list[str] = []
            reasons: list[str] = []
            suspicious = False
            unexplained = False
            manifest_mentions = False
            if same_dir_manifests:
                for m in same_dir_manifests:
                    mt = gm.diff_text(repo, base, sha, m)
                    if display.lower() in mt.lower():
                        manifest_mentions = True
                        break
            ctype = r["type"]
            if ctype == "integrity_changed":
                suspicious = True
                signals.append("integrity_changed_same_version")
                reasons.append(f"The integrity hash of {display}@{nd.version} changed although the version did not "
                               f"({_short(od.integrity)} -> {_short(nd.integrity)}). A republished or tampered artifact looks like this; "
                               "registry re-publishing and lockfile format migrations can also cause it.")
            elif ctype == "integrity_removed":
                suspicious = True
                signals.append("integrity_removed")
                reasons.append(f"{display}@{nd.version} previously had an integrity hash; the new lockfile has none, which weakens tamper detection.")
            elif ctype == "source_changed":
                suspicious = True
                signals.append("source_changed")
                reasons.append(f"The resolved source of {display}@{nd.version} changed ({od.source_type}:{host_of(od.resolved)} -> {nd.source_type}:{host_of(nd.resolved)}).")
            if nd is not None and ctype in ("added", "version_changed") and nd.source_type in ("git", "url", "path"):
                if not (od is not None and od.source_type == nd.source_type and host_of(od.resolved) == host_of(nd.resolved)):
                    suspicious = True
                    signals.append(f"non_registry_source_{nd.source_type}")
                    reasons.append(f"{display} is resolved from a non-registry {nd.source_type} source ({_short(nd.resolved, 80)}) instead of the package registry.")
            if (od is not None and nd is not None and ctype == "version_changed" and od.source_type == "registry" and nd.source_type == "registry"
                    and host_of(od.resolved) and host_of(nd.resolved) and host_of(od.resolved) != host_of(nd.resolved)):
                suspicious = True
                signals.append("registry_host_changed")
                reasons.append(f"The registry host changed from {host_of(od.resolved)} to {host_of(nd.resolved)}.")
            if ctype == "version_changed":
                c = _cmp(eco_k, nd.version, od.version)
                if c is not None and c < 0:
                    signals.append("downgrade")
                    reasons.append(f"Version moved backwards ({od.version} -> {nd.version}).")
                    if not manifest_mentions:
                        unexplained = True
                elif c is not None and c > 0:
                    reasons.append(f"Version upgraded ({od.version} -> {nd.version}).")
                else:
                    reasons.append(f"Version set changed ({', '.join(r.get('old_versions', []))} -> {', '.join(r.get('new_versions', []))}).")
            elif ctype == "added":
                reasons.append(f"New package {display}@{nd.version} entered the lockfile.")
            elif ctype == "removed":
                reasons.append(f"{display}@{od.version} was removed from the lockfile.")
            # explanation logic (only matters if nothing suspicious was found)
            if not suspicious:
                is_direct = bool((nd and nd.direct) or (od and od.direct))
                if manifest_mentions:
                    reasons.append("The same commit also modifies a manifest that mentions this package, which explains the change.")
                elif ctype in ("added", "version_changed") and is_direct and not same_dir_manifests:
                    unexplained = True
                    signals.append("direct_dependency_changed_without_manifest_change")
                    reasons.append("A direct dependency changed in the lockfile but no manifest in the same directory changed in this commit "
                                   "(possible `update`/`audit fix` run; verify the update was intended).")
                elif ctype == "added" and not is_direct and nm not in cascade_requires and not same_dir_manifests and not direct_changed:
                    unexplained = True
                    signals.append("new_package_without_dependent")
                    reasons.append("A new package appeared with no changed parent requiring it and no manifest change.")
                elif ctype in ("added", "version_changed", "removed"):
                    reasons.append("Consistent with a normal dependency update/cascade (transitive change alongside other dependency changes).")
            cls = "potentially_suspicious" if suspicious else "unexplained_change" if unexplained else "normal_update"
            strength = ("high" if any(s in signals for s in ("integrity_changed_same_version", "non_registry_source_git", "non_registry_source_url")) and not manifest_mentions
                        else "medium" if suspicious else "low")
            sev = {"potentially_suspicious": "HIGH" if strength == "high" else "MEDIUM", "unexplained_change": "LOW"}.get(cls)
            needles = [display, (nd.version if nd else None) or "", (od.version if od else None) or ""]
            out.append(mk(file=path, ecosystem=eco_k, package_name=display, change_type=ctype, previous=_snap(od), new=_snap(nd),
                          manifest_changed=bool(same_dir_manifests), manifest_files_changed=same_dir_manifests, classification=cls,
                          signals=signals, reasons=reasons, evidence_strength=strength,
                          diff_excerpt=_diff_excerpt(repo, base, sha, path, [display]), severity=sev))
        if len(records) > MAX_CHANGES_PER_FILE:
            result["limitations"].append(f"{path}: {len(records) - MAX_CHANGES_PER_FILE} further changes omitted (limit {MAX_CHANGES_PER_FILE}).")
    return out


def _short(s: Optional[str], n: int = 28) -> str:
    return "none" if not s else (s if len(s) <= n else s[:n] + "...")
