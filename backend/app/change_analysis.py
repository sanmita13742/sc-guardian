from __future__ import annotations

import json
import re
import subprocess
from pathlib import Path
from typing import Any, Callable


DEPENDENCY_SECTIONS = ("dependencies", "devDependencies", "optionalDependencies", "peerDependencies")


def _dependencies(package_json: dict[str, Any]) -> dict[str, dict[str, str]]:
    result: dict[str, dict[str, str]] = {}
    for section in DEPENDENCY_SECTIONS:
        values = package_json.get(section) or {}
        if isinstance(values, dict):
            for name, version in values.items():
                if isinstance(name, str) and isinstance(version, str):
                    result[name] = {"version": version, "section": section}
    return result


def _numeric_version(value: str) -> tuple[int, ...] | None:
    match = re.fullmatch(r"[~^<>= ]*v?(\d+)(?:\.(\d+))?(?:\.(\d+))?(?:[-+].*)?", value.strip())
    if not match:
        return None
    return tuple(int(part or 0) for part in match.groups())


def compare_manifests(before: dict[str, Any], after: dict[str, Any]) -> list[dict[str, Any]]:
    old = _dependencies(before)
    new = _dependencies(after)
    changes: list[dict[str, Any]] = []
    for name in sorted(set(old) | set(new)):
        if name not in old:
            changes.append({"package_name": name, "change_type": "added", "before": None, "after": new[name]["version"], "section": new[name]["section"]})
        elif name not in new:
            changes.append({"package_name": name, "change_type": "removed", "before": old[name]["version"], "after": None, "section": old[name]["section"]})
        elif old[name]["version"] != new[name]["version"]:
            old_numeric = _numeric_version(old[name]["version"])
            new_numeric = _numeric_version(new[name]["version"])
            change_type = "version_changed"
            if old_numeric and new_numeric:
                change_type = "downgrade" if new_numeric < old_numeric else "upgrade" if new_numeric > old_numeric else "constraint_changed"
            elif any(token in new[name]["version"] for token in ("git+", "http:", "https:", "file:")):
                change_type = "source_changed"
            changes.append({"package_name": name, "change_type": change_type, "before": old[name]["version"], "after": new[name]["version"], "section": new[name]["section"]})
    return changes


def _git_json(run_git: Callable[[list[str]], subprocess.CompletedProcess[str]], revision: str) -> dict[str, Any] | None:
    result = run_git(["git", "show", f"{revision}:package.json"])
    if result.returncode:
        return None
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError:
        return None


def _git_lock_json(run_git: Callable[[list[str]], subprocess.CompletedProcess[str]], revision: str) -> dict[str, Any] | None:
    result = run_git(["git", "show", f"{revision}:package-lock.json"])
    if result.returncode:
        return None
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError:
        return None


def _lock_instance(lock: dict[str, Any], package_name: str) -> list[dict[str, Any]]:
    matches: list[dict[str, Any]] = []
    packages = lock.get("packages")
    if isinstance(packages, dict):
        suffix = f"node_modules/{package_name}"
        for install_path, item in packages.items():
            if isinstance(item, dict) and (install_path == suffix or install_path.endswith("/" + suffix)):
                matches.append({"install_path": install_path, "version": item.get("version"), "resolved": item.get("resolved"), "integrity": item.get("integrity")})
    dependencies = lock.get("dependencies")
    if not matches and isinstance(dependencies, dict) and isinstance(dependencies.get(package_name), dict):
        item = dependencies[package_name]
        matches.append({"install_path": f"node_modules/{package_name}", "version": item.get("version"), "resolved": item.get("resolved"), "integrity": item.get("integrity")})
    return matches


def manifest_lock_mismatches(package_json: dict[str, Any], lock: dict[str, Any]) -> list[dict[str, Any]]:
    manifest = _dependencies(package_json)
    root_lock = (lock.get("packages") or {}).get("") if isinstance(lock.get("packages"), dict) else None
    lock_declared: dict[str, Any] = {}
    if isinstance(root_lock, dict):
        for section in DEPENDENCY_SECTIONS:
            if isinstance(root_lock.get(section), dict):
                lock_declared.update(root_lock[section])
    if not lock_declared:
        lock_declared = {name: item.get("version") for name, item in (lock.get("dependencies") or {}).items() if isinstance(item, dict)}
    mismatches: list[dict[str, Any]] = []
    for name, item in manifest.items():
        if name not in lock_declared:
            mismatches.append({"package_name": name, "kind": "manifest_dependency_missing_from_lockfile", "manifest_value": item["version"]})
    return mismatches


def analyze_history(
    run_git: Callable[[list[str]], subprocess.CompletedProcess[str]],
    max_commits: int,
    osv_query: Callable[[str, str], set[str]],
    educational_context: bool,
) -> dict[str, Any]:
    log = run_git(["git", "log", f"--max-count={max_commits}", "--format=%H", "--", "package.json", "package-lock.json"])
    if log.returncode:
        return {"status": "unavailable", "warnings": ["Git dependency history could not be read"], "commits_examined": 0, "changes": [], "case_study": None}
    commits = [line.strip() for line in log.stdout.splitlines() if re.fullmatch(r"[0-9a-fA-F]{40}", line.strip())]
    all_changes: list[dict[str, Any]] = []
    warnings: list[str] = []
    case_study: dict[str, Any] | None = None
    case_score = (-1, -1, -1)
    osv_comparisons = 0
    for child in commits:
        parent_result = run_git(["git", "rev-parse", f"{child}^"])
        if parent_result.returncode:
            continue
        parent = parent_result.stdout.strip()
        before = _git_json(run_git, parent)
        after = _git_json(run_git, child)
        if before is None or after is None:
            continue
        changes = compare_manifests(before, after)
        for change in changes:
            record = {**change, "parent_sha": parent, "child_sha": child, "historical": True}
            all_changes.append(record)
            if change["change_type"] == "downgrade" and osv_comparisons < 12:
                osv_comparisons += 1
                before_version = str(change["before"]).lstrip("~^=<> ")
                after_version = str(change["after"]).lstrip("~^=<> ")
                before_ids: set[str] = set()
                after_ids: set[str] = set()
                query_status = "completed"
                try:
                    before_ids = osv_query(change["package_name"], before_version)
                    after_ids = osv_query(change["package_name"], after_version)
                except Exception as exc:
                    query_status = "unavailable"
                    warnings.append(f"OSV before/after query failed for {change['package_name']}: {exc}")
                before_lock = _git_lock_json(run_git, parent)
                after_lock = _git_lock_json(run_git, child)
                before_instances = _lock_instance(before_lock or {}, change["package_name"])
                after_instances = _lock_instance(after_lock or {}, change["package_name"])
                subject_result = run_git(["git", "show", "-s", "--format=%s", child])
                commit_subject = subject_result.stdout.strip() if not subject_result.returncode else ""
                intentional_signal = bool(re.search(r"\b(vulnerable|security training|intentional)\b", commit_subject, re.IGNORECASE))
                candidate = {
                    **record,
                    "before_advisory_ids": sorted(before_ids),
                    "after_advisory_ids": sorted(after_ids),
                    "newly_applicable_advisory_ids": sorted(after_ids - before_ids),
                    "no_longer_applicable_advisory_ids": sorted(before_ids - after_ids),
                    "osv_comparison_status": query_status,
                    "lockfile_evidence": {"before_instances": before_instances, "after_instances": after_instances},
                    "source_or_integrity_changed": any(
                        before_item.get(field) != after_item.get(field)
                        for before_item in before_instances for after_item in after_instances
                        for field in ("resolved", "integrity")
                    ),
                    "commit_subject": commit_subject,
                    "intentional_training_signal": intentional_signal,
                    "assessment": "intentional historical security regression in an educational project" if educational_context and intentional_signal else "intentional historical dependency regression documented by the commit subject" if intentional_signal else "historical dependency downgrade requiring review",
                    "malicious": False,
                }
                score = (int(intentional_signal), len(after_ids - before_ids), len(after_ids))
                if score > case_score:
                    case_score = score
                    case_study = candidate
    return {
        "schema": "nodegoat-guardian-changes-v1",
        "status": "completed" if commits else "unavailable",
        "commits_examined": len(commits),
        "dependency_change_count": len(all_changes),
        "osv_version_comparisons": osv_comparisons,
        "suspicious_change_count": sum(change["change_type"] in {"downgrade", "source_changed"} for change in all_changes),
        "changes": all_changes[:250],
        "case_study": case_study,
        "warnings": warnings,
    }


def inspect_supply_chain(repo_dir: Path) -> dict[str, Any]:
    candidates = sorted((repo_dir / ".github" / "workflows").glob("*.yml"))
    candidates += sorted((repo_dir / ".github" / "workflows").glob("*.yaml"))
    for name in ("Dockerfile", "docker-compose.yml", "docker-compose.yaml"):
        path = repo_dir / name
        if path.is_file():
            candidates.append(path)
    observations: list[dict[str, Any]] = []
    inspected: list[str] = []
    for path in candidates[:10]:
        try:
            relative = path.relative_to(repo_dir).as_posix()
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        inspected.append(relative)
        for line_number, line in enumerate(text.splitlines(), 1):
            stripped = line.strip()
            action = re.search(r"\buses:\s*([^\s#]+)", stripped)
            if action:
                value = action.group(1)
                ref = value.rsplit("@", 1)[-1] if "@" in value else ""
                pinned = bool(re.fullmatch(r"[0-9a-fA-F]{40}", ref))
                observations.append({"file": relative, "line": line_number, "kind": "github_action", "value": value, "risk_signal": None if pinned else "action reference is not pinned to a full commit SHA"})
            image = re.match(r"(?:FROM|image:)\s+([^\s#]+)", stripped, re.IGNORECASE)
            if image:
                value = image.group(1)
                observations.append({"file": relative, "line": line_number, "kind": "container_image", "value": value, "risk_signal": None if "@sha256:" in value else "container image is not pinned by digest"})
    return {
        "schema": "nodegoat-guardian-ci-inspection-v1",
        "status": "completed" if inspected else "unresolved",
        "files_inspected": inspected,
        "observations": observations,
        "risk_signal_count": sum(bool(item.get("risk_signal")) for item in observations),
        "limitations": ["Static text inspection only; no workflow or container definition was executed"],
    }


def inspect_marked_source(repo_dir: Path, commit_sha: str) -> list[dict[str, Any]]:
    targets = {
        "server.js": ("require(\"marked\")", "require('marked')", "sanitize", "app.locals.marked"),
        "app/routes/memos.js": ("/memos",),
        "app/routes/index.js": ("/memos",),
        "app/views/memos.html": ("marked(",),
    }
    evidence: list[dict[str, Any]] = []
    for relative, needles in targets.items():
        path = repo_dir / relative
        if not path.is_file():
            continue
        for line_number, line in enumerate(path.read_text(encoding="utf-8", errors="replace").splitlines(), 1):
            if any(needle in line for needle in needles):
                evidence.append({"type": "file", "path": relative, "line": line_number, "url": None, "commit_sha": commit_sha, "observation": line.strip()[:500]})
    return evidence

