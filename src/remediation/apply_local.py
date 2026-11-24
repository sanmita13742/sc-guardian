"""Apply an accepted remediation directly to a local project folder (coding-agent style), with backup and undo.

Used when the scanned project came from a folder path instead of a GitHub URL: there is no PR to open, so accepting a
proposal edits the real files. Steps: apply the manifest patch, back up every touched file first, then refresh the lockfile
with the ecosystem's package manager (scripts disabled) so that a rescan no longer reports the fixed advisories.
Nothing is committed, no branch is created and the working branch is never switched.
Backups and undo records are kept outside the project, in ~/.sc-guardian/local-changes/.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import time
from pathlib import Path
from typing import Any, Optional

from sbom.tool_locator import find_tool

_HUNK = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")


def _store(root: Path) -> Path:
    """Backups and undo records live outside the project (so scanners never see the backup copies)."""
    h = hashlib.sha1(str(Path(root).resolve()).lower().encode("utf-8")).hexdigest()[:16]
    return Path(os.environ.get("SC_GUARDIAN_HOME") or (Path.home() / ".sc-guardian")) / "local-changes" / h


class ApplyError(Exception):
    pass


# --------------------------------------------------------------------------------------------- unified diff
def _parse(diff: str) -> list[tuple[str, list[tuple[int, list[str]]]]]:
    """Return [(relative path, [(old_start, hunk_lines)])] for a unified diff (a/<path> b/<path> headers)."""
    files: list[tuple[str, list]] = []
    cur: Optional[list] = None
    hunk: Optional[list[str]] = None
    for ln in diff.splitlines():
        if ln.startswith("+++ "):
            p = ln[4:].split("\t")[0].strip()
            p = p[2:] if p.startswith("b/") else p
            cur = []
            files.append((p, cur))
            hunk = None
        elif ln.startswith("--- "):
            hunk = None
        elif ln.startswith("@@") and cur is not None:
            m = _HUNK.match(ln)
            if not m:
                raise ApplyError(f"unreadable hunk header: {ln[:60]}")
            hunk = []
            cur.append((int(m.group(1)), hunk))
        elif hunk is not None and ln[:1] in (" ", "+", "-"):
            hunk.append(ln)
        elif hunk is not None and ln.startswith("\\"):
            continue  # "\ No newline at end of file"
    return files


def apply_unified(old: str, hunks: list[tuple[int, list[str]]]) -> str:
    """Apply hunks to ``old``; every context/removed line must match exactly, otherwise ApplyError (nothing is guessed)."""
    src = old.split("\n")
    out: list[str] = []
    pos = 0  # index into src
    for start, lines in hunks:
        begin = max(start - 1, 0) if any(l[:1] != "+" for l in lines) else start
        if begin < pos:
            raise ApplyError("overlapping hunks")
        out.extend(src[pos:begin])
        pos = begin
        for l in lines:
            tag, text = l[:1], l[1:]
            if tag == "+":
                out.append(text)
            else:
                if pos >= len(src) or src[pos] != text:
                    raise ApplyError("the file no longer matches the scanned version (it changed since the scan)")
                if tag == " ":
                    out.append(text)
                pos += 1
    out.extend(src[pos:])
    return "\n".join(out)


def _safe(root: Path, rel: str) -> Path:
    p = (root / rel).resolve()
    if root.resolve() not in p.parents:
        raise ApplyError(f"refusing to touch a path outside the project: {rel}")
    return p


# --------------------------------------------------------------------------------------------- npm override repair
_DEP_SECTIONS = ("dependencies", "devDependencies", "optionalDependencies")


def _ver_tuple(spec: str) -> tuple[int, ...]:
    return tuple(int(x) for x in re.findall(r"\d+", spec)[:3]) or (0,)


def normalize_npm_overrides(pkg_json: Path) -> list[dict]:
    """npm refuses an ``overrides`` entry that differs from the same package's direct dependency spec (EOVERRIDE). Repair each such entry
    the way npm documents it: keep the pinned security floor on the direct dependency and make the override a ``$name`` reference.
    Returns the changes made (empty = nothing to repair)."""
    from remediation.patchers import _json_dump
    text = pkg_json.read_text(encoding="utf-8")
    try:
        data = json.loads(text)
    except ValueError:
        return []
    ov = data.get("overrides")
    if not isinstance(data, dict) or not isinstance(ov, dict):
        return []
    changes: list[dict] = []
    for name, val in list(ov.items()):
        if not isinstance(val, str) or val.startswith("$"):
            continue
        for sec in _DEP_SECTIONS:
            deps = data.get(sec) or {}
            cur = deps.get(name)
            if not isinstance(cur, str) or cur == val:
                continue
            after = cur
            m = re.match(r"^[v=]?(\d+\.\d+\.\d+(?:[-+][\w.]+)?)$", val.strip())
            if m and _ver_tuple(m.group(1)) > _ver_tuple(cur):  # keep the security floor the override expressed
                after = ("~" if cur.startswith("~") else "^") + m.group(1)
            deps[name] = after
            ov[name] = f"${name}"
            changes.append({"package": name, "direct_before": cur, "direct_after": after, "override_before": val, "override_after": f"${name}"})
            break
    if changes:
        pkg_json.write_text(_json_dump(data, text), encoding="utf-8")
    return changes


# --------------------------------------------------------------------------------------------- lockfile refresh
def _lock_command(eco: str, rem: dict, mdir: Path) -> Optional[tuple[list[str], str]]:
    """(argv, display) to refresh the lockfile next to the changed manifest, or None when the ecosystem needs none/has no safe command."""
    has = lambda n: (mdir / n).exists()  # noqa: E731
    pkg = ((rem.get("target") or {}).get("package") or rem.get("package") or rem.get("source_package") or "").strip()
    if eco == "npm":
        if has("package-lock.json") or has("npm-shrinkwrap.json"):
            return ["npm", "install", "--package-lock-only", "--ignore-scripts", "--no-audit", "--no-fund"], "npm install --package-lock-only --ignore-scripts"
        if has("pnpm-lock.yaml"):
            return ["pnpm", "install", "--lockfile-only", "--ignore-scripts"], "pnpm install --lockfile-only --ignore-scripts"
        if has("yarn.lock"):
            return ["yarn", "install", "--mode", "update-lockfile", "--mode", "skip-build"], "yarn install --mode update-lockfile"
    elif eco == "Go" and has("go.sum"):
        return ["go", "mod", "tidy"], "go mod tidy"
    elif eco == "crates.io" and has("Cargo.lock") and pkg:
        return ["cargo", "update", "-p", pkg], f"cargo update -p {pkg}"
    elif eco == "Packagist" and has("composer.lock") and pkg:
        return ["composer", "update", pkg, "--no-scripts", "--no-plugins", "--no-interaction"], f"composer update {pkg} --no-scripts"
    elif eco == "PyPI":
        if has("poetry.lock"):
            return ["poetry", "lock"], "poetry lock"
        if has("uv.lock"):
            return ["uv", "lock"], "uv lock"
    return None


def _refresh_lock(eco: str, rem: dict, mdir: Path, backups: dict[str, Path], root: Path, bdir: Path) -> dict[str, Any]:
    cmd = _lock_command(eco, rem, mdir)
    if not cmd:
        return {"status": "not_needed", "note": "no lockfile for this manifest (or none that can be refreshed safely); the pinned manifest is what a rescan reads"}
    argv, shown = cmd
    exe = find_tool(argv[0])
    if not exe:
        return {"status": "tool_missing", "command": shown, "note": f"`{argv[0]}` is not installed; run `{shown}` in `{mdir}` to finish"}
    for lock in ("package-lock.json", "npm-shrinkwrap.json", "pnpm-lock.yaml", "yarn.lock", "go.sum", "go.mod", "Cargo.lock", "composer.lock", "poetry.lock", "uv.lock"):
        f = mdir / lock
        if f.exists():
            rel = f.relative_to(root).as_posix()
            if rel not in backups:
                dest = bdir / rel
                dest.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(f, dest)
                backups[rel] = dest
    def _run() -> subprocess.CompletedProcess:
        return subprocess.run([exe, *argv[1:]], cwd=str(mdir), capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=300, shell=False,
                              env={**os.environ, "npm_config_ignore_scripts": "true", "CI": "1"})
    normalized: list[dict] = []
    try:
        p = _run()
        if p.returncode != 0 and eco == "npm" and "EOVERRIDE" in (p.stderr or p.stdout) and (mdir / "package.json").exists():
            normalized = normalize_npm_overrides(mdir / "package.json")
            if normalized:
                p = _run()
    except subprocess.TimeoutExpired:
        return {"status": "failed", "command": shown, "note": f"`{shown}` timed out; run it manually in `{mdir}`"}
    except OSError as e:
        return {"status": "failed", "command": shown, "note": str(e)}
    if p.returncode == 0 and normalized:
        return {"status": "refreshed", "command": shown, "normalized": normalized,
                "note": "lockfile refreshed after repairing conflicting overrides: "
                        + "; ".join(f"{c['package']} (override {c['override_before']} -> {c['override_after']}, direct {c['direct_before']} -> {c['direct_after']})" for c in normalized)}
    if p.returncode != 0:
        err = (p.stderr or p.stdout).strip()
        m = re.search(r"Override for (\S+?)@(\S+) conflicts with direct dependency", err)
        if "EOVERRIDE" in err and m:
            return {"status": "failed", "command": shown, "kind": "override_conflict",
                    "note": f"npm refuses this project's package.json: `{m.group(1)}` is in `overrides` and is also a direct dependency declared as `{m.group(2)}`. "
                            f"Make them agree first (set the override to \"${m.group(1)}\" or change the direct dependency), then re-validate"}
        return {"status": "failed", "command": shown, "note": f"`{shown}` exited {p.returncode}: {err[-300:]}"}
    return {"status": "refreshed", "command": shown, "note": f"lockfile refreshed with `{shown}`"}


# --------------------------------------------------------------------------------------------- public API
def _state_file(root: Path, rid: str) -> Path:
    return _store(root) / "applied" / f"{re.sub(r'[^A-Za-z0-9_.-]', '_', rid)}.json"


def applied_record(root: Path | str, rem: dict) -> Optional[dict]:
    f = _state_file(Path(root), rem["id"])
    try:
        return json.loads(f.read_text(encoding="utf-8")) if f.exists() else None
    except (OSError, ValueError):
        return None


def apply_in_place(root: Path | str, rem: dict, repo: dict | None = None) -> dict[str, Any]:
    """Edit the project's files for ``rem``. Returns {status: success|error, files, lock, backup_dir, ...}."""
    root = Path(root).resolve()
    diff = (rem.get("patch") or {}).get("diff")
    if not diff:
        return {"status": "error", "error": f"Proposal '{rem.get('id')}' ({rem.get('action', 'remediation')}) has no automated patch; follow the rationale for a manual change."}
    if not root.is_dir():
        return {"status": "error", "error": f"Project folder not found: {root}"}
    if applied_record(root, rem):
        return {"status": "error", "error": "This proposal was already applied. Use Undo to revert it first."}
    stamp = time.strftime("%Y%m%dT%H%M%S")
    bdir = _store(root) / "backups" / f"{rem['id']}-{stamp}"
    backups: dict[str, Path] = {}
    changed: list[str] = []
    try:
        plan: list[tuple[Path, str, str, str]] = []  # (file, rel, original bytes-as-text, new text)
        for rel, hunks in _parse(diff):
            f = _safe(root, rel)
            if not f.is_file():
                raise ApplyError(f"file not found: {rel}")
            raw = f.read_bytes().decode("utf-8")
            crlf = "\r\n" in raw
            new = apply_unified(raw.replace("\r\n", "\n"), hunks)
            plan.append((f, rel, raw, new.replace("\n", "\r\n") if crlf else new))
        if not plan:
            raise ApplyError("the patch contains no file changes")
        for f, rel, raw, new in plan:  # back up first, then write
            dest = bdir / rel
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(f, dest)
            backups[rel] = dest
        for f, rel, raw, new in plan:
            f.write_bytes(new.encode("utf-8"))
            changed.append(rel)
    except (ApplyError, UnicodeDecodeError, OSError) as e:
        for rel in changed:  # roll back any file already written
            try:
                shutil.copy2(backups[rel], root / rel)
            except OSError:
                pass
        return {"status": "error", "error": f"Could not apply the change: {e}"}

    eco = rem.get("ecosystem") or (rem.get("target") or {}).get("ecosystem") or _guess_eco(changed[0])
    lock = _refresh_lock(eco, rem, (root / changed[0]).parent, backups, root, bdir)
    result = {"status": "success", "files": changed, "lock": lock, "backup_dir": str(bdir), "applied_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
              "backups": {k: str(v) for k, v in backups.items()}, "id": rem["id"], "title": rem.get("title", "")}
    sf = _state_file(root, rem["id"])
    sf.parent.mkdir(parents=True, exist_ok=True)
    sf.write_text(json.dumps(result, indent=2), encoding="utf-8")
    return result


def _guess_eco(path: str) -> str:
    base = path.rsplit("/", 1)[-1]
    return {"package.json": "npm", "pyproject.toml": "PyPI", "pom.xml": "Maven", "go.mod": "Go", "Cargo.toml": "crates.io", "composer.json": "Packagist"}.get(
        base, "PyPI" if base.startswith("requirements") else "")


def undo_in_place(root: Path | str, rem: dict) -> dict[str, Any]:
    """Restore the backed-up files of a previously applied proposal."""
    root = Path(root).resolve()
    rec = applied_record(root, rem)
    if not rec:
        return {"status": "error", "error": "No applied change recorded for this proposal."}
    restored = []
    try:
        for rel, src in (rec.get("backups") or {}).items():
            dest = _safe(root, rel)
            shutil.copy2(src, dest)
            restored.append(rel)
        _state_file(root, rem["id"]).unlink(missing_ok=True)
    except (ApplyError, OSError) as e:
        return {"status": "error", "error": f"Undo failed: {e}", "restored": restored}
    return {"status": "success", "restored": restored}
