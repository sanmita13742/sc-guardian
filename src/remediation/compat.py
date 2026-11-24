"""Static compatibility check of a proposed version change, from the package registry's own metadata for the target version.

Checks (npm): deprecated flag, ``engines.node`` against the project's declared engines, ``peerDependencies`` against the project's direct
dependencies, and major-version jumps. PyPI: yanked releases and ``requires_python``. Range logic uses the semver library bundled with npm
(``npm root -g`` / npm / node_modules / semver) so it follows npm's exact rules; when it is unavailable the range checks report "unknown".
This does not replace running the project's tests; it catches the declared incompatibilities cheaply, before any build.
"""
from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path
from typing import Any, Optional
from urllib.parse import quote

from core.http import HttpClient, NotFound, SourceUnavailable

_SEMVER_JS = ("const s=require(process.argv[1]);const ops=JSON.parse(require('fs').readFileSync(0,'utf8'));"
              "console.log(JSON.stringify(ops.map(o=>{try{return o.op==='intersects'?s.intersects(o.a,o.b):s.satisfies(o.a,o.b)}catch(e){return null}})))")
_semver_path: Optional[str] = None


def _find_semver() -> Optional[str]:
    global _semver_path
    if _semver_path is not None:
        return _semver_path or None
    _semver_path = ""
    npm = shutil.which("npm")
    if npm:
        cands = [Path(npm).resolve().parent / "node_modules" / "npm" / "node_modules" / "semver",   # Windows installer layout
                 Path(npm).resolve().parent.parent / "lib" / "node_modules" / "npm" / "node_modules" / "semver"]  # unix layout
        try:
            root = subprocess.run([npm, "root", "-g"], capture_output=True, text=True, timeout=30, shell=False).stdout.strip()
            cands.append(Path(root) / "npm" / "node_modules" / "semver")
        except (OSError, subprocess.TimeoutExpired):
            pass
        for cand in cands:
            if cand.exists():
                _semver_path = str(cand)
                break
    return _semver_path or None


def _semver(ops: list[dict]) -> list[Optional[bool]]:
    node, sv = shutil.which("node"), _find_semver()
    if not node or not sv or not ops:
        return [None] * len(ops)
    try:
        p = subprocess.run([node, "-e", _SEMVER_JS, sv], input=json.dumps(ops), capture_output=True, text=True, timeout=30, shell=False)
        out = json.loads(p.stdout.strip() or "[]")
        return out if len(out) == len(ops) else [None] * len(ops)
    except (OSError, subprocess.TimeoutExpired, ValueError):
        return [None] * len(ops)


def _c(name: str, status: str, detail: str) -> dict[str, str]:
    return {"name": name, "status": status, "detail": detail}


def _npm(http: HttpClient, rem: dict, root: Path, manifest_dir: Path) -> list[dict]:
    out: list[dict] = []
    try:
        proj = json.loads((manifest_dir / "package.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        proj = {}
    direct = {**(proj.get("dependencies") or {}), **(proj.get("devDependencies") or {}), **(proj.get("optionalDependencies") or {})}
    proj_engine = (proj.get("engines") or {}).get("node")
    ops: list[dict] = []
    todo: list[tuple[str, str]] = []  # (check name, what the result means) aligned with ops
    for ch in (rem.get("changes") or [])[:6]:
        name, to = ch["package"], ch["to"]
        try:
            meta = http.get_json(f"https://registry.npmjs.org/{quote(name, safe='')}/{quote(to, safe='')}")
        except (NotFound, SourceUnavailable):
            out.append(_c(f"{name}@{to} metadata", "unknown", "registry metadata unavailable"))
            continue
        label = f"{name}@{to}"
        if meta.get("deprecated"):
            out.append(_c(f"{label} deprecated", "warn", str(meta["deprecated"])[:200]))
        else:
            out.append(_c(f"{label} deprecated", "ok", "not deprecated"))
        eng = (meta.get("engines") or {}).get("node")
        if eng and proj_engine:
            ops.append({"op": "intersects", "a": proj_engine, "b": eng})
            todo.append((f"{label} engines.node", f"project declares node {proj_engine}; package needs {eng}"))
        elif eng:
            out.append(_c(f"{label} engines.node", "ok", f"requires node {eng}; the project declares no engine range, so this cannot conflict"))
        for peer, rng in (meta.get("peerDependencies") or {}).items():
            optional = bool(((meta.get("peerDependenciesMeta") or {}).get(peer) or {}).get("optional"))
            have = direct.get(peer)
            if have:
                ops.append({"op": "intersects", "a": have, "b": rng})
                todo.append((f"{label} peer {peer}", f"project declares {peer}@{have}; package needs {rng}"))
            elif not optional:
                out.append(_c(f"{label} peer {peer}", "warn", f"needs {peer}@{rng}, which the project does not declare directly"))
    for (name, detail), res in zip(todo, _semver(ops)):
        out.append(_c(name, "ok" if res else "unknown" if res is None else "fail" if "engines" in name else "warn", detail + ("" if res else (" - semver library unavailable" if res is None else " - ranges do not overlap"))))
    return out


def _pypi(http: HttpClient, rem: dict) -> list[dict]:
    out: list[dict] = []
    for ch in (rem.get("changes") or [])[:6]:
        name, to = ch["package"], ch["to"]
        try:
            d = http.get_json(f"https://pypi.org/pypi/{quote(name, safe='')}/{quote(to, safe='')}/json")
        except (NotFound, SourceUnavailable):
            out.append(_c(f"{name}=={to} metadata", "unknown", "PyPI metadata unavailable"))
            continue
        info = d.get("info") or {}
        if info.get("yanked"):
            out.append(_c(f"{name}=={to} yanked", "fail", str(info.get("yanked_reason") or "this release was yanked by its maintainers")[:200]))
        else:
            out.append(_c(f"{name}=={to} yanked", "ok", "not yanked"))
        if info.get("requires_python"):
            out.append(_c(f"{name}=={to} requires_python", "ok", f"requires Python {info['requires_python']} (confirm your runtime satisfies it)"))
    return out


def static_compat(rem: dict, root: Path | str) -> dict[str, Any]:
    """Return {status: ok|warn|fail|unknown, checks: [{name, status, detail}]} for the proposal's version change."""
    root = Path(root)
    eco = rem.get("ecosystem") or (rem.get("target") or {}).get("ecosystem")
    http = HttpClient(timeout=15, retries=2)
    checks: list[dict] = []
    ch = (rem.get("compatibility") or {})
    if ch.get("semver_change") == "major":
        checks.append(_c("major version change", "warn", f"{(rem.get('target') or {}).get('from')} -> {(rem.get('target') or {}).get('to')}: read the release notes; breaking changes are expected"))
    patch_path = (rem.get("patch") or {}).get("path") or ""
    mdir = (root / patch_path).parent if patch_path else root
    try:
        if eco == "npm":
            checks += _npm(http, rem, root, mdir)
        elif eco == "PyPI":
            checks += _pypi(http, rem)
        else:
            checks.append(_c("registry metadata", "unknown", f"no automated compatibility metadata for {eco or 'this ecosystem'}"))
    except Exception as e:  # noqa: BLE001 - metadata is advisory; never break validation
        checks.append(_c("registry metadata", "unknown", f"{type(e).__name__}: {str(e)[:120]}"))
    imp = rem.get("reachability_impact") or {}
    if imp.get("app_files_affected"):
        checks.append(_c("application usage", "warn" if (imp.get("reachability_preservation_score") or 100) < 100 else "ok",
                         f"{len(imp['app_files_affected'])} application file(s) import this package; {imp.get('impact_summary', '')}".strip()))
    statuses = {c["status"] for c in checks}
    status = "fail" if "fail" in statuses else "warn" if "warn" in statuses else "ok" if statuses == {"ok"} or ("ok" in statuses and statuses <= {"ok", "unknown"}) else "unknown"
    return {"status": status, "checks": checks}
