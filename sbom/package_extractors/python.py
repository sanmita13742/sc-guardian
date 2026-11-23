"""PyPI ecosystem: requirements*.txt, poetry.lock, uv.lock, Pipfile.lock."""
from __future__ import annotations

import json
import re
from typing import Optional

from core.models import LockDependency
from sbom.package_extractors.common import classify_source, make_purl, normalize_name

try:
    import tomllib
except ImportError:  # pragma: no cover
    import tomli as tomllib  # type: ignore

ECO = "PyPI"
_REQ = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*(\[[^\]]*\])?\s*(.*)$")


def _mk(name, version, lockfile, service_dir, **kw) -> LockDependency:
    return LockDependency(name=normalize_name(ECO, name), version=version, ecosystem=ECO,
                          purl=make_purl(ECO, name, version), lockfile=lockfile, service_dir=service_dir, **kw)


def parse_requirements(text: str, lockfile: str, service_dir: str, **_) -> list[LockDependency]:
    out: list[LockDependency] = []
    # join continuation lines
    joined: list[str] = []
    buf = ""
    for line in text.splitlines():
        if line.rstrip().endswith("\\"):
            buf += line.rstrip()[:-1] + " "
            continue
        joined.append(buf + line)
        buf = ""
    if buf:
        joined.append(buf)
    for i, line in enumerate(joined, 1):
        line = re.sub(r"(^|\s)#.*$", "", line).strip()
        if not line or line.startswith(("-", "git+", "http://", "https://", ".", "/")):
            continue
        spec = line.split(";", 1)[0]
        hashes = re.findall(r"--hash=(\S+)", spec)
        spec = re.sub(r"--hash=\S+", "", spec)
        m = _REQ.match(spec)
        if not m:
            continue
        name, rest = m.group(1), m.group(3).strip()
        pm = re.match(r"^(?:==|===)\s*([A-Za-z0-9.!+_*-]+)\s*$", rest.split(",")[0].strip()) if "," not in rest else None
        version = pm.group(1) if pm and "*" not in pm.group(1) else None
        out.append(_mk(name, version, lockfile, service_dir, direct=None, record=f"line {i}",
                       integrity=hashes[0] if hashes else None, source_type="registry"))
    return out


def _poetry_direct(pyproject: Optional[str]) -> Optional[set[str]]:
    if not pyproject:
        return None
    try:
        d = tomllib.loads(pyproject)
    except Exception:
        return None
    names: set[str] = set()
    for dep in (d.get("project", {}).get("dependencies") or []):
        names.add(normalize_name(ECO, re.split(r"[<>=!~\[; ]", dep, 1)[0]))
    poetry = d.get("tool", {}).get("poetry", {})
    names |= {normalize_name(ECO, n) for n in (poetry.get("dependencies") or {}) if n.lower() != "python"}
    names |= {normalize_name(ECO, n) for n in (poetry.get("dev-dependencies") or {})}
    for grp in (poetry.get("group") or {}).values():
        names |= {normalize_name(ECO, n) for n in (grp.get("dependencies") or {})}
    for grp in (d.get("dependency-groups") or {}).values():
        for dep in grp:
            if isinstance(dep, str):
                names.add(normalize_name(ECO, re.split(r"[<>=!~\[; ]", dep, 1)[0]))
    return names or None


def parse_poetry_lock(text: str, lockfile: str, service_dir: str, pyproject: Optional[str] = None, **_) -> list[LockDependency]:
    data = tomllib.loads(text)
    direct = _poetry_direct(pyproject)
    out = []
    for i, p in enumerate(data.get("package", [])):
        name, version = p.get("name"), p.get("version")
        if not name:
            continue
        src = p.get("source") or {}
        nn = normalize_name(ECO, name)
        out.append(_mk(name, version, lockfile, service_dir, direct=(nn in direct) if direct is not None else None,
                       dev=True if p.get("category") == "dev" or (p.get("groups") and "main" not in p.get("groups")) else None,
                       requires=sorted(normalize_name(ECO, k) for k in (p.get("dependencies") or {})),
                       record=f"package[{name}]", resolved=src.get("url") or src.get("reference"),
                       source_type=("git" if src.get("type") == "git" else "path" if src.get("type") in ("directory", "file") else "registry")))
    return out


def parse_uv_lock(text: str, lockfile: str, service_dir: str, **_) -> list[LockDependency]:
    data = tomllib.loads(text)
    pkgs = data.get("package", [])
    roots = [p for p in pkgs if (p.get("source") or {}).get("virtual") or (p.get("source") or {}).get("editable")]
    direct: set[str] = set()
    for r in roots:
        for d in (r.get("dependencies") or []):
            direct.add(normalize_name(ECO, d.get("name", "")))
        for grp in (r.get("dev-dependencies") or {}).values():
            for d in grp:
                direct.add(normalize_name(ECO, d.get("name", "")))
        for grp in (r.get("optional-dependencies") or {}).values():
            for d in grp:
                direct.add(normalize_name(ECO, d.get("name", "")))
    out = []
    for p in pkgs:
        src = p.get("source") or {}
        if src.get("virtual") or src.get("editable"):
            continue
        name = p.get("name")
        nn = normalize_name(ECO, name or "")
        sdist = p.get("sdist") or {}
        stype = "git" if "git" in src else "path" if "directory" in src or "path" in src else "registry" if "registry" in src else "unknown"
        out.append(_mk(name, p.get("version"), lockfile, service_dir, direct=(nn in direct) if roots else None,
                       requires=sorted(normalize_name(ECO, d.get("name", "")) for d in (p.get("dependencies") or [])),
                       record=f"package[{name}]", integrity=sdist.get("hash"), resolved=src.get("registry") or src.get("git"),
                       source_type=stype))
    return out


def parse_pipfile_lock(text: str, lockfile: str, service_dir: str, **_) -> list[LockDependency]:
    data = json.loads(text)
    out = []
    for section, dev in (("default", False), ("develop", True)):
        for name, meta in (data.get(section) or {}).items():
            ver = (meta.get("version") or "").lstrip("=") or None
            hashes = meta.get("hashes") or []
            out.append(_mk(name, ver, lockfile, service_dir, direct=None, dev=True if dev else None,
                           record=f"{section}[{name}]", integrity=hashes[0] if hashes else None,
                           resolved=meta.get("git") or meta.get("file") or meta.get("path"),
                           source_type="git" if meta.get("git") else "path" if (meta.get("file") or meta.get("path")) else "registry"))
    return out
