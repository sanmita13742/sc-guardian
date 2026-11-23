"""Go, Rust, PHP, .NET and Java/Maven extractors."""
from __future__ import annotations

import json
import re
import xml.etree.ElementTree as ET
from typing import Optional

from core.models import LockDependency
from sbom.package_extractors.common import classify_source, make_purl

try:
    import tomllib
except ImportError:  # pragma: no cover
    import tomli as tomllib  # type: ignore


def _mk(eco, name, version, lockfile, service_dir, **kw) -> LockDependency:
    return LockDependency(name=name, version=version, ecosystem=eco, purl=make_purl(eco, name, version),
                          lockfile=lockfile, service_dir=service_dir, **kw)


# ---------------------------------------------------------------- Go
def parse_go_mod(text: str, lockfile: str, service_dir: str, **_) -> list[LockDependency]:
    out = []
    in_block = False
    for i, line in enumerate(text.splitlines(), 1):
        s = line.strip()
        if s.startswith("require ("):
            in_block = True
            continue
        if in_block and s == ")":
            in_block = False
            continue
        body = None
        if in_block:
            body = s
        elif s.startswith("require ") and "(" not in s:
            body = s[len("require "):].strip()
        if not body or body.startswith("//"):
            continue
        indirect = "// indirect" in body
        body = body.split("//", 1)[0].strip()
        parts = body.split()
        if len(parts) >= 2:
            out.append(_mk("Go", parts[0], parts[1], lockfile, service_dir, direct=not indirect, record=f"line {i}",
                           source_type="registry"))
    return out


def parse_go_sum(text: str, lockfile: str, service_dir: str, **_) -> list[LockDependency]:
    seen: dict[tuple[str, str], LockDependency] = {}
    for i, line in enumerate(text.splitlines(), 1):
        parts = line.split()
        if len(parts) != 3:
            continue
        mod, ver, h = parts
        is_mod_only = ver.endswith("/go.mod")
        ver = ver.removesuffix("/go.mod")
        key = (mod, ver)
        if key not in seen or (not is_mod_only):
            if is_mod_only and key in seen:
                continue
            seen[key] = _mk("Go", mod, ver, lockfile, service_dir, direct=None, record=f"line {i}", integrity=h,
                            source_type="registry")
    return list(seen.values())


# ---------------------------------------------------------------- Rust
def parse_cargo_lock(text: str, lockfile: str, service_dir: str, **_) -> list[LockDependency]:
    data = tomllib.loads(text)
    pkgs = data.get("package", [])
    members = [p for p in pkgs if not p.get("source")]

    def depname(entry: str) -> str:
        return entry.split(" ")[0]

    direct = {depname(d) for m in members for d in (m.get("dependencies") or [])}
    member_names = {m["name"] for m in members}
    out = []
    for p in pkgs:
        if not p.get("source"):
            continue
        src = p["source"]
        out.append(_mk("crates.io", p["name"], p.get("version"), lockfile, service_dir,
                       direct=(p["name"] in direct) if members else None,
                       requires=sorted({depname(d) for d in (p.get("dependencies") or [])} - member_names),
                       record=f"package[{p['name']}]", integrity=p.get("checksum"), resolved=src,
                       source_type="git" if src.startswith("git+") else "registry" if src.startswith("registry+") else classify_source(src)))
    return out


# ---------------------------------------------------------------- PHP
def parse_composer_lock(text: str, lockfile: str, service_dir: str, composer_json: Optional[str] = None, **_) -> list[LockDependency]:
    data = json.loads(text)
    direct: Optional[set[str]] = None
    if composer_json:
        try:
            cj = json.loads(composer_json)
            direct = {k.lower() for k in (cj.get("require") or {})} | {k.lower() for k in (cj.get("require-dev") or {})}
        except Exception:
            direct = None
    out = []
    for section, dev in (("packages", False), ("packages-dev", True)):
        for p in data.get(section) or []:
            name = p.get("name")
            if not name:
                continue
            ver = (p.get("version") or "").lstrip("v") or None
            dist = p.get("dist") or {}
            src = p.get("source") or {}
            out.append(_mk("Packagist", name.lower(), ver, lockfile, service_dir,
                           direct=(name.lower() in direct) if direct is not None else None, dev=True if dev else None,
                           requires=sorted(k.lower() for k in (p.get("require") or {}) if "/" in k),
                           record=f"{section}[{name}]", integrity=dist.get("shasum") or None,
                           resolved=dist.get("url") or src.get("url"),
                           license=" OR ".join(p.get("license") or []) or None,
                           meta={k: v for k, v in (("homepage", p.get("homepage")), ("description", p.get("description")), ("published", p.get("time")),
                                                    ("authors", [a.get("name") for a in p.get("authors", []) if a.get("name")]),
                                                    ("vcs", src.get("url")), ("vcs_ref", src.get("reference")), ("abandoned", p.get("abandoned") or None)) if v},
                           source_type=classify_source(dist.get("url") or src.get("url"))))
    return out


# ---------------------------------------------------------------- .NET
def parse_nuget_lock(text: str, lockfile: str, service_dir: str, **_) -> list[LockDependency]:
    data = json.loads(text)
    out: dict[tuple[str, str], LockDependency] = {}
    for fw, pkgs in (data.get("dependencies") or {}).items():
        for name, meta in pkgs.items():
            if meta.get("type") == "Project":
                continue
            ver = meta.get("resolved")
            key = (name.lower(), ver or "")
            dep = out.get(key)
            is_direct = meta.get("type") == "Direct"
            if dep:
                dep.direct = bool(dep.direct or is_direct)
                continue
            out[key] = _mk("NuGet", name, ver, lockfile, service_dir, direct=is_direct,
                           requires=sorted((meta.get("dependencies") or {}).keys()), record=f"{fw}[{name}]",
                           integrity=meta.get("contentHash"), source_type="registry", meta={"hash_alg": "sha512"} if meta.get("contentHash") else {})
    return list(out.values())


def parse_csproj(text: str, lockfile: str, service_dir: str, **_) -> list[LockDependency]:
    out = []
    try:
        root = ET.fromstring(text)
    except ET.ParseError:
        return out
    for el in root.iter():
        if el.tag.split("}")[-1] == "PackageReference":
            name = el.attrib.get("Include") or el.attrib.get("Update")
            ver = el.attrib.get("Version")
            if ver is None:
                for ch in el:
                    if ch.tag.split("}")[-1] == "Version":
                        ver = (ch.text or "").strip()
            if name:
                if ver and ver.startswith("$("):
                    ver = None
                out.append(_mk("NuGet", name, ver, lockfile, service_dir, direct=True, record="PackageReference",
                               source_type="registry"))
    return out


# ---------------------------------------------------------------- Java
def parse_pom(text: str, lockfile: str, service_dir: str, **_) -> list[LockDependency]:
    out = []
    text = re.sub(r"<\?xml[^>]*\?>", "", text, count=1)
    try:
        root = ET.fromstring(text)
    except ET.ParseError:
        return out

    def local(tag):
        return tag.split("}")[-1]

    props: dict[str, str] = {}
    for el in root:
        if local(el.tag) == "properties":
            for p in el:
                props[local(p.tag)] = (p.text or "").strip()
    for el in root:
        if local(el.tag) in ("groupId", "version"):
            props[f"project.{local(el.tag)}"] = (el.text or "").strip()
            props[f"pom.{local(el.tag)}"] = (el.text or "").strip()

    def resolve(v: Optional[str]) -> Optional[str]:
        if v is None:
            return None
        v = v.strip()
        for _ in range(5):
            m = re.search(r"\$\{([^}]+)\}", v)
            if not m:
                break
            repl = props.get(m.group(1))
            if repl is None:
                return None
            v = v.replace(m.group(0), repl)
        return v or None

    managed: dict[str, str] = {}
    for dm in root.iter():
        if local(dm.tag) == "dependencyManagement":
            for dep in dm.iter():
                if local(dep.tag) == "dependency":
                    g = a = v = None
                    for ch in dep:
                        t = local(ch.tag)
                        if t == "groupId":
                            g = ch.text
                        elif t == "artifactId":
                            a = ch.text
                        elif t == "version":
                            v = ch.text
                    if g and a and v:
                        managed[f"{g.strip()}:{a.strip()}"] = resolve(v) or ""
    in_mgmt = {id(d) for dm in root.iter() if local(dm.tag) == "dependencyManagement" for d in dm.iter()}
    for dep in root.iter():
        if local(dep.tag) != "dependency" or id(dep) in in_mgmt:
            continue
        g = a = v = scope = None
        for ch in dep:
            t = local(ch.tag)
            if t == "groupId":
                g = (ch.text or "").strip()
            elif t == "artifactId":
                a = (ch.text or "").strip()
            elif t == "version":
                v = ch.text
            elif t == "scope":
                scope = (ch.text or "").strip()
        if not (g and a):
            continue
        g = resolve(g) or g
        name = f"{g}:{a}"
        ver = resolve(v) if v else (managed.get(name) or None)
        out.append(_mk("Maven", name, ver, lockfile, service_dir, direct=True, dev=True if scope == "test" else None,
                       record=f"dependency[{name}]", source_type="registry"))
    return out


_GRADLE = re.compile(r"""(?:implementation|api|compile|runtimeOnly|compileOnly|testImplementation|testCompile|annotationProcessor)\s*\(?\s*['"]([\w.\-]+):([\w.\-]+):([\w.\-${}]+)['"]""")


def parse_gradle(text: str, lockfile: str, service_dir: str, **_) -> list[LockDependency]:
    out = []
    for m in _GRADLE.finditer(text):
        g, a, v = m.groups()
        out.append(_mk("Maven", f"{g}:{a}", None if "$" in v else v, lockfile, service_dir, direct=True,
                       dev=True if "test" in m.group(0).lower() else None, record=m.group(0)[:80], source_type="registry"))
    return out


def parse_gradle_lockfile(text: str, lockfile: str, service_dir: str, **_) -> list[LockDependency]:
    out = []
    for i, line in enumerate(text.splitlines(), 1):
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("empty="):
            continue
        coords = line.split("=", 1)[0].split(":")
        if len(coords) == 3:
            out.append(_mk("Maven", f"{coords[0]}:{coords[1]}", coords[2], lockfile, service_dir, direct=None,
                           record=f"line {i}", source_type="registry"))
    return out
