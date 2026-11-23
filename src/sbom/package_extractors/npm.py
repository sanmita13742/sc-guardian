"""npm ecosystem: package-lock.json (v1/v2/v3), npm-shrinkwrap.json, yarn.lock (v1 + berry), pnpm-lock.yaml."""
from __future__ import annotations

import json
import re
from typing import Optional

import yaml

from core.models import LockDependency
from sbom.package_extractors.common import classify_source, make_purl

ECO = "npm"


def _manifest_deps(package_json_text: Optional[str]) -> tuple[Optional[set[str]], set[str]]:
    """Return (direct names or None if unknown, dev-only names)."""
    if not package_json_text:
        return None, set()
    try:
        d = json.loads(package_json_text)
    except Exception:
        return None, set()
    prod = set((d.get("dependencies") or {})) | set((d.get("optionalDependencies") or {})) | set((d.get("peerDependencies") or {}))
    dev = set((d.get("devDependencies") or {}))
    return prod | dev, dev - prod


def _npm_license(v) -> Optional[str]:
    if isinstance(v, str):
        return v
    if isinstance(v, dict):
        return v.get("type")
    if isinstance(v, list):
        parts = [_npm_license(x) for x in v if x]
        return " OR ".join(p for p in parts if p) or None
    return None


def _npm_meta(meta: dict) -> dict:
    """What package-lock v2/v3 records about a package besides its version (only keys that are present)."""
    m: dict = {}
    for k in ("optional", "peer", "devOptional", "inBundle"):
        if meta.get(k):
            m[k] = True
    if meta.get("hasInstallScript"):
        m["install_script"] = True
    if meta.get("deprecated"):
        m["deprecated"] = str(meta["deprecated"])[:200]
    for k in ("engines", "os", "cpu"):
        if meta.get(k):
            m[k] = meta[k]
    return m


def _mk(name, version, lockfile, service_dir, **kw) -> LockDependency:
    return LockDependency(name=name, version=version, ecosystem=ECO, purl=make_purl(ECO, name, version),
                          lockfile=lockfile, service_dir=service_dir, **kw)


def parse_package_lock(text: str, lockfile: str, service_dir: str, package_json: Optional[str] = None) -> list[LockDependency]:
    data = json.loads(text)
    out: list[LockDependency] = []
    pkgs = data.get("packages")
    if isinstance(pkgs, dict):  # lockfileVersion 2/3
        root = pkgs.get("") or {}
        direct_names = set((root.get("dependencies") or {})) | set((root.get("devDependencies") or {})) \
            | set((root.get("optionalDependencies") or {})) | set((root.get("peerDependencies") or {}))
        dev_only = set((root.get("devDependencies") or {})) - set((root.get("dependencies") or {}))
        for key, meta in pkgs.items():
            if key == "" or not isinstance(meta, dict):
                continue
            if "node_modules/" not in key:
                continue  # workspace member paths are not registry packages
            name = meta.get("name") or key.rsplit("node_modules/", 1)[1]
            top_level = key == f"node_modules/{name}"
            version = meta.get("version")
            resolved = meta.get("resolved")
            if meta.get("link"):
                continue
            out.append(_mk(
                name, version, lockfile, service_dir,
                direct=(name in direct_names) if top_level else False,
                dev=True if (meta.get("dev") or (top_level and name in dev_only)) else None,
                requires=sorted(set((meta.get("dependencies") or {})) | set((meta.get("optionalDependencies") or {}))),
                record=f"packages[{key}]", integrity=meta.get("integrity"), resolved=resolved,
                source_type=classify_source(resolved) if resolved else ("path" if meta.get("link") else "unknown"),
                license=_npm_license(meta.get("license")), meta=_npm_meta(meta),
            ))
        return out
    deps = data.get("dependencies")  # lockfileVersion 1
    direct, dev_only = _manifest_deps(package_json)

    def walk(d: dict, top: bool, path: str):
        for name, meta in d.items():
            if not isinstance(meta, dict):
                continue
            resolved = meta.get("resolved")
            version = meta.get("version")
            out.append(_mk(
                name, version if not str(version).startswith(("git", "file:", "http")) else version, lockfile, service_dir,
                direct=(name in direct) if (top and direct is not None) else (False if not top else None),
                dev=True if meta.get("dev") else None,
                requires=sorted((meta.get("requires") or {}).keys()),
                record=f"dependencies[{path}{name}]", integrity=meta.get("integrity"), resolved=resolved,
                source_type=classify_source(resolved) if resolved else classify_source(str(version)),
                meta=({"optional": True} if meta.get("optional") else {}),
            ))
            if meta.get("dependencies"):
                walk(meta["dependencies"], False, f"{path}{name}>")

    if isinstance(deps, dict):
        walk(deps, True, "")
    return out


_YARN_HEADER = re.compile(r'^("?[^\s].*?"?):\s*$')


def parse_yarn_lock(text: str, lockfile: str, service_dir: str, package_json: Optional[str] = None) -> list[LockDependency]:
    direct_names, dev_only = _manifest_deps(package_json)
    out: list[LockDependency] = []
    blocks: list[tuple[list[str], dict, list[str]]] = []
    cur_specs: list[str] | None = None
    cur: dict = {}
    reqs: list[str] = []
    section = None
    for raw in text.splitlines() + [""]:
        if not raw.strip() or raw.lstrip().startswith("#"):
            if not raw.strip() and cur_specs is not None and cur:
                blocks.append((cur_specs, cur, reqs))
                cur_specs, cur, reqs, section = None, {}, [], None
            continue
        if not raw.startswith(" "):
            m = _YARN_HEADER.match(raw)
            if m:
                specs = [s.strip().strip('"') for s in m.group(1).split(",")]
                cur_specs, cur, reqs, section = specs, {}, [], None
            continue
        if cur_specs is None:
            continue
        indent = len(raw) - len(raw.lstrip())
        line = raw.strip()
        if indent == 2:
            section = None
            if line.endswith(":") and line[:-1] in ("dependencies", "optionalDependencies"):
                section = "deps"
                continue
            if line.endswith(":"):
                continue
            k, _, v = line.partition(": ") if ": " in line else line.partition(" ")
            cur[k.strip('"')] = v.strip().strip('"')
        elif indent >= 4 and section == "deps":
            nm = line.split(" ")[0].rstrip(":").strip('"').rstrip(":")
            reqs.append(nm)
    for specs, meta, rq in blocks:
        first = specs[0]
        at = first.rfind("@")
        name = first[:at] if at > 0 else first
        version = meta.get("version")
        resolved = meta.get("resolved") or meta.get("resolution")
        if name.startswith("@") is False and "@npm:" in first:
            name = first.split("@npm:")[0]
        if direct_names is None:
            direct = None
        else:
            direct = name in direct_names
        out.append(_mk(name, version, lockfile, service_dir, direct=direct,
                       dev=(name in dev_only) if direct_names is not None and name in dev_only else None,
                       requires=sorted(set(rq)), record=f"entry[{first}]",
                       integrity=meta.get("integrity") or meta.get("checksum"), resolved=resolved,
                       source_type=classify_source(resolved) if resolved else "unknown",
                       meta={k: v for k, v in (("link_type", meta.get("linkType")), ("language", meta.get("languageName"))) if v}))
    return out


def parse_pnpm_lock(text: str, lockfile: str, service_dir: str, package_json: Optional[str] = None) -> list[LockDependency]:
    data = yaml.safe_load(text) or {}
    out: list[LockDependency] = []
    direct_names: set[str] = set()
    importers = data.get("importers") or {}
    sources = [importers.get(".", {})] if importers else [data]
    for src in sources:
        for k in ("dependencies", "devDependencies", "optionalDependencies"):
            direct_names |= set((src.get(k) or {}).keys())
    snapshots = data.get("snapshots") or {}
    pk = data.get("packages") or {}
    for key, meta in pk.items():
        k = key.lstrip("/")
        m = re.match(r"^(@?[^@]+)@(.+?)(\(.*)?$", k) or re.match(r"^(@?[^/]+(?:/[^/]+)?)/(\d[^_(]*)", k)
        if not m:
            continue
        name, version = m.group(1), m.group(2)
        meta = meta or {}
        snap = snapshots.get(key) or snapshots.get(k) or {}
        requires = sorted(set((snap.get("dependencies") or meta.get("dependencies") or {}).keys())
                          | set((snap.get("optionalDependencies") or meta.get("optionalDependencies") or {}).keys()))
        res = (meta.get("resolution") or {})
        out.append(_mk(name, version, lockfile, service_dir, direct=name in direct_names, requires=requires,
                       dev=True if meta.get("dev") else None, record=f"packages[{key}]",
                       meta={k: v for k, v in (("optional", True if meta.get("optional") else None), ("install_script", True if meta.get("requiresBuild") else None),
                                                ("deprecated", str(meta["deprecated"])[:200] if meta.get("deprecated") else None), ("engines", meta.get("engines")),
                                                ("cpu", meta.get("cpu")), ("os", meta.get("os"))) if v},
                       integrity=res.get("integrity"), resolved=res.get("tarball") or res.get("repo"),
                       source_type="git" if res.get("type") == "git" else (classify_source(res.get("tarball")) if res.get("tarball") else "registry")))
    return out
