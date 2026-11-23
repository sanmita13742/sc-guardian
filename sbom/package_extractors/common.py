"""Shared helpers for ecosystem extractors: name normalization, PURLs, source classification."""
from __future__ import annotations

import re
from typing import Optional
from urllib.parse import quote, unquote

from config.constants import OSV_TO_PURL, PURL_TO_OSV


def normalize_name(ecosystem: str, name: str) -> str:
    """Canonical comparison form of a package name within an ecosystem."""
    if ecosystem == "PyPI":
        return re.sub(r"[-_.]+", "-", name).lower()
    if ecosystem in ("Packagist", "NuGet", "RubyGems"):
        return name.lower()
    return name  # npm, Go, Maven, crates.io are case-sensitive / exact


def make_purl(ecosystem: str, name: str, version: Optional[str]) -> Optional[str]:
    ptype = OSV_TO_PURL.get(ecosystem)
    if not ptype or not name:
        return None
    v = f"@{quote(version, safe='')}" if version else ""
    if ecosystem == "npm":
        if name.startswith("@") and "/" in name:
            scope, base = name.split("/", 1)
            return f"pkg:npm/{quote(scope, safe='')}/{quote(base, safe='')}{v}"
        return f"pkg:npm/{quote(name, safe='')}{v}"
    if ecosystem == "PyPI":
        return f"pkg:pypi/{normalize_name('PyPI', name)}{v}"
    if ecosystem == "Maven":
        if ":" in name:
            g, a = name.split(":", 1)
            return f"pkg:maven/{quote(g, safe='.')}/{quote(a, safe='.')}{v}"
        return None
    if ecosystem == "Go":
        return f"pkg:golang/{name}{v}"
    if ecosystem == "crates.io":
        return f"pkg:cargo/{name}{v}"
    if ecosystem == "Packagist":
        return f"pkg:composer/{name.lower()}{v}"
    if ecosystem == "NuGet":
        return f"pkg:nuget/{name}{v}"
    if ecosystem == "RubyGems":
        return f"pkg:gem/{name}{v}"
    return None


def parse_purl(purl: str) -> Optional[dict]:
    """Minimal PURL parser -> {type, namespace, name, version, ecosystem, osv_name}."""
    if not purl or not purl.startswith("pkg:"):
        return None
    body = purl[4:].split("#", 1)[0].split("?", 1)[0]
    if "/" not in body:
        return None
    ptype, rest = body.split("/", 1)
    version = None
    if "@" in rest:
        rest, version = rest.rsplit("@", 1)
        version = unquote(version)
    parts = [unquote(p) for p in rest.split("/")]
    name = parts[-1]
    ns = "/".join(parts[:-1]) or None
    eco = PURL_TO_OSV.get(ptype.lower())
    if eco == "npm":
        osv_name = f"{ns}/{name}" if ns else name
    elif eco == "Maven":
        osv_name = f"{ns}:{name}" if ns else name
    elif eco in ("Go",):
        osv_name = f"{ns}/{name}" if ns else name
    elif eco == "Packagist":
        osv_name = f"{ns}/{name}" if ns else name
    elif eco == "PyPI":
        osv_name = normalize_name("PyPI", name)
    else:
        osv_name = name
    return {"type": ptype.lower(), "namespace": ns, "name": name, "version": version, "ecosystem": eco,
            "osv_name": osv_name}


def classify_source(resolved: Optional[str]) -> str:
    if not resolved:
        return "unknown"
    r = resolved.strip().lower()
    if r.startswith(("git+", "git://", "github:", "gitlab:", "bitbucket:", "ssh://git@")) or r.endswith(".git") or "git+" in r:
        return "git"
    if r.startswith(("file:", "link:", "workspace:", "path:", "./", "../", "/")):
        return "path"
    known = ("registry.npmjs.org", "registry.yarnpkg.com", "pypi.org", "files.pythonhosted.org", "crates.io",
             "repo.maven.apache.org", "repo1.maven.org", "packagist.org", "api.nuget.org", "proxy.golang.org",
             "npm.pkg.github.com")
    if any(k in r for k in known) or r.startswith("registry+"):
        return "registry"
    if r.startswith(("http://", "https://")):
        return "url"
    return "unknown"


def host_of(resolved: Optional[str]) -> Optional[str]:
    if not resolved:
        return None
    m = re.match(r"^(?:[a-z+]+://)?(?:[^@/]+@)?([^/:]+)", resolved.strip(), re.I)
    return m.group(1).lower() if m else None
