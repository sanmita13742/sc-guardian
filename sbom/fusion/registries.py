"""Registry clients used to fill metadata the lockfile/scanner did not record and to verify lockfile integrity digests.

Each fetcher returns a *record*: {licenses, supplier, description, links[{type,url}], published_at, deprecated, install_script,
digests[{alg, hex, what}], yanked, url}. Fields a registry does not state are omitted (never defaulted).
Only public read-only GET requests are made; the scanned repository's code is never run.
"""
from __future__ import annotations

import re
from typing import Any, Callable, Optional
from urllib.parse import quote

from core.http import HttpClient
from sbom.fusion.hashes import parse_digest

DEPSDEV_SYSTEM = {"npm": "npm", "PyPI": "pypi", "Maven": "maven", "Go": "go", "crates.io": "cargo", "NuGet": "nuget"}
_LINK_TYPE = {"HOMEPAGE": "website", "SOURCE_REPO": "vcs", "ISSUE_TRACKER": "issue-tracker", "DOCUMENTATION": "documentation", "ORIGIN": "distribution"}
_PYPI_CLASSIFIER = {
    "MIT License": "MIT", "Apache Software License": "Apache-2.0", "ISC License (ISCL)": "ISC", "Mozilla Public License 2.0 (MPL 2.0)": "MPL-2.0",
    "The Unlicense (Unlicense)": "Unlicense", "GNU General Public License v2 (GPLv2)": "GPL-2.0-only", "GNU General Public License v3 (GPLv3)": "GPL-3.0-only",
    "GNU Lesser General Public License v3 (LGPLv3)": "LGPL-3.0-only", "GNU Affero General Public License v3": "AGPL-3.0-only", "Python Software Foundation License": "PSF-2.0",
}


def _clean_license(v: Any) -> Optional[str]:
    if isinstance(v, dict):
        v = v.get("type") or v.get("name")
    if not isinstance(v, str):
        return None
    v = v.strip()
    if not v or v.lower() in ("non-standard", "other", "unknown", "unlicensed", "see license in license", "none") or len(v) > 120 or "\n" in v:
        return None
    return v


def depsdev(http: HttpClient, eco: str, name: str, version: str) -> dict:
    system = DEPSDEV_SYSTEM[eco]
    url = f"https://api.deps.dev/v3/systems/{system}/packages/{quote(name, safe='')}/versions/{quote(version, safe='')}"
    d = http.get_json(url)
    rec: dict[str, Any] = {"url": url}
    lic = [x for x in (_clean_license(x) for x in d.get("licenses") or []) if x]
    if lic:
        rec["licenses"] = lic
    if d.get("publishedAt"):
        rec["published_at"] = d["publishedAt"]
    if "isDeprecated" in d:
        rec["deprecated"] = bool(d["isDeprecated"])
    links = [{"type": _LINK_TYPE[l["label"]], "url": l["url"]} for l in d.get("links") or [] if l.get("label") in _LINK_TYPE and l.get("url")]
    if links:
        rec["links"] = links
    if d.get("slsaProvenances"):
        rec["provenance_attestations"] = len(d["slsaProvenances"])
    return rec


def npm(http: HttpClient, eco: str, name: str, version: str) -> dict:
    url = f"https://registry.npmjs.org/{quote(name, safe='@')}/{quote(version, safe='')}"
    d = http.get_json(url)
    rec: dict[str, Any] = {"url": url}
    lic = _clean_license(d.get("license"))
    if not lic and isinstance(d.get("licenses"), list):
        lic = " OR ".join(x for x in (_clean_license(x) for x in d["licenses"]) if x) or None
    if lic:
        rec["licenses"] = [lic]
    author = d.get("author")
    pub = (d.get("_npmUser") or {}).get("name") or ((d.get("maintainers") or [{}])[0] or {}).get("name") or (author.get("name") if isinstance(author, dict) else None)
    if pub:
        rec["supplier"] = pub
    if d.get("description"):
        rec["description"] = str(d["description"])[:300]
    links = []
    if d.get("homepage"):
        links.append({"type": "website", "url": d["homepage"]})
    repo = d.get("repository")
    ru = repo.get("url") if isinstance(repo, dict) else repo if isinstance(repo, str) else None
    if ru:
        links.append({"type": "vcs", "url": re.sub(r"^git\+", "", ru)})
    if (d.get("bugs") or {}).get("url") if isinstance(d.get("bugs"), dict) else False:
        links.append({"type": "issue-tracker", "url": d["bugs"]["url"]})
    if links:
        rec["links"] = links
    scripts = d.get("scripts") or {}
    rec["install_script"] = bool(d.get("gypfile") or any(k in scripts for k in ("preinstall", "install", "postinstall")))
    if d.get("deprecated"):
        rec["deprecated"] = True
    dist = d.get("dist") or {}
    dig = []
    for key in ("integrity", "shasum"):
        p = parse_digest(dist.get(key))
        if p:
            dig.append({**p, "what": "tarball"})
    if dig:
        rec["digests"] = dig
    return rec


def pypi(http: HttpClient, eco: str, name: str, version: str) -> dict:
    url = f"https://pypi.org/pypi/{quote(name, safe='')}/{quote(version, safe='')}/json"
    d = http.get_json(url)
    info = d.get("info") or {}
    rec: dict[str, Any] = {"url": url}
    lic = _clean_license(info.get("license_expression")) or None
    if not lic:
        for cl in info.get("classifiers") or []:
            if cl.startswith("License ::") and cl.split(" :: ")[-1] in _PYPI_CLASSIFIER:
                lic = _PYPI_CLASSIFIER[cl.split(" :: ")[-1]]
                break
    if not lic and info.get("license") and len(info["license"]) < 60 and "\n" not in info["license"]:
        lic = _clean_license(info["license"])
    if not lic:  # unambiguous label only (e.g. "BSD License" has no single SPDX id, so it is recorded by name)
        for cl in info.get("classifiers") or []:
            if cl.startswith("License :: OSI Approved :: "):
                lic = cl.split(" :: ")[-1]
                break
    if lic:
        rec["licenses"] = [lic]
    pub = info.get("author") or info.get("maintainer")
    if pub:
        rec["supplier"] = pub
    if info.get("summary"):
        rec["description"] = str(info["summary"])[:300]
    links = []
    if info.get("home_page"):
        links.append({"type": "website", "url": info["home_page"]})
    for k, v in (info.get("project_urls") or {}).items():
        t = "vcs" if re.search(r"source|repo|github|code", k, re.I) else "issue-tracker" if re.search(r"issue|bug|tracker", k, re.I) else "documentation" if re.search(r"doc", k, re.I) else "website" if re.search(r"home", k, re.I) else None
        if t and v:
            links.append({"type": t, "url": v})
    if links:
        rec["links"] = links[:5]
    files = d.get("urls") or []
    dig = [{"alg": "sha256", "hex": f["digests"]["sha256"].lower(), "kind": "file", "what": f.get("filename", "")} for f in files if (f.get("digests") or {}).get("sha256")]
    if dig:
        rec["digests"] = dig
    if files:
        rec["published_at"] = files[0].get("upload_time_iso_8601") or files[0].get("upload_time")
        rec["yanked"] = any(f.get("yanked") for f in files)
    return rec


def crates(http: HttpClient, eco: str, name: str, version: str) -> dict:
    url = f"https://crates.io/api/v1/crates/{quote(name, safe='')}/{quote(version, safe='')}"
    v = (http.get_json(url) or {}).get("version") or {}
    rec: dict[str, Any] = {"url": url}
    if v.get("checksum"):
        p = parse_digest(v["checksum"], "sha256")
        if p:
            rec["digests"] = [{**p, "what": "crate"}]
    if v.get("license"):
        rec["licenses"] = [v["license"]]
    if v.get("created_at"):
        rec["published_at"] = v["created_at"]
    if v.get("yanked"):
        rec["yanked"] = True
        rec["deprecated"] = True
    return rec


def maven_central(http: HttpClient, eco: str, name: str, version: str) -> dict:
    if ":" not in name:
        return {}
    g, a = name.split(":", 1)
    base = f"https://repo1.maven.org/maven2/{g.replace('.', '/')}/{a}/{version}/{a}-{version}"
    r = http.request("GET", base + ".jar.sha1")
    h = r.text.strip().split()[0] if r.text.strip() else ""
    p = parse_digest(h)
    return {"url": base + ".jar.sha1", "digests": [{**p, "what": "jar"}]} if p else {}


FETCHERS: dict[str, list[tuple[str, Callable]]] = {
    "npm": [("npm-registry", npm), ("deps.dev", depsdev)],
    "PyPI": [("pypi", pypi), ("deps.dev", depsdev)],
    "crates.io": [("crates.io", crates), ("deps.dev", depsdev)],
    "Maven": [("deps.dev", depsdev), ("maven-central", maven_central)],
    "Go": [("deps.dev", depsdev)],
    "NuGet": [("deps.dev", depsdev)],
}


def supported(eco: Optional[str]) -> bool:
    return bool(eco and eco in FETCHERS)
