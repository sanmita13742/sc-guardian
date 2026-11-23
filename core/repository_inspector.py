"""Static repository inspection: languages, ecosystems, manifests, frameworks, services.

Nothing here executes repository code. Symlinks are never followed and every read is confined to the repo root.
"""
from __future__ import annotations

import json
import os
import re
from pathlib import Path

from config.constants import (CI_FILE_PATTERNS, EXTENSION_LANGUAGES, FRAMEWORK_CONFIG_FILES, FRAMEWORK_HINTS,
                              IGNORED_DIRS, MANIFEST_FILES, MANIFEST_SUFFIXES, MARKUP_LANGUAGES)
from config.settings import Settings, get_settings
from core.models import FrameworkHit, InspectionResult, ManifestFile

try:
    import tomllib
except ImportError:  # pragma: no cover
    import tomli as tomllib  # type: ignore

# ecosystems we detect but cannot parse lockfiles for
UNSUPPORTED_MANIFESTS = {"Gemfile": "RubyGems", "Gemfile.lock": "RubyGems", "build.gradle": None}


def safe_read_text(root: Path, rel: str, max_bytes: int = 20 * 1024 * 1024) -> str | None:
    """Read a text file confined to ``root``; returns None for symlinks, escapes, oversize or unreadable files."""
    try:
        root_r = root.resolve()
        p = (root / rel)
        if p.is_symlink():
            return None
        p = p.resolve()
        p.relative_to(root_r)  # raises ValueError on traversal
        if not p.is_file() or p.stat().st_size > max_bytes:
            return None
        return p.read_text(encoding="utf-8", errors="replace")
    except (OSError, ValueError):
        return None


def _classify(name: str):
    if name in MANIFEST_FILES:
        return MANIFEST_FILES[name]
    suf = os.path.splitext(name)[1].lower()
    if suf in MANIFEST_SUFFIXES:
        return MANIFEST_SUFFIXES[suf]
    if name.startswith("requirements") and name.endswith(".txt"):
        return ("lockfile", "PyPI")
    return None


def walk_repo(root: Path, settings: Settings | None = None):
    """Yield (relative_posix_path, size) for regular files, skipping ignored dirs and symlinks."""
    s = settings or get_settings()
    count = 0
    for cur, dirs, files in os.walk(root, followlinks=False):
        dirs[:] = [d for d in dirs if d not in IGNORED_DIRS and not os.path.islink(os.path.join(cur, d))]
        for f in files:
            fp = os.path.join(cur, f)
            if os.path.islink(fp):
                continue
            count += 1
            if count > s.max_files_walked:
                return
            try:
                size = os.path.getsize(fp)
            except OSError:
                continue
            yield Path(os.path.relpath(fp, root)).as_posix(), size


def _declared_names(root: Path, mf: ManifestFile) -> set[str]:
    """Best-effort dependency names declared in a manifest (for framework hints)."""
    text = safe_read_text(root, mf.path)
    names: set[str] = set()
    if text is None:
        return names
    try:
        if mf.name == "package.json":
            d = json.loads(text)
            for k in ("dependencies", "devDependencies", "peerDependencies", "optionalDependencies"):
                names |= set((d.get(k) or {}).keys())
        elif mf.name == "composer.json":
            d = json.loads(text)
            names |= set((d.get("require") or {}).keys()) | set((d.get("require-dev") or {}).keys())
        elif mf.name == "pyproject.toml":
            d = tomllib.loads(text)
            for dep in (d.get("project", {}).get("dependencies") or []):
                names.add(re.split(r"[<>=!~\[; ]", dep, 1)[0].strip().lower())
            for grp in (d.get("project", {}).get("optional-dependencies") or {}).values():
                for dep in grp:
                    names.add(re.split(r"[<>=!~\[; ]", dep, 1)[0].strip().lower())
            poetry = d.get("tool", {}).get("poetry", {})
            names |= {n.lower() for n in (poetry.get("dependencies") or {})}
            names |= {n.lower() for n in (poetry.get("dev-dependencies") or {})}
        elif mf.name.startswith("requirements") and mf.name.endswith(".txt"):
            for line in text.splitlines():
                line = line.split("#", 1)[0].strip()
                if line and not line.startswith("-"):
                    names.add(re.split(r"[<>=!~\[; ]", line, 1)[0].strip().lower())
        elif mf.name == "Cargo.toml":
            d = tomllib.loads(text)
            names |= set((d.get("dependencies") or {}).keys())
        elif mf.name == "go.mod":
            for m in re.finditer(r"^\s*(?:require\s+)?([\w.\-]+\.[\w.\-]+/[^\s]+)\s+v", text, re.M):
                names.add(m.group(1))
        elif mf.name in ("pom.xml", "build.gradle", "build.gradle.kts") or mf.name.endswith("proj"):
            names |= set(re.findall(r"[\w.\-]+", text))  # token bag; matched by substring below
    except Exception:
        pass
    return names


def inspect_repository(root: Path, settings: Settings | None = None) -> InspectionResult:
    s = settings or get_settings()
    root = Path(root)
    res = InspectionResult()
    lang_files: dict[str, int] = {}
    lang_bytes: dict[str, int] = {}
    dockers, containers, ci, unsupported = [], [], [], set()
    config_hits: list[FrameworkHit] = []
    total = 0
    for rel, size in walk_repo(root, s):
        total += 1
        name = rel.rsplit("/", 1)[-1]
        folder = rel.rsplit("/", 1)[0] if "/" in rel else "."
        ext = os.path.splitext(name)[1].lower()
        if ext in EXTENSION_LANGUAGES:
            lang = EXTENSION_LANGUAGES[ext]
            lang_files[lang] = lang_files.get(lang, 0) + 1
            lang_bytes[lang] = lang_bytes.get(lang, 0) + size
        c = _classify(name)
        if c:
            res.manifests.append(ManifestFile(path=rel, name=name, kind=c[0], ecosystem=c[1], service_dir=folder))
        if name in UNSUPPORTED_MANIFESTS:
            unsupported.add(f"{name} ({UNSUPPORTED_MANIFESTS[name] or 'Gradle'}) found at {rel}")
        if name == "Dockerfile" or name.startswith("Dockerfile.") or name.endswith(".dockerfile"):
            dockers.append(rel)
        if name in ("docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml", ".dockerignore"):
            containers.append(rel)
        if any(rel == p or rel.startswith(p) or rel.endswith("/" + p) for p in CI_FILE_PATTERNS):
            ci.append(rel)
        if name in FRAMEWORK_CONFIG_FILES:
            config_hits.append(FrameworkHit(name=FRAMEWORK_CONFIG_FILES[name], ecosystem="", service_dir=folder,
                                            evidence=f"config file {rel}"))
    res.total_files = total
    res.truncated = total > s.max_files_walked
    res.languages = {l: {"files": lang_files[l], "bytes": lang_bytes[l]}
                     for l in sorted(lang_files, key=lambda k: -lang_bytes[k])}
    res.dockerfiles, res.container_files, res.ci_files = sorted(dockers), sorted(containers), sorted(ci)
    res.unsupported = sorted(unsupported)
    res.ecosystems = sorted({m.ecosystem for m in res.manifests})

    # Frameworks from dependency declarations (manifest evidence, not extensions)
    seen = set()
    for mf in res.manifests:
        if mf.kind not in ("manifest", "lockfile") or mf.name.endswith(".lock"):
            continue
        declared = _declared_names(root, mf)
        hints = FRAMEWORK_HINTS.get(mf.ecosystem, {})
        low = {d.lower() for d in declared}
        for key, fw in hints.items():
            hit = key.lower() in low if mf.ecosystem not in ("Maven", "NuGet", "Packagist", "Go") else any(key.lower() in d for d in low)
            if hit and (fw, mf.service_dir) not in seen:
                seen.add((fw, mf.service_dir))
                res.frameworks.append(FrameworkHit(name=fw, ecosystem=mf.ecosystem, service_dir=mf.service_dir,
                                                   evidence=f"dependency declared in {mf.path}"))
    for h in config_hits:
        if (h.name, h.service_dir) not in seen:
            seen.add((h.name, h.service_dir))
            res.frameworks.append(h)

    # Services: every directory holding a manifest/lockfile
    svc: dict[str, dict] = {}
    for mf in res.manifests:
        d = svc.setdefault(mf.service_dir, {"dir": mf.service_dir, "ecosystems": set(), "files": [], "frameworks": []})
        d["ecosystems"].add(mf.ecosystem)
        d["files"].append(mf.path)
    for h in res.frameworks:
        if h.service_dir in svc and h.name not in svc[h.service_dir]["frameworks"]:
            svc[h.service_dir]["frameworks"].append(h.name)
    res.services = [{**v, "ecosystems": sorted(v["ecosystems"])} for _, v in sorted(svc.items())]

    if not res.manifests:
        res.limitations.append("No dependency manifests or lockfiles were found; SBOM coverage will be limited.")
    if res.truncated:
        res.limitations.append(f"File walk truncated at {s.max_files_walked} files.")
    if res.unsupported:
        res.limitations.append("Some detected ecosystems have no lockfile parser: " + "; ".join(res.unsupported))
    if res.dockerfiles or res.container_files:
        res.limitations.append("Container files were detected and recorded only; images are never built or scanned in this MVP.")
    if res.ci_files:
        res.limitations.append("CI/CD configuration was detected and recorded only; pipeline security analysis is not implemented.")
    return res


def service_for_path(path: str, services: list[str]) -> str:
    """Nearest ancestor service directory for a repo-relative file path ('.' = root)."""
    best, best_len = ".", -1
    for d in services:
        if d == ".":
            if best_len < 0:
                best, best_len = ".", 0
            continue
        if path == d or path.startswith(d.rstrip("/") + "/"):
            if len(d) > best_len:
                best, best_len = d, len(d)
    return best


def headline_languages(res: InspectionResult) -> list[str]:
    return [l for l in res.languages if l not in MARKUP_LANGUAGES]
