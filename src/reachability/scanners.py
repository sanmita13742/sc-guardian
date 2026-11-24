"""Static reachability evidence: is a dependency actually imported by the application's own source code?

This is *package-level import evidence*, not a call graph: it tells you whether the application can load the package, not whether a specific
vulnerable function is called. The result is therefore worded as evidence ("imported in app code at file:line"), never as proof of exploitability,
and absence of an import is never "safe" (packages can be used through configuration, plugins, CLIs or reflection).

One pass over the working tree builds an index of imports per file; every package query is then a dictionary lookup. Files are only read
(size-capped, path-confined, vendored folders skipped); nothing is executed.
"""
from __future__ import annotations

import ast
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from config.constants import IGNORED_DIRS
from sbom.package_extractors.common import normalize_name

EXT_LANG = {".py": "py", ".js": "js", ".jsx": "js", ".mjs": "js", ".cjs": "js", ".ts": "js", ".tsx": "js", ".vue": "js", ".java": "java", ".kt": "java", ".scala": "java",
            ".go": "go", ".rs": "rs", ".php": "php", ".cs": "cs", ".rb": "rb"}
LANG_ECO = {"py": "PyPI", "js": "npm", "java": "Maven", "go": "Go", "rs": "crates.io", "php": "Packagist", "cs": "NuGet", "rb": "RubyGems"}
SKIP_DIRS = IGNORED_DIRS | {"vendor", "third_party", "third-party", "site-packages", "coverage", ".next", ".nuxt", "out", "bower_components", "external", "Pods"}
TEST_PARTS = ("/test/", "/tests/", "/__tests__/", "/spec/", "/specs/", "/e2e/", "/cypress/", "/fixtures/", "/mocks/", "/__mocks__/", "/testing/", "/benchmark/", "/benchmarks/")
TEST_NAME = re.compile(r"(^|[/\\])(test_[^/\\]*\.py|[^/\\]*_test\.(py|go)|[^/\\]*\.(test|spec)\.[jt]sx?|[^/\\]*Test\.(java|kt)|[^/\\]*Tests?\.cs|conftest\.py)$")
# distribution name -> import name where they differ (PyPI)
PY_ALIAS = {"pyyaml": "yaml", "pillow": "PIL", "beautifulsoup4": "bs4", "scikit-learn": "sklearn", "python-dateutil": "dateutil", "opencv-python": "cv2", "opencv-python-headless": "cv2",
            "protobuf": "google", "attrs": "attr", "pyjwt": "jwt", "python-dotenv": "dotenv", "pycryptodome": "Crypto", "pymysql": "pymysql", "mysqlclient": "MySQLdb", "psycopg2-binary": "psycopg2",
            "msgpack-python": "msgpack", "pytest-cov": "pytest_cov", "ruamel-yaml": "ruamel", "typing-extensions": "typing_extensions", "setuptools": "pkg_resources", "importlib-metadata": "importlib_metadata",
            "google-auth": "google", "azure-storage-blob": "azure", "markdown": "markdown", "docker": "docker", "websocket-client": "websocket", "python-jose": "jose", "pyopenssl": "OpenSSL"}

_JS_IMPORT = re.compile(r"""(?:require\(\s*|\bfrom\s+|\bimport\s*\(\s*|\bimport\s+)['"]([^'"\n]+)['"]""")
_JAVA = re.compile(r"^\s*import\s+(?:static\s+)?([\w.]+)\s*;", re.M)
_GO_SINGLE = re.compile(r'^\s*import\s+(?:[\w._]+\s+)?"([^"]+)"', re.M)
_GO_BLOCK = re.compile(r"^\s*import\s*\((.*?)\)", re.M | re.S)
_GO_LINE = re.compile(r'^\s*(?:[\w._]+\s+)?"([^"]+)"', re.M)
_RUST = re.compile(r"^\s*(?:pub\s+)?use\s+([A-Za-z_][\w]*)(?:::|;)|^\s*extern\s+crate\s+([A-Za-z_]\w*)", re.M)
_PHP = re.compile(r"^\s*use\s+(?:function\s+|const\s+)?([A-Za-z_][\w\\]*)", re.M)
_CS = re.compile(r"^\s*using\s+(?:static\s+)?([\w.]+)\s*;", re.M)
_RB = re.compile(r"""^\s*require(?:_relative)?\s*\(?\s*['"]([^'"]+)['"]""", re.M)
_PY = re.compile(r"^\s*(?:from\s+([\w.]+)\s+import|import\s+([\w.]+(?:\s*,\s*[\w.]+)*))", re.M)


@dataclass
class Usage:
    path: str
    line: int
    module: str
    test: bool


@dataclass
class SourceIndex:
    root: Path
    by_lang: dict[str, list[Usage]] = field(default_factory=dict)
    files_by_lang: dict[str, int] = field(default_factory=dict)
    skipped: int = 0
    truncated: bool = False

    @property
    def languages(self) -> list[str]:
        return sorted(l for l, n in self.files_by_lang.items() if n)


def _is_test(rel: str) -> bool:
    r = "/" + rel.replace("\\", "/")
    return any(p in r for p in TEST_PARTS) or bool(TEST_NAME.search(r))


def _line_of(text: str, pos: int) -> int:
    return text.count("\n", 0, pos) + 1


def _extract(lang: str, text: str) -> list[tuple[str, int]]:
    out: list[tuple[str, int]] = []
    if lang == "py":
        try:
            for n in ast.walk(ast.parse(text)):
                if isinstance(n, ast.Import):
                    out += [(a.name, n.lineno) for a in n.names]
                elif isinstance(n, ast.ImportFrom) and n.module and n.level == 0:
                    out.append((n.module, n.lineno))
            return out
        except (SyntaxError, ValueError, RecursionError):
            for m in _PY.finditer(text):
                for mod in re.split(r"\s*,\s*", m.group(1) or m.group(2) or ""):
                    if mod:
                        out.append((mod.strip(), _line_of(text, m.start())))
            return out
    if lang == "js":
        return [(m.group(1), _line_of(text, m.start())) for m in _JS_IMPORT.finditer(text) if not m.group(1).startswith((".", "/"))]
    if lang == "java":
        return [(m.group(1), _line_of(text, m.start())) for m in _JAVA.finditer(text)]
    if lang == "go":
        for m in _GO_SINGLE.finditer(text):
            out.append((m.group(1), _line_of(text, m.start())))
        for b in _GO_BLOCK.finditer(text):
            base = _line_of(text, b.start())
            for ln in _GO_LINE.finditer(b.group(1)):
                out.append((ln.group(1), base + b.group(1).count("\n", 0, ln.start())))
        return out
    if lang == "rs":
        return [(m.group(1) or m.group(2), _line_of(text, m.start())) for m in _RUST.finditer(text)]
    if lang == "php":
        return [(m.group(1), _line_of(text, m.start())) for m in _PHP.finditer(text)]
    if lang == "cs":
        return [(m.group(1), _line_of(text, m.start())) for m in _CS.finditer(text)]
    if lang == "rb":
        return [(m.group(1), _line_of(text, m.start())) for m in _RB.finditer(text)]
    return out


def build_index(root: Path, max_files: int = 6000, max_bytes: int = 1_000_000) -> SourceIndex:
    idx = SourceIndex(root=Path(root))
    n = 0
    for dp, dirs, files in os.walk(root, followlinks=False):
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS and not d.startswith(".git")]
        for f in files:
            lang = EXT_LANG.get(os.path.splitext(f)[1].lower())
            if not lang:
                continue
            p = Path(dp) / f
            try:
                if p.is_symlink() or p.stat().st_size > max_bytes:
                    idx.skipped += 1
                    continue
                text = p.read_text(encoding="utf-8", errors="replace")
            except OSError:
                idx.skipped += 1
                continue
            n += 1
            if n > max_files:
                idx.truncated = True
                return idx
            rel = p.relative_to(root).as_posix()
            idx.files_by_lang[lang] = idx.files_by_lang.get(lang, 0) + 1
            tst = _is_test(rel)
            idx.by_lang.setdefault(lang, []).extend(Usage(rel, ln, mod, tst) for mod, ln in _extract(lang, text))
    return idx


def _matches(eco: str, name: str, module: str) -> bool:
    m = module
    if eco == "npm":
        return m == name or m.startswith(name + "/")
    if eco == "PyPI":
        top = m.split(".")[0].lower()
        n = normalize_name("PyPI", name)
        cands = {n.replace("-", "_"), n.replace("-", "")}
        if n in PY_ALIAS:
            cands.add(PY_ALIAS[n].lower())
        if n.startswith("python-"):
            cands.add(n[7:].replace("-", "_"))
        if n.endswith("-python"):
            cands.add(n[:-7].replace("-", "_"))
        return top in cands
    if eco == "Maven":
        g, _, a = name.partition(":")
        return bool(g) and (m == g or m.startswith(g + "."))
    if eco == "Go":
        return m == name or m.startswith(name + "/")
    if eco == "crates.io":
        return m.split("::")[0] == name.replace("-", "_")
    if eco == "Packagist":
        vendor, _, pkg = name.lower().partition("/")
        first = m.lower().split("\\")[0]
        return first == vendor.replace("-", "") or first == vendor.replace("-", "_")
    if eco == "NuGet":
        return m.lower() == name.lower() or m.lower().startswith(name.lower() + ".")
    if eco == "RubyGems":
        return m == name or m == name.replace("-", "/") or m.startswith(name + "/")
    return False


def package_usage(idx: SourceIndex, eco: str, name: str, limit: int = 5) -> dict:
    """Evidence for one package. ``status``: used_by_app | used_in_tests_only | not_imported | unknown (no analysable source for the ecosystem)."""
    lang = next((l for l, e in LANG_ECO.items() if e == eco), None)
    if not lang or not idx.files_by_lang.get(lang):
        return {"status": "unknown", "reason": f"no {eco} source files were analysed", "app_files": 0, "test_files": 0, "locations": [], "confidence": "none",
                "import_density": "none", "import_ratio": 0.0, "influence_tier": "unknown"}
    hits = [u for u in idx.by_lang.get(lang, []) if _matches(eco, name, u.module)]
    app = [u for u in hits if not u.test]
    tst = [u for u in hits if u.test]
    conf = "medium" if eco in ("Maven", "Packagist", "NuGet") else "high"
    locs = [{"path": u.path, "line": u.line, "module": u.module, "test": u.test} for u in (app + tst)[:limit]]
    total_files = idx.files_by_lang.get(lang, 0)
    app_files_count = len({u.path for u in app})
    test_files_count = len({u.path for u in tst})
    import_ratio = round(app_files_count / max(1, total_files), 3)

    if app_files_count >= 5 or (total_files > 0 and import_ratio >= 0.15):
        density = "heavy"
        tier = "heavy"
    elif app_files_count >= 2:
        density = "moderate"
        tier = "moderate"
    elif app_files_count == 1:
        density = "light"
        tier = "light"
    elif test_files_count > 0:
        density = "test_only"
        tier = "tests_only"
    else:
        density = "none"
        tier = "not_imported"

    base = {"app_files": app_files_count, "test_files": test_files_count, "locations": locs, "confidence": conf, "files_analysed": total_files,
            "truncated": idx.truncated, "import_density": density, "import_ratio": import_ratio, "influence_tier": tier}
    if app:
        return {**base, "status": "used_by_app"}
    if tst:
        return {**base, "status": "used_in_tests_only"}
    return {**base, "status": "not_imported", "reason": "no import found in analysed source; the package may still be used through configuration, plugins, a CLI or reflection"}
