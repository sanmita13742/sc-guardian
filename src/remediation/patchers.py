"""Per-ecosystem manifest patch generators. Pure functions: (manifest text, change) -> new text, rendered as a unified diff.

Two kinds of change:
  bump  - raise the version of a *direct* dependency
  pin   - force a *transitive* dependency to a fixed version (npm overrides/resolutions, pip constraint line, Maven dependencyManagement, ...)

A patcher returns None when it cannot make a safe, minimal textual change; the plan then carries instructions only. Patches are never
applied by the Guardian: they are proposals that a human approves and applies (``git apply``).
"""
from __future__ import annotations

import difflib
import json
import re
from typing import Optional

from sbom.package_extractors.common import normalize_name


def unified_diff(path: str, old: str, new: str) -> str:
    return "".join(difflib.unified_diff(old.splitlines(keepends=True), new.splitlines(keepends=True), fromfile=f"a/{path}", tofile=f"b/{path}", n=3))


def _indent_of(text: str) -> str | int:
    m = re.search(r"^(\s+)\"", text, re.M)
    if not m:
        return 2
    return "\t" if "\t" in m.group(1) else len(m.group(1))


def _json_dump(data: dict, original: str) -> str:
    out = json.dumps(data, indent=_indent_of(original), ensure_ascii=False)
    return out + ("\n" if original.endswith("\n") else "")


# ------------------------------------------------------------------ npm
def npm(text: str, name: str, to: str, kind: str, lock_hint: str = "") -> Optional[str]:
    if kind == "bump":
        pat = re.compile(r'("' + re.escape(name) + r'"\s*:\s*")([\^~]|>=)?([^"]+)(")')
        m = pat.search(text)
        if not m:
            return None
        return text[:m.start()] + f"{m.group(1)}{m.group(2) or ''}{to}{m.group(4)}" + text[m.end():]
    try:
        data = json.loads(text)
    except ValueError:
        return None
    if not isinstance(data, dict):
        return None
    for sec in ("dependencies", "devDependencies", "optionalDependencies"):
        cur = (data.get(sec) or {}).get(name)
        if isinstance(cur, str):  # a direct dependency: raise its own spec; an override here would make npm fail with EOVERRIDE
            data[sec][name] = ("~" if cur.startswith("~") else "^") + to
            return _json_dump(data, text)
    if "yarn" in lock_hint:
        data.setdefault("resolutions", {})[name] = to
    elif "pnpm" in lock_hint:
        data.setdefault("pnpm", {}).setdefault("overrides", {})[name] = to
    else:
        data.setdefault("overrides", {})[name] = to
    return _json_dump(data, text)


# ------------------------------------------------------------------ PyPI
def pypi_requirements(text: str, name: str, to: str, kind: str) -> Optional[str]:
    n = normalize_name("PyPI", name)
    lines = text.splitlines(keepends=True)
    for i, ln in enumerate(lines):
        m = re.match(r"^(\s*)([A-Za-z0-9_.\-]+)(\[[^\]]*\])?\s*(==|>=|~=|<=|>|<|!=)?\s*([^\s;#,]+)?(.*)$", ln)
        if m and normalize_name("PyPI", m.group(2)) == n and not ln.lstrip().startswith(("#", "-")):
            if kind == "bump":
                op = m.group(4) if m.group(4) in ("==", "~=", ">=") else "=="
                lines[i] = f"{m.group(1)}{m.group(2)}{m.group(3) or ''}{op}{to}{m.group(6)}\n" if ln.endswith("\n") else f"{m.group(1)}{m.group(2)}{m.group(3) or ''}{op}{to}{m.group(6)}"
                return "".join(lines)
    if kind == "pin":
        sep = "" if text.endswith("\n") or not text else "\n"
        return text + f"{sep}{name}>={to}  # guardian: constraint for a vulnerable transitive dependency\n"
    return None


def pypi_pyproject(text: str, name: str, to: str, kind: str) -> Optional[str]:
    if kind != "bump":
        return None
    n = re.escape(name)
    pat = re.compile(r'(["\']' + n + r'(?:\[[^\]]*\])?\s*)(==|>=|~=|\^)?\s*[0-9][^"\',\]]*(["\'])', re.I)
    m = pat.search(text)
    if not m:
        pat2 = re.compile(r'^(\s*' + n + r'\s*=\s*["\'])[\^~>=]*[0-9][^"\']*(["\'])', re.M | re.I)  # poetry style
        m2 = pat2.search(text)
        return (text[:m2.start()] + f"{m2.group(1)}^{to}{m2.group(2)}" + text[m2.end():]) if m2 else None
    return text[:m.start()] + f"{m.group(1)}{m.group(2) or '>='}{to}{m.group(3)}" + text[m.end():]


# ------------------------------------------------------------------ Maven
def maven(text: str, name: str, to: str, kind: str) -> Optional[str]:
    g, _, a = name.partition(":")
    if not a:
        return None
    if kind == "bump":
        for m in re.finditer(r"<dependency>.*?</dependency>", text, re.S):
            blk = m.group(0)
            if re.search(r"<groupId>\s*" + re.escape(g) + r"\s*</groupId>", blk) and re.search(r"<artifactId>\s*" + re.escape(a) + r"\s*</artifactId>", blk):
                v = re.search(r"<version>\s*([^<]+?)\s*</version>", blk)
                if not v:
                    return None
                ver = v.group(1)
                pm = re.match(r"^\$\{([^}]+)\}$", ver)
                if pm:  # version comes from a property: change the property definition
                    prop = re.search(r"(<" + re.escape(pm.group(1)) + r">\s*)([^<]+?)(\s*</" + re.escape(pm.group(1)) + r">)", text)
                    return (text[:prop.start()] + prop.group(1) + to + prop.group(3) + text[prop.end():]) if prop else None
                nb = blk[:v.start(1)] + to + blk[v.end(1):]
                return text[:m.start()] + nb + text[m.end():]
        return None
    entry = (f"      <dependency>\n        <groupId>{g}</groupId>\n        <artifactId>{a}</artifactId>\n        <version>{to}</version>\n      </dependency>\n")
    dm = re.search(r"<dependencyManagement>.*?</dependencyManagement>", text, re.S)
    if dm:
        close = dm.group(0).rfind("</dependencies>")
        if close < 0:
            return None
        pos = dm.start() + close
        return text[:pos] + entry + "    " + text[pos:]
    top = re.search(r"^(\s*)<dependencies>", text, re.M)
    if not top:
        return None
    block = f"{top.group(1)}<dependencyManagement>\n{top.group(1)}  <dependencies>\n{entry}{top.group(1)}  </dependencies>\n{top.group(1)}</dependencyManagement>\n"
    return text[:top.start()] + block + text[top.start():]


# ------------------------------------------------------------------ Go / Cargo / Composer / NuGet
def go(text: str, name: str, to: str, kind: str) -> Optional[str]:
    to = to if to.startswith("v") else "v" + to
    pat = re.compile(r"^(\s*(?:require\s+)?" + re.escape(name) + r"\s+)v[^\s]+((?:\s*//.*)?)$", re.M)
    m = pat.search(text)
    if m:
        return text[:m.start()] + f"{m.group(1)}{to}{m.group(2)}" + text[m.end():]
    if kind == "pin":
        rb = re.search(r"^require\s*\((.*?)^\)", text, re.M | re.S)
        if rb:
            pos = rb.end() - 1
            return text[:pos] + f"\t{name} {to} // indirect\n" + text[pos:]
        return text + ("" if text.endswith("\n") else "\n") + f"\nrequire {name} {to} // indirect\n"
    return None


def cargo(text: str, name: str, to: str, kind: str) -> Optional[str]:
    if kind != "bump":
        return None
    p1 = re.compile(r'^(\s*' + re.escape(name) + r'\s*=\s*")[\^~=]?[0-9][^"]*(")', re.M)
    m = p1.search(text)
    if m:
        return text[:m.start()] + f"{m.group(1)}{to}{m.group(2)}" + text[m.end():]
    p2 = re.compile(r'^(\s*' + re.escape(name) + r'\s*=\s*\{[^}]*version\s*=\s*")[\^~=]?[0-9][^"]*(")', re.M)
    m = p2.search(text)
    return (text[:m.start()] + f"{m.group(1)}{to}{m.group(2)}" + text[m.end():]) if m else None


def composer(text: str, name: str, to: str, kind: str) -> Optional[str]:
    try:
        data = json.loads(text)
    except ValueError:
        return None
    for sec in ("require", "require-dev"):
        if name in (data.get(sec) or {}):
            cur = data[sec][name]
            data[sec][name] = ("^" if cur.startswith("^") else "~" if cur.startswith("~") else "") + to.lstrip("v")
            return _json_dump(data, text)
    if kind == "pin":
        data.setdefault("require", {})[name] = ">=" + to.lstrip("v")
        return _json_dump(data, text)
    return None


def nuget(text: str, name: str, to: str, kind: str) -> Optional[str]:
    pat = re.compile(r'(<PackageReference\s+[^>]*Include\s*=\s*"' + re.escape(name) + r'"[^>]*Version\s*=\s*")[^"]+(")', re.I)
    m = pat.search(text)
    if m:
        return text[:m.start()] + f"{m.group(1)}{to}{m.group(2)}" + text[m.end():]
    if kind == "pin":
        close = text.rfind("</Project>")
        if close > 0:
            return text[:close] + f'  <ItemGroup>\n    <PackageReference Include="{name}" Version="{to}" />\n  </ItemGroup>\n' + text[close:]
    return None


def patch_for(eco: str, manifest_path: str, text: str, name: str, to: str, kind: str, lock_hint: str = "") -> Optional[dict]:
    """Return {path, diff, new_text} or None."""
    base = manifest_path.rsplit("/", 1)[-1]
    new: Optional[str] = None
    if eco == "npm" and base == "package.json":
        new = npm(text, name, to, kind, lock_hint)
    elif eco == "PyPI" and base.startswith("requirements") and base.endswith(".txt"):
        new = pypi_requirements(text, name, to, kind)
    elif eco == "PyPI" and base == "pyproject.toml":
        new = pypi_pyproject(text, name, to, kind)
    elif eco == "Maven" and base == "pom.xml":
        new = maven(text, name, to, kind)
    elif eco == "Go" and base == "go.mod":
        new = go(text, name, to, kind)
    elif eco == "crates.io" and base == "Cargo.toml":
        new = cargo(text, name, to, kind)
    elif eco == "Packagist" and base == "composer.json":
        new = composer(text, name, to, kind)
    elif eco == "NuGet" and base.endswith("proj"):
        new = nuget(text, name, to, kind)
    if new is None or new == text:
        return None
    return {"path": manifest_path, "diff": unified_diff(manifest_path, text, new), "new_text": new}
