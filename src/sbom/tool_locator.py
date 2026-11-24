"""Locate external scanner binaries (Syft, Trivy) even when the running process has a stale PATH.

Installers such as winget/choco/scoop add their folder to the *registry* PATH, which processes started earlier (an open
terminal, VS Code, a running Streamlit server) never see. ``find_tool`` therefore checks, in order: the process PATH, the
current Windows registry PATH (user + machine), and the usual install locations.
"""
from __future__ import annotations

import os
import shutil
import sys
from pathlib import Path
from typing import Optional


def _registry_path_dirs() -> list[str]:
    if sys.platform != "win32":
        return []
    dirs: list[str] = []
    try:
        import winreg
        for hive, sub in ((winreg.HKEY_CURRENT_USER, r"Environment"),
                          (winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Control\Session Manager\Environment")):
            try:
                with winreg.OpenKey(hive, sub) as k:
                    val, _ = winreg.QueryValueEx(k, "Path")
                dirs += [os.path.expandvars(p) for p in str(val).split(os.pathsep) if p]
            except OSError:
                continue
    except ImportError:
        pass
    return dirs


def _known_dirs(name: str) -> list[Path]:
    home = Path.home()
    out: list[Path] = [home / "bin", home / ".local" / "bin", home / "go" / "bin", Path("/usr/local/bin"), Path("/opt/homebrew/bin")]
    if sys.platform == "win32":
        local = Path(os.environ.get("LOCALAPPDATA", home / "AppData" / "Local"))
        pf = [Path(os.environ.get(v, d)) for v, d in (("ProgramFiles", r"C:\Program Files"), ("ProgramFiles(x86)", r"C:\Program Files (x86)"))]
        out += [local / "Microsoft" / "WinGet" / "Links", home / "scoop" / "shims", Path(os.environ.get("ChocolateyInstall", r"C:\ProgramData\chocolatey")) / "bin"]
        out += [p / name for p in pf]
        pkgs = local / "Microsoft" / "WinGet" / "Packages"  # winget "portable" packages live in one folder per package
        if pkgs.is_dir():
            out += [d for d in pkgs.iterdir() if d.is_dir() and name.lower() in d.name.lower()]
    return out


def find_tool(name: str) -> Optional[str]:
    """Return the full path of ``name`` (e.g. 'syft', 'trivy') or None."""
    hit = shutil.which(name)
    if hit:
        return hit
    for d in _registry_path_dirs():
        hit = shutil.which(name, path=d)
        if hit:
            return hit
    for d in _known_dirs(name):
        try:
            hit = shutil.which(name, path=str(d))
        except OSError:
            hit = None
        if hit:
            return hit
    return None
