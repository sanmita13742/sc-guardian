"""Controlled Syft subprocess wrapper. No shell, argument list only, captured output, timeout."""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Optional

from config.settings import Settings, get_settings


@dataclass
class SyftResult:
    ok: bool
    command: list[str] = field(default_factory=list)
    exit_code: Optional[int] = None
    stdout: str = ""
    stderr: str = ""
    duration_s: float = 0.0
    version: Optional[str] = None
    sbom_path: Optional[str] = None
    error: Optional[str] = None
    options: dict = field(default_factory=lambda: {"javascript.include-dev-dependencies": True})

    def to_dict(self) -> dict:
        d = asdict(self)
        d["stdout"] = self.stdout[-2000:]
        d["stderr"] = self.stderr[-2000:]
        return d


def resolve_syft(settings: Settings | None = None) -> Optional[str]:
    s = settings or get_settings()
    cand = s.syft_bin
    if os.path.sep in cand or "/" in cand:
        return cand if Path(cand).exists() else None
    return shutil.which(cand)


def syft_version(syft_bin: str) -> Optional[str]:
    try:
        p = subprocess.run([syft_bin, "version"], capture_output=True, text=True, timeout=20, shell=False)
    except (OSError, subprocess.TimeoutExpired):
        return None
    for line in p.stdout.splitlines():
        if line.lower().startswith("version:"):
            return line.split(":", 1)[1].strip()
    return p.stdout.strip() or None


def build_command(syft_bin: str, repo_dir: Path, out_path: Path) -> list[str]:
    return [syft_bin, "scan", f"dir:{Path(repo_dir).resolve()}", "-o", f"cyclonedx-json={Path(out_path).resolve()}", "-q"]


def run_syft(repo_dir: Path, out_path: Path, settings: Settings | None = None) -> SyftResult:
    s = settings or get_settings()
    syft = resolve_syft(s)
    if not syft:
        return SyftResult(ok=False, error="Syft executable not found. Install Syft (see README) or set SYFT_BIN.")
    out_path = Path(out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    if out_path.exists():
        out_path.unlink()
    cmd = build_command(syft, repo_dir, out_path)
    res = SyftResult(ok=False, command=cmd, version=syft_version(syft))
    env = dict(os.environ, SYFT_CHECK_FOR_APP_UPDATE="false", SYFT_JAVASCRIPT_INCLUDE_DEV_DEPENDENCIES="true")
    t0 = time.time()
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace",
                           timeout=s.syft_timeout_s, shell=False, env=env)
    except subprocess.TimeoutExpired:
        res.duration_s = time.time() - t0
        res.error = f"Syft timed out after {s.syft_timeout_s}s"
        return res
    except OSError as e:
        res.error = f"Could not execute Syft: {e}"
        return res
    res.duration_s = round(time.time() - t0, 2)
    res.exit_code, res.stdout, res.stderr = p.returncode, p.stdout, p.stderr
    if p.returncode != 0:
        res.error = f"Syft exited with code {p.returncode}: {p.stderr.strip()[:300]}"
        return res
    if not out_path.exists():
        res.error = "Syft reported success but produced no output file"
        return res
    try:
        json.loads(out_path.read_text(encoding="utf-8"))
    except Exception as e:
        res.error = f"Syft output is not valid JSON: {e}"
        return res
    res.ok, res.sbom_path = True, str(out_path)
    return res
