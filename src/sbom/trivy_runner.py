"""Controlled Trivy subprocess wrapper (SBOM generation only). No shell, argument list, captured output, timeout.

``--scanners license`` is used on purpose: it makes Trivy walk the lockfiles and emit the package inventory without
needing its vulnerability database (vulnerabilities are looked up separately against OSV).
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import time
from pathlib import Path
from typing import Optional

from config.settings import Settings, get_settings
from core.safe_env import scrubbed_env
from sbom.tool_locator import find_tool
from sbom.syft_runner import ScannerResult  # same result shape for every scanner


def resolve_trivy(settings: Settings | None = None) -> Optional[str]:
    cand = (settings or get_settings()).trivy_bin
    if os.path.sep in cand or "/" in cand:
        return cand if Path(cand).exists() else None
    return shutil.which(cand) or find_tool(cand)


def trivy_version(trivy_bin: str) -> Optional[str]:
    try:
        p = subprocess.run([trivy_bin, "--version"], capture_output=True, text=True, timeout=60, shell=False, env=scrubbed_env())
    except (OSError, subprocess.TimeoutExpired):
        return None
    for line in p.stdout.splitlines():
        if line.lower().startswith("version:"):
            return line.split(":", 1)[1].strip()
    return None


def build_command(trivy_bin: str, repo_dir: Path, out_path: Path) -> list[str]:
    return [trivy_bin, "fs", "--format", "cyclonedx", "--scanners", "license", "--include-dev-deps",
            "--skip-db-update", "--skip-java-db-update", "--offline-scan", "--quiet", "--output", str(Path(out_path).resolve()),
            str(Path(repo_dir).resolve())]


def run_trivy(repo_dir: Path, out_path: Path, settings: Settings | None = None) -> ScannerResult:
    s = settings or get_settings()
    trivy = resolve_trivy(s)
    if not trivy:
        return ScannerResult(ok=False, error="Trivy executable not found. Install Trivy (see README) or set TRIVY_BIN.", options={})
    out_path = Path(out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    if out_path.exists():
        out_path.unlink()
    cmd = build_command(trivy, repo_dir, out_path)
    res = ScannerResult(ok=False, command=cmd, version=trivy_version(trivy), options={"include-dev-deps": True, "scanners": "license"})
    t0 = time.time()
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace",
                           timeout=s.syft_timeout_s, shell=False, env=scrubbed_env({"TRIVY_DISABLE_TELEMETRY": "true", "TRIVY_SKIP_VERSION_CHECK": "true"}))
    except subprocess.TimeoutExpired:
        res.duration_s = round(time.time() - t0, 2)
        res.error = f"Trivy timed out after {s.syft_timeout_s}s"
        return res
    except OSError as e:
        res.error = f"Could not execute Trivy: {e}"
        return res
    res.duration_s = round(time.time() - t0, 2)
    res.exit_code, res.stdout, res.stderr = p.returncode, p.stdout, p.stderr
    if p.returncode != 0:
        res.error = f"Trivy exited with code {p.returncode}: {(p.stderr or p.stdout).strip()[-300:]}"
        return res
    if not out_path.exists():
        res.error = "Trivy reported success but produced no output file"
        return res
    try:
        json.loads(out_path.read_text(encoding="utf-8"))
    except Exception as e:
        res.error = f"Trivy output is not valid JSON: {e}"
        return res
    res.ok, res.sbom_path = True, str(out_path)
    return res
