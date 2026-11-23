"""SBOM scanner selection engine.

Strategy ``auto`` tries the scanners in priority order and falls through on failure:

    1. Syft   (best coverage of container/OS/binary catalogers)
    2. Trivy  (lockfile-oriented, no vulnerability DB needed)
    3. built-in rule engine (always available; lockfile/manifest parsing, see ``builtin_generator``)

Choosing a specific scanner tries it first and still falls back to the rule engine, so a CycloneDX file exists for
every scan that has any dependency evidence. Every attempt is recorded so the UI can show what was tried and why.
The raw scanner output is stored untouched; Trivy documents are normalised in memory (never rewritten on disk).
"""
from __future__ import annotations

import copy
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from config.settings import Settings
from core.models import LockDependency
from sbom.builtin_generator import TOOL_NAME, generate_cyclonedx
from sbom.cyclonedx_validator import load_sbom
from sbom.syft_runner import SyftResult, resolve_syft, run_syft
from sbom.trivy_runner import resolve_trivy, run_trivy

SCANNER_CHOICES = ("auto", "syft", "trivy", "builtin")
SCANNER_LABELS = {"auto": "Auto (Syft → Trivy → built-in rules)", "syft": "Syft", "trivy": "Trivy", "builtin": "Built-in rule engine"}


@dataclass
class SbomOutcome:
    scanner: Optional[str] = None  # syft | trivy | builtin | None
    raw_path: Optional[str] = None  # file exactly as the scanner wrote it
    doc: dict = field(default_factory=dict)  # normalised document used for analysis
    run: Optional[SyftResult] = None  # command/version/duration of the winning external scanner
    attempts: list[dict] = field(default_factory=list)
    engine_stats: dict = field(default_factory=dict)  # built-in rule engine counters
    requested: str = "auto"


def available_scanners(settings: Settings) -> dict:
    return {"syft": resolve_syft(settings), "trivy": resolve_trivy(settings), "builtin": "built-in"}


def plan(choice: str, settings: Settings) -> list[str]:
    """Ordered list of scanners that will be tried (unavailable ones are listed too so the UI can explain skips)."""
    choice = choice if choice in SCANNER_CHOICES else "auto"
    order = ["syft", "trivy", "builtin"] if choice == "auto" else [choice] + [s for s in ("builtin",) if s != choice]
    return order


def normalize_trivy(doc: dict) -> dict:
    """Trivy emits one ``application`` component per lockfile plus a root. Fold them into per-package locations."""
    d = copy.deepcopy(doc)
    comps = d.get("components") or []
    deps = d.get("dependencies") or []
    apps = {c.get("bom-ref"): c for c in comps if c.get("type") == "application" and not c.get("purl")}
    loc_of: dict[str, str] = {}
    for rec in deps:
        app = apps.get(rec.get("ref"))
        if app:
            for t in rec.get("dependsOn") or []:
                loc_of.setdefault(t, app.get("name", ""))
    meta_root = ((d.get("metadata") or {}).get("component") or {}).get("bom-ref")
    out = []
    for c in comps:
        if c.get("bom-ref") in apps:
            continue
        loc = loc_of.get(c.get("bom-ref"))
        if loc:
            c.setdefault("properties", []).append({"name": "sc-guardian:location:0:path", "value": loc})
        out.append(c)
    d["components"] = out
    d["dependencies"] = [r for r in deps if r.get("ref") not in apps and r.get("ref") != meta_root]
    return d


def generate_sbom(repo_dir: Path, lock_deps: list[LockDependency], out_dir: Path, prefix: str, choice: str,
                  settings: Settings, repo_name: str, commit_sha: str = "") -> SbomOutcome:
    out = SbomOutcome(requested=choice)
    out_dir.mkdir(parents=True, exist_ok=True)
    for name in plan(choice, settings):
        if name in ("syft", "trivy"):
            path = out_dir / f"{prefix}.{name}.cdx.json"
            res = (run_syft if name == "syft" else run_trivy)(repo_dir, path, settings)
            att = {"scanner": name, "ok": res.ok, "version": res.version, "duration_s": res.duration_s, "error": res.error,
                   "command": " ".join(res.command) if res.command else None}
            out.attempts.append(att)
            if not res.ok:
                continue
            try:
                raw = load_sbom(res.sbom_path)
            except Exception as e:  # unreadable output counts as a failed attempt
                att.update(ok=False, error=f"unreadable output: {e}")
                continue
            out.scanner, out.raw_path, out.run = name, res.sbom_path, res
            out.doc = normalize_trivy(raw) if name == "trivy" else raw
            return out
        # built-in rule engine
        doc, stats = generate_cyclonedx(lock_deps, repo_name, commit_sha)
        path = out_dir / f"{prefix}.builtin.cdx.json"
        path.write_text(json.dumps(doc, indent=2), encoding="utf-8")
        out.attempts.append({"scanner": "builtin", "ok": True, "version": None, "duration_s": 0.0, "error": None,
                             "command": f"{TOOL_NAME} (in-process, {len(lock_deps)} lockfile/manifest records)"})
        out.scanner, out.raw_path, out.doc, out.engine_stats = "builtin", str(path), doc, stats
        return out
    return out
