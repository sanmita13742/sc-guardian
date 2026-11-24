"""Integrity and provenance evidence for one validation run.

Produces an in-toto v1 Statement with an SLSA-provenance-v1-shaped predicate. The statement is **unsigned** unless a signing step is
added later (e.g. ``cosign sign-blob``); the report always states which, and never claims verification it did not perform.
"""
from __future__ import annotations

import hashlib
import shutil
import subprocess
from pathlib import Path
from typing import Any, Optional

from core.safe_env import scrubbed_env

STATEMENT_TYPE = "https://in-toto.io/Statement/v1"
PREDICATE_TYPE = "https://slsa.dev/provenance/v1"
BUILD_TYPE = "https://sc-guardian.local/fix-validation/v1"


def sha256_bytes(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def sha256_text(t: str) -> str:
    return sha256_bytes(t.encode("utf-8"))


def sha256_file(p: Path) -> Optional[str]:
    try:
        h = hashlib.sha256()
        with open(p, "rb") as f:
            for chunk in iter(lambda: f.read(1 << 20), b""):
                h.update(chunk)
        return h.hexdigest()
    except OSError:
        return None


def docker_image_digest(exe: Optional[str], image: Optional[str]) -> Optional[str]:
    """Repo digest of a locally pulled image (``name@sha256:...``), or None when unknown."""
    if not exe or not image:
        return None
    try:
        p = subprocess.run([exe, "image", "inspect", "--format", "{{index .RepoDigests 0}}", image], capture_output=True, text=True, timeout=30,
                           shell=False, env=scrubbed_env())
    except (OSError, subprocess.TimeoutExpired):
        return None
    out = p.stdout.strip()
    return out if p.returncode == 0 and "@sha256:" in out else None


def subject(name: str, path: Path) -> Optional[dict[str, Any]]:
    d = sha256_file(path)
    return {"name": name, "digest": {"sha256": d}} if d else None


def statement(subjects: list[dict], *, repo_url: str, commit_sha: str, patch_sha256: Optional[str], remediation_id: str,
              recipe: Optional[dict], image_digest: Optional[str], started_on: str, finished_on: str, tool_version: str, image: Optional[str] = None) -> dict[str, Any]:
    materials = [{"uri": f"git+{repo_url}@{commit_sha}", "digest": {"gitCommit": commit_sha}}]
    if patch_sha256:
        materials.append({"uri": f"remediation:{remediation_id}.patch", "digest": {"sha256": patch_sha256}})
    if image_digest:
        name, _, dig = image_digest.partition("@")
        materials.append({"uri": f"docker://{image or name}", "digest": {dig.split(":")[0]: dig.split(":")[1]}})
    return {
        "_type": STATEMENT_TYPE,
        "subject": [s for s in subjects if s],
        "predicateType": PREDICATE_TYPE,
        "predicate": {
            "buildDefinition": {"buildType": BUILD_TYPE, "externalParameters": {"remediation_id": remediation_id, "recipe": recipe},
                                "resolvedDependencies": materials},
            "runDetails": {"builder": {"id": "sc-guardian/fix-validator", "version": {"sc-guardian": tool_version}},
                           "metadata": {"startedOn": started_on, "finishedOn": finished_on}},
        },
    }


def signature_status() -> dict[str, Any]:
    """Signing is not performed yet; report what is available so the gap is explicit."""
    return {"signed": False, "cosign_available": shutil.which("cosign") is not None,
            "note": "Statement is unsigned; digests are recorded for independent re-verification."}
