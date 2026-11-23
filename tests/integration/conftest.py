import json
import shutil
import socket
import subprocess
from pathlib import Path

import pytest

from config.settings import Settings
from storage.database import Database

ROOT = Path(__file__).resolve().parents[2]
FIX = ROOT / "tests" / "fixtures"
RECORDS = ROOT / "artifacts" / "scans" / "integration-test-records.json"


def online(host="api.osv.dev") -> bool:
    try:
        socket.create_connection((host, 443), timeout=5).close()
        return True
    except OSError:
        return False


@pytest.fixture
def isolated(tmp_path):
    """Settings/DB pointing at a temp dir so integration runs never touch the real database or artifacts."""
    s = Settings(data_dir=tmp_path / "data", workspace_dir=tmp_path / "ws", artifacts_dir=tmp_path / "artifacts")
    for p in (s.data_dir, s.workspace_dir, *(s.artifacts_dir / x for x in ("sbom", "scans", "reports", "graphs"))):
        p.mkdir(parents=True, exist_ok=True)
    return s, Database(s.db_path)


def git(repo, *args):
    subprocess.run(["git", "-c", "user.name=t", "-c", "user.email=t@example.com", "-c", "commit.gpgsign=false", *args],
                   cwd=repo, check=True, capture_output=True)


@pytest.fixture
def monorepo_git(tmp_path):
    """The monorepo fixture as a real Git repo with a suspicious second commit (integrity change + git-sourced dependency)."""
    dst = tmp_path / "monorepo"
    shutil.copytree(FIX / "monorepo", dst)
    git(dst, "init", "-q")
    git(dst, "add", "-A")
    git(dst, "commit", "-q", "-m", "initial import")
    lp = dst / "frontend" / "package-lock.json"
    data = json.loads(lp.read_text())
    data["packages"]["node_modules/lodash"]["integrity"] = "sha512-TAMPEREDTAMPEREDTAMPEREDTAMPEREDTAMPEREDTAMPEREDTAMPEREDTAMPEREDTAMPEREDTAMPERED=="
    data["packages"]["node_modules/left-pad-ng"] = {"version": "1.0.0", "resolved": "git+https://example.com/left-pad-ng.git#abc123"}
    lp.write_text(json.dumps(data, indent=2))
    git(dst, "add", "-A")
    git(dst, "commit", "-q", "-m", "update deps")
    return dst


def record(name: str, result: dict, passed: bool, extra: dict | None = None) -> None:
    """Append an integration-run record (fixture, revision, SBOM/graph/vuln status, findings, paths, outcome)."""
    try:
        RECORDS.parent.mkdir(parents=True, exist_ok=True)
        existing = json.loads(RECORDS.read_text()) if RECORDS.exists() else []
        v = result.get("vulnerabilities", [])
        existing.append({
            "test": name, "repository": result["repo"]["url"], "revision": result["repo"]["commit_sha"],
            "sbom": {"inventory_source": result.get("inventory_source"), "valid": result.get("sbom", {}).get("validation", {}).get("valid"),
                     "components": result.get("summary", {}).get("components")},
            "graph": {k: result.get("graph", {}).get("validation", {}).get(k) for k in ("nodes", "edges", "is_acyclic")},
            "vulnerability_query": {k: s.get("state") for k, s in result.get("source_status", {}).items()},
            "findings": {"vulnerabilities": len(v), "typosquatting": len(result.get("typosquatting", [])), "lockfile": len(result.get("lockfile_changes", []))},
            "sample_paths": [f["dependency_paths"][0] for f in v if f["dependency_paths"]][:3],
            "passed": passed, **(extra or {}),
        })
        RECORDS.write_text(json.dumps(existing, indent=2))
    except Exception:
        pass
