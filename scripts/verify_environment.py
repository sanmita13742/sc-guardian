"""Verify that the toolchain needed by SC Guardian is present and working.

Usage:  python scripts/verify_environment.py [--offline]
Exit code 0 = everything required is available; 1 = a required component is missing.
"""
from __future__ import annotations

import importlib
import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

REQUIRED = ["langgraph", "streamlit", "networkx", "pydantic", "requests", "rapidfuzz", "packaging", "jsonschema", "yaml", "pandas"]
OPTIONAL = ["dotenv"]
failures: list[str] = []


def check(label: str, ok: bool, detail: str = "", required: bool = True) -> None:
    mark = "PASS" if ok else ("FAIL" if required else "WARN")
    print(f"[{mark}] {label}" + (f" - {detail}" if detail else ""))
    if not ok and required:
        failures.append(label)


def main() -> int:
    offline = "--offline" in sys.argv
    check("Python >= 3.10", sys.version_info >= (3, 10), sys.version.split()[0])
    for m in REQUIRED:
        try:
            mod = importlib.import_module(m)
            check(f"import {m}", True, getattr(mod, "__version__", ""))
        except Exception as e:
            check(f"import {m}", False, str(e))
    for m in OPTIONAL:
        try:
            importlib.import_module(m)
            check(f"import {m}", True, required=False)
        except Exception as e:
            check(f"import {m}", False, str(e), required=False)

    git = shutil.which("git")
    check("git available", bool(git), subprocess.run(["git", "--version"], capture_output=True, text=True).stdout.strip() if git else "install Git")

    from config.settings import get_settings
    from sbom.cyclonedx_validator import load_sbom, validate_cyclonedx
    from sbom.syft_runner import resolve_syft, run_syft
    s = get_settings()
    syft = resolve_syft(s)
    check("syft executable", bool(syft), syft or "not installed - optional, the built-in rule engine is used instead (see README)", required=False)
    from sbom.trivy_runner import resolve_trivy
    trivy = resolve_trivy(s)
    check("trivy executable", bool(trivy), trivy or "not installed - optional (see README)", required=False)
    from sbom.builtin_generator import generate_cyclonedx
    from core.models import LockDependency
    bdoc, _ = generate_cyclonedx([LockDependency(name="left-pad", version="1.3.0", ecosystem="npm", lockfile="package-lock.json", direct=True)], "demo")
    check("built-in rule engine generates a valid CycloneDX SBOM", validate_cyclonedx(bdoc)["valid"] and len(bdoc["components"]) == 1)
    if syft:
        with tempfile.TemporaryDirectory() as td:
            demo = Path(td) / "demo"
            demo.mkdir()
            (demo / "package.json").write_text('{"name":"demo","version":"1.0.0","dependencies":{"left-pad":"1.3.0"}}')
            (demo / "package-lock.json").write_text(json.dumps({"name": "demo", "lockfileVersion": 3, "packages": {
                "": {"name": "demo", "dependencies": {"left-pad": "1.3.0"}},
                "node_modules/left-pad": {"version": "1.3.0", "resolved": "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz"}}}))
            res = run_syft(demo, Path(td) / "sbom.json", s)
            check("syft scan of a test directory", res.ok, f"version {res.version}, {res.duration_s}s" if res.ok else str(res.error))
            if res.ok:
                doc = load_sbom(res.sbom_path)
                v = validate_cyclonedx(doc)
                names = {c.get("name") for c in doc.get("components", [])}
                check("CycloneDX JSON generated, parsed and valid", v["valid"] and "left-pad" in names, f"specVersion {doc.get('specVersion')}, {len(names)} component(s)")
    if not offline:
        import requests
        for name, url in (("OSV.dev", "https://api.osv.dev/v1/vulns/GHSA-p6mc-m468-83gw"), ("NVD", "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2020-8203"),
                          ("CISA KEV", "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"), ("GitHub", "https://github.com")):
            try:
                r = requests.head(url, timeout=15, allow_redirects=True) if name == "GitHub" else requests.get(url, timeout=20, stream=True)
                check(f"network: {name}", r.status_code < 400, f"HTTP {r.status_code}", required=False)
            except Exception as e:
                check(f"network: {name}", False, type(e).__name__, required=False)
    check("NVD_API_KEY (optional)", bool(s.nvd_api_key), "configured" if s.nvd_api_key else "not set - NVD enrichment works at a lower rate limit", required=False)
    check("LLM_API_KEY (optional)", bool(s.llm_api_key), "configured" if s.llm_api_key else "not set - fully deterministic mode (no LLM calls)", required=False)
    print("\nResult:", "ALL REQUIRED CHECKS PASSED" if not failures else f"FAILED: {', '.join(failures)}")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
