#!/usr/bin/env python
"""SC Guardian command line: scan a public repository, gate a pipeline on a policy, re-assess stored scans, export reports.

    python guardian.py scan https://github.com/owner/repo [--ref main] [--policy default] [--format md|json|sarif|vex] [--out DIR] [--llm]
    python guardian.py gate [SCAN_ID|latest] --policy strict          # exit 1 when the policy blocks
    python guardian.py monitor [--repo URL] [--max N]                 # re-check stored inventories for newly disclosed issues
    python guardian.py scans                                          # list stored scans
    python guardian.py report SCAN_ID --format sarif --out report.sarif

Exit codes: 0 = pass / no new alerts, 1 = policy blocked (scan/gate) or new alerts (monitor), 2 = error.
The scanner is static: repository code is never executed, built or installed.
"""
from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "src"))

from config.settings import get_settings  # noqa: E402
from storage.database import Database  # noqa: E402


def _progress(quiet: bool):
    last = {"step": None}

    def cb(e: dict) -> None:
        if quiet:
            return
        if e["kind"] in ("start", "decision", "warning", "error") or (e["kind"] == "done" and e["step"] != last["step"]):
            tag = {"start": ">", "done": "+", "decision": "*", "warning": "!", "error": "x"}.get(e["kind"], " ")
            print(f"[{e['progress'] * 100:3.0f}%] {tag} {e['agent']}: {e['message'][:140]}", file=sys.stderr)
            last["step"] = e["step"]
    return cb


def _emit(result: dict, fmt: str, out: str | None, decisions: dict | None = None) -> None:
    from reporting import json_exporter, report_generator
    from reporting.sarif import to_sarif
    from reporting.vex import to_vex
    text = {"md": lambda: report_generator.generate_markdown(result), "html": lambda: report_generator.generate_html(result), "json": lambda: json_exporter.dumps(result),
            "sarif": lambda: json_exporter.dumps(to_sarif(result)), "vex": lambda: json_exporter.dumps(to_vex(result, decisions))}[fmt]()
    if out:
        p = Path(out)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(text, encoding="utf-8")
        print(f"wrote {p}", file=sys.stderr)
    else:
        print(text)


def _gate(result: dict, policy_name: str, db: Database, as_json: bool) -> int:
    from policy.engine import evaluate, load_policy
    from storage.memory import Memory
    pol = load_policy(policy_name)
    pr = evaluate(pol, result, Memory(db).decisions(result["repo"]["url"]))
    result["policy_result"] = pr
    if as_json:
        print(json.dumps(pr, indent=2, default=str))
    else:
        print(f"\nPolicy '{pr['policy']}': {'PASS' if pr['passed'] else 'FAIL'}  ({pr['blocking']} blocking, {pr['warnings']} warning(s), {pr['info']} info, {pr['waived']} waived)")
        for v in [x for x in pr["violations"] if x["action"] == "block"][:25]:
            print(f"  BLOCK {v['rule_id']}: {v['subject']}")
        for v in [x for x in pr["violations"] if x["action"] == "warn"][:10]:
            print(f"  warn  {v['rule_id']}: {v['subject']}")
    return 0 if pr["passed"] else 1


def _load(db: Database, which: str) -> dict:
    scans = db.list_scans(200)
    sid = scans[0]["scan_id"] if which == "latest" and scans else which
    r = db.load_scan(sid)
    if not r:
        raise SystemExit(f"scan '{which}' not found (see `guardian.py scans`)")
    return r


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="guardian", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("scan", help="scan a public GitHub repository")
    p.add_argument("url")
    p.add_argument("--ref")
    p.add_argument("--policy", default="default", help="policy name or YAML path (default: default; use 'none' to skip the gate)")
    p.add_argument("--format", choices=["md", "html", "json", "sarif", "vex"], default=None, help="also print/write a report")
    p.add_argument("--out")
    p.add_argument("--llm", action="store_true", help="allow optional LLM reasoning (needs LLM_API_KEY)")
    p.add_argument("--no-nvd", action="store_true")
    p.add_argument("--scanner", choices=["auto", "syft", "trivy", "builtin"], default="auto")
    p.add_argument("--fresh", action="store_true", help="ignore stored scans of the same commit")
    p.add_argument("--quiet", action="store_true")
    p.add_argument("--json", action="store_true", help="print the gate result as JSON")
    g = sub.add_parser("gate", help="evaluate a policy against a stored scan")
    g.add_argument("scan", nargs="?", default="latest")
    g.add_argument("--policy", default="default")
    g.add_argument("--json", action="store_true")
    m = sub.add_parser("monitor", help="re-assess stored inventories against newly disclosed vulnerabilities")
    m.add_argument("--repo")
    m.add_argument("--max", type=int, default=20)
    m.add_argument("--json", action="store_true")
    sub.add_parser("scans", help="list stored scans")
    r = sub.add_parser("report", help="export a report of a stored scan")
    r.add_argument("scan", nargs="?", default="latest")
    r.add_argument("--format", choices=["md", "html", "json", "sarif", "vex"], default="md")
    r.add_argument("--out")
    a = ap.parse_args(argv)
    s = get_settings()
    db = Database(s.db_path)
    try:
        if a.cmd == "scan":
            from core.scan_orchestrator import ScanOptions, run_scan
            res = run_scan(ScanOptions(url=a.url, ref=a.ref, use_nvd=not a.no_nvd, use_llm=a.llm, sbom_scanner=a.scanner, reuse_cached=not a.fresh), s, db, on_event=_progress(a.quiet))
            if res.get("status") == "failed":
                print("scan failed: " + res.get("error", ""), file=sys.stderr)
                return 2
            sm = res["summary"]
            print(f"{res['repo']['name']} @ {res['repo']['commit_sha'][:8]}: {sm['components']} components, {sm['vulnerabilities_confirmed']} confirmed vulnerabilities, "
                  f"{sm.get('pipeline_findings', 0)} pipeline findings, {len((res.get('remediation') or {}).get('items', []))} remediation proposal(s)")
            code = 0
            if a.policy != "none":
                code = _gate(res, a.policy, db, a.json)
            if a.format:
                _emit(res, a.format, a.out)
            return code
        if a.cmd == "gate":
            return _gate(_load(db, a.scan), a.policy, db, a.json)
        if a.cmd == "scans":
            for x in db.list_scans(30):
                print(f"{x['scan_id']}  {x['scan_timestamp']}  {x['repo_name']:<28} {x['commit_sha'][:8]}  {x['status']}")
            return 0
        if a.cmd == "report":
            from storage.memory import Memory
            res = _load(db, a.scan)
            _emit(res, a.format, a.out, Memory(db).decisions(res["repo"]["url"]))
            return 0
        if a.cmd == "monitor":
            from monitor.watch import run_monitor
            out = run_monitor(s, db, repo_url=a.repo, max_repos=a.max)
            if a.json:
                print(json.dumps(out, indent=2, default=str))
            else:
                print(f"Re-assessed {out['repos_checked']} repository inventory(ies); {len(out['alerts'])} new alert(s)")
                for al in out["alerts"][:30]:
                    print(f"  [{al['severity']}] {al['repo']}: {al['title']}")
            return 1 if out["alerts"] else 0
    except SystemExit:
        raise
    except Exception as e:  # noqa: BLE001
        print(f"error: {type(e).__name__}: {e}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
