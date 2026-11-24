"""History reader + the Fix Validation page rendered with Streamlit's AppTest (no Docker, network or model calls)."""
import json
import os
import tempfile
from pathlib import Path

import pytest

from storage.database import Database
from storage.memory import Memory
from validation import history

ROOT = Path(__file__).resolve().parents[2]
URL = "https://github.com/o/demo-app"


def write_run(art: Path, scan: str, rid: str, verdict: str = "no_effect") -> None:
    d = art / "validation" / scan / rid
    d.mkdir(parents=True)
    (d / "final_assessment.json").write_text(json.dumps({"remediation_id": rid, "fingerprint": "fp", "scan_id": scan, "verdict": verdict,
                                                         "reasons": ["None of the 2 targeted finding(s) disappeared."], "created_at": "2026-11-24T10:00:00+00:00",
                                                         "approved_by": "analyst", "checks": {"install_ok": True, "tests_ok": None}, "limitations": []}))
    (d / "before_after_comparison.json").write_text(json.dumps({
        "targeted_fixed": [], "targeted_remaining": [{"advisory": "CVE-2021-23358", "package": "underscore", "version": "1.8.3", "severity": "CRITICAL"}],
        "newly_introduced": [], "other_resolved": [{"advisory": "CVE-2021-23358", "package": "underscore", "version": "1.9.1", "severity": "CRITICAL"}],
        "components_changed": [{"key": "npm|.|underscore", "before": ["1.8.3", "1.9.1"], "after": ["1.13.8", "1.8.3"]}], "components_added": [], "components_removed": [],
        "target_versions_present": True, "risk_before": {"CRITICAL": 6}, "risk_after": {"CRITICAL": 5},
        "predicted_vs_observed": {"predicted_verdict": "reduces_risk", "predicted_fixed": 2, "observed_fixed": 0}}))
    (d / "validation_report.json").write_text(json.dumps({
        "seconds": 523.5, "sandbox": {"status": "passed", "runs": [{"phase": "install", "exit_code": 0, "seconds": 400.2, "log_tail": "ok"}],
                                      "test_evidence": {"executed": 0, "zero_marker": "No files to check"}, "reason": "tests exited 0 but no test was executed"},
        "agent": {"decider": {"enabled": True, "model": "m", "threshold": 0.7, "calls": [{"questions": ["reviewer_would_merge"], "ok": True, "http_status": 200, "seconds": 1.2}]},
                  "decisions": [{"step": "verdict", "question": "merge?", "answer": False, "source": "model", "probability": 0.147, "reason": "model probability"}],
                  "notes": [], "timings_seconds": {"install": 400.2, "test": 69.7, "total": 523.5}},
        "signature": {"signed": False, "note": "Statement is unsigned"}}))
    (d / "provenance.intoto.json").write_text(json.dumps({"subject": [{"name": "package.json", "digest": {"sha256": "ab"}}],
                                                         "predicate": {"buildDefinition": {"resolvedDependencies": [{"uri": "git+x@abc", "digest": {"gitCommit": "abc"}}]}}}))


def test_history_lists_and_loads_runs(tmp_path):
    write_run(tmp_path, "s1", "REM-002")
    (tmp_path / "validation" / "s1" / "REM-009").mkdir()  # an interrupted run without a final assessment is ignored
    rows = history.list_runs(tmp_path, "s1")
    assert [(r["remediation_id"], r["verdict"], r["sandbox"], r["decider"]) for r in rows] == [("REM-002", "no_effect", "passed", True)]
    run = history.load_run(tmp_path, "s1", "REM-002")
    assert run["final"]["verdict"] == "no_effect" and "provenance.intoto.json" in run["files"]
    assert history.load_run(tmp_path, "s1", "REM-009") is None and history.list_runs(tmp_path, "nope") == []


@pytest.fixture
def page_env(tmp_path, item):
    art, data = tmp_path / "artifacts", tmp_path / "data"
    data.mkdir()
    db = Database(data / "scanner.db")
    auto = {**item, "id": "REM-002", "fingerprint": "fp-auto", "title": "Upgrade underscore", "automation_tier": "automated"}
    result = {"repo": {"scan_id": "s1", "url": URL, "name": "demo-app", "commit_sha": "abc", "scan_timestamp": "2026-11-24T00:00:00Z"},
              "status": "completed", "summary": {}, "vulnerabilities": [], "remediation": {"items": [item, auto]}}
    m = Memory(db)
    m.set_approval(URL, item["fingerprint"], "approved", "ok", item["title"], "analyst")
    m.set_approval(URL, "fp-auto", "approved", "Automated policy: MEDIUM", "t", "SC Guardian Policy Engine")
    write_run(art, "s1", "REM-001", "fixed_untested")
    return {"art": art, "data": data, "result": result}


SCRIPT = """
import sys, json
sys.path.insert(0, {src!r})
import streamlit as st
from pathlib import Path
from config.settings import Settings
from validation.decider import Decider
import ui.pages.validation_page as vp
vp.get_settings = lambda: Settings(data_dir=Path({data!r}), artifacts_dir=Path({art!r}))
vp._docker = lambda: {{"available": False, "reason": "Docker is not installed"}}
vp.Decider = lambda: Decider(api_key="")
st.session_state["result"] = json.loads({result!r})
vp.render()
"""


def test_page_renders_proposals_gate_and_results(page_env):
    from streamlit.testing.v1 import AppTest
    at = AppTest.from_string(SCRIPT.format(src=str(ROOT / "src"), data=str(page_env["data"]), art=str(page_env["art"]),
                                           result=json.dumps(page_env["result"])), default_timeout=30).run()
    assert not at.exception, at.exception
    text = " ".join(m.value for m in at.markdown) + " ".join(c.value for c in at.caption)
    assert "Fixed, untested" in text  # verdict card of the stored run
    assert "REM-002" in text and "need a person" in text  # auto-approved proposal is waiting for a human
    assert [o for o in at.multiselect[0].options] == ["REM-001"]  # only the human-approved proposal can be validated
    assert at.toggle[0].value is False  # no Docker -> sandbox off
    assert [t.label for t in at.tabs] == ["Before / After", "Sandbox", "Agent decisions", "Timings", "Provenance"]
    assert at.button(key="fv_go").disabled is False  # static run allowed without consent when the sandbox is off
