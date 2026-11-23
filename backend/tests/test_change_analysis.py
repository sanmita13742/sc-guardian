import json
import subprocess
from pathlib import Path

from app.change_analysis import analyze_history, compare_manifests, inspect_supply_chain


PARENT = "1" * 40
CHILD = "2" * 40


def result(code=0, stdout="", stderr=""):
    return subprocess.CompletedProcess([], code, stdout, stderr)


def test_manifest_change_types():
    changes = compare_manifests(
        {"dependencies": {"down": "2.0.0", "gone": "1", "source": "1"}},
        {"dependencies": {"down": "1.0.0", "added": "1", "source": "https://example.test/pkg.tgz"}},
    )
    assert {item["change_type"] for item in changes} >= {"downgrade", "added", "removed", "source_changed"}


def test_historical_regression_uses_fixture_query_sets_not_hardcoded_values():
    before = {"dependencies": {"marked": "0.3.9"}}
    after = {"dependencies": {"marked": "0.3.5"}}
    lock_before = {"dependencies": {"marked": {"version": "0.3.9", "resolved": "old", "integrity": "old-integrity"}}}
    lock_after = {"dependencies": {"marked": {"version": "0.3.5", "resolved": "new", "integrity": "new-integrity"}}}

    def git(args):
        if args[:2] == ["git", "log"]: return result(stdout=CHILD + "\n")
        if args[:3] == ["git", "rev-parse", f"{CHILD}^"]: return result(stdout=PARENT + "\n")
        if args[-1] == f"{PARENT}:package.json": return result(stdout=json.dumps(before))
        if args[-1] == f"{CHILD}:package.json": return result(stdout=json.dumps(after))
        if args[-1] == f"{PARENT}:package-lock.json": return result(stdout=json.dumps(lock_before))
        if args[-1] == f"{CHILD}:package-lock.json": return result(stdout=json.dumps(lock_after))
        if args[:4] == ["git", "show", "-s", "--format=%s"]: return result(stdout="restore vulnerable training version\n")
        return result(1)

    advisory_sets = {"0.3.9": {"SHARED", "OLD"}, "0.3.5": {"SHARED", "NEW-A", "NEW-B"}}
    output = analyze_history(git, 10, lambda _name, version: advisory_sets[version], True)
    case = output["case_study"]
    assert case["package_name"] == "marked"
    assert case["parent_sha"] == PARENT and case["child_sha"] == CHILD
    assert case["newly_applicable_advisory_ids"] == ["NEW-A", "NEW-B"]
    assert case["source_or_integrity_changed"] is True
    assert case["malicious"] is False
    assert case["assessment"] == "intentional historical security regression in an educational project"


def test_static_ci_inspection(tmp_path):
    workflow = tmp_path / ".github" / "workflows" / "test.yml"
    workflow.parent.mkdir(parents=True)
    workflow.write_text("steps:\n  - uses: actions/checkout@v4\n", encoding="utf-8")
    result_data = inspect_supply_chain(tmp_path)
    assert result_data["status"] == "completed"
    assert result_data["risk_signal_count"] == 1
    assert result_data["observations"][0]["line"] == 2
