from conftest import comp, make_after, vuln

from validation.comparison import compare
from validation.contracts import ApprovedRemediation, PhaseRun, SandboxOutcome
from validation.provenance import sha256_text, statement
from validation.verdict import decide

PASSED = SandboxOutcome(status="passed", runs=[PhaseRun(phase="install", exit_code=0), PhaseRun(phase="test", exit_code=0)])
NO_DOCKER = SandboxOutcome(status="skipped", reason="Docker is not installed")


def test_adapter_reads_current_remediation_item(item):
    rem = ApprovedRemediation.from_item(item)
    assert rem.id == "REM-001" and rem.ecosystem == "npm" and rem.patch_path == "package.json"
    assert rem.changes[0].to_version == "4.21.2"
    assert rem.predicted["verdict"] == "reduces_risk"


def test_all_targeted_fixed_and_tests_pass_is_verified(item, before):
    after = make_after([vuln("X-9", "lodash", "4.17.21", "GHSA-cccc", "LOW")], [comp("express", "4.21.2"), comp("qs", "6.13.0"), comp("lodash", "4.17.21")])
    cmp = compare(before, after, ApprovedRemediation.from_item(item))
    assert {f.advisory for f in cmp.targeted_fixed} == {"GHSA-aaaa", "GHSA-bbbb"}
    assert not cmp.newly_introduced and not cmp.other_resolved  # lodash matched by natural key despite a new finding_id
    assert cmp.target_versions_present is True
    assert {c.key for c in cmp.components_changed} == {"npm|.|express", "npm|.|qs"}
    assert cmp.predicted_vs_observed["observed_fixed"] == 2
    v, _, checks = decide(cmp, PASSED, True)
    assert v == "verified_fixed" and checks["all_targeted_fixed"]


def test_without_docker_is_fixed_untested(item, before):
    after = make_after([], [comp("express", "4.21.2")])
    v, reasons, _ = decide(compare(before, after, ApprovedRemediation.from_item(item)), NO_DOCKER, True)
    assert v == "fixed_untested" and any("Docker" in r for r in reasons)


def test_partial_and_no_effect(item, before):
    rem = ApprovedRemediation.from_item(item)
    partial = make_after([vuln("Y", "qs", "6.7.0", "GHSA-bbbb", "MEDIUM")], [comp("express", "4.21.2"), comp("qs", "6.7.0")])
    assert decide(compare(before, partial, rem), PASSED, True)[0] == "partial"
    same = make_after(before["vulnerabilities"], before["components"])
    v, reasons, _ = decide(compare(before, same, rem), PASSED, True)
    assert v == "no_effect" and any("express==4.21.2" in r for r in reasons)


def test_new_high_finding_is_regression(item, before):
    after = make_after([vuln("Z", "body-parser", "1.20.3", "GHSA-zzzz", "HIGH")], [comp("express", "4.21.2"), comp("body-parser", "1.20.3")])
    v, reasons, _ = decide(compare(before, after, ApprovedRemediation.from_item(item)), PASSED, True)
    assert v == "regressed" and "GHSA-zzzz" in reasons[0]


def test_tests_broken_by_patch_is_regression(item, before):
    broke = SandboxOutcome(status="failed", runs=[PhaseRun(phase="install", exit_code=0), PhaseRun(phase="test", exit_code=1)], baseline={"status": "passed"})
    preexisting = broke.model_copy(update={"baseline": {"status": "failed"}})
    cmp = compare(before, make_after([], [comp("express", "4.21.2")]), ApprovedRemediation.from_item(item))
    assert decide(cmp, broke, True)[0] == "regressed"
    assert decide(cmp, preexisting, True)[0] == "fixed_untested"


def test_no_rescan_is_inconclusive():
    assert decide(None, PASSED, False)[0] == "inconclusive"


def test_provenance_statement_shape():
    st = statement([{"name": "package-lock.json", "digest": {"sha256": "ab"}}], repo_url="https://github.com/o/r", commit_sha="abc", patch_sha256=sha256_text("x"),
                   remediation_id="REM-001", recipe={"image": "node:22"}, image_digest="node@sha256:ff", started_on="t0", finished_on="t1", tool_version="0.1.0")
    assert st["_type"].startswith("https://in-toto.io/Statement") and st["predicateType"] == "https://slsa.dev/provenance/v1"
    deps = st["predicate"]["buildDefinition"]["resolvedDependencies"]
    assert deps[0]["digest"]["gitCommit"] == "abc" and deps[2]["digest"] == {"sha256": "ff"}
