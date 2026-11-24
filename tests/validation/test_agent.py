"""Agent decision logic with a fake decider and stubbed sandbox (no Docker, network or model calls)."""
from types import SimpleNamespace

import pytest

from validation import agent as ag
from validation.contracts import ApprovedRemediation
from validation.decider import Decider


class FakeDecider(Decider):
    def __init__(self, answers):
        super().__init__(api_key="test-key")
        self.answers = answers

    def ask(self, state, questions):
        self.calls.append({"questions": list(questions)})
        return {k: self.answers[k] for k in questions if k in self.answers} or None


def make_agent(decider, tmp_path):
    return ag.FixValidationAgent(settings=SimpleNamespace(artifacts_dir=tmp_path), db=object(), decider=decider)


def test_model_answer_used_only_above_threshold(tmp_path):
    a = make_agent(FakeDecider({"q": {"choice": "environment", "probabilities": {"environment": 0.9}}}), tmp_path)
    q = {"type": "choice", "instructions": "why?", "criteria": {"environment": "", "unclear": ""}}
    d = a._ask("install", "q", q, [], "unclear", "rule")
    assert (d.answer, d.source, d.probability) == ("environment", "model", 0.9)
    a.decider.answers["q"] = {"choice": "environment", "probabilities": {"environment": 0.4}}
    d = a._ask("install", "q", q, [], "unclear", "rule")
    assert (d.answer, d.source) == ("unclear", "rule") and "below threshold" in d.reason


def test_model_answer_outside_allowed_options_is_ignored(tmp_path):
    a = make_agent(FakeDecider({"q": {"choice": "delete_repo", "probabilities": {"delete_repo": 0.99}}}), tmp_path)
    d = a._ask("x", "q", {"type": "choice", "instructions": "", "criteria": {"a": "", "b": ""}}, [], "a", "rule")
    assert (d.answer, d.source) == ("a", "rule")


def test_no_key_falls_back_to_rules(tmp_path, monkeypatch):
    monkeypatch.delenv("OPENROUTER_API_KEY", raising=False)
    a = make_agent(Decider(), tmp_path)
    d = a._ask("x", "q", {"type": "noul", "instructions": "", "criteria": {}}, [], True, "rule")
    assert d.source == "rule" and "OPENROUTER_API_KEY" in d.reason


def test_environment_install_failure_is_retried(tmp_path, monkeypatch, item):
    calls = []

    def run_phase(exe, repo_dir, recipe, phase, timeout=None):
        calls.append(phase)
        if phase == "install" and calls.count("install") == 1:
            return {"phase": "install", "exit_code": 1, "seconds": 1, "log_tail": "npm ERR! code ETIMEDOUT"}
        return {"phase": phase, "exit_code": 0, "seconds": 1, "log_tail": "ok"}

    monkeypatch.setattr(ag.sbx, "docker_status", lambda: {"available": True, "exe": "docker", "version": "27"})
    monkeypatch.setattr(ag.sbx, "detect_recipe", lambda *a: {"image": "node", "workdir": ".", "install": "i", "test": "t"})
    monkeypatch.setattr(ag.sbx, "run_phase", run_phase)
    a = make_agent(FakeDecider({}), tmp_path)  # model returns nothing -> rule sees ETIMEDOUT -> environment
    r = ag._Run(rem=ApprovedRemediation.from_item(item), clone=tmp_path)
    a._sandbox(r, {"url": "https://github.com/o/r"})
    assert calls == ["install", "install", "test"] and r.sandbox.status == "passed"
    assert a.decisions[0].answer == "environment" and a.decisions[0].source == "rule"


def test_missing_target_after_lock_regen_is_nested_copy(tmp_path, item):
    a = make_agent(FakeDecider({}), tmp_path)
    r = ag._Run(rem=ApprovedRemediation.from_item(item), lock_run={"exit_code": 0},
                before={"lockfile_dependencies": [{"name": "express", "version": "4.17.1", "direct": False, "lockfile": "package-lock.json"}]})
    a._explain_missing_target(r)
    assert r.notes[0]["finding"] == "nested_copy" and r.notes[0]["for"] == "remediation engine"


@pytest.mark.parametrize("lock_ok,expected", [(None, "lockfile_stale")])
def test_missing_target_without_regen_is_stale_lockfile(tmp_path, item, lock_ok, expected):
    a = make_agent(FakeDecider({}), tmp_path)
    r = ag._Run(rem=ApprovedRemediation.from_item(item), before={"lockfile_dependencies": []})
    a._explain_missing_target(r)
    assert r.notes[0]["finding"] == expected
