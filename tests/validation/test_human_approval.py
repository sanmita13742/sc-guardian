"""Validation runs repository code, so only a person's approval authorises it; policy auto-approvals are refused or skipped."""
import os
import tempfile

import pytest

from storage.database import Database
from storage.memory import Memory
from validation.fix_validator import ValidationError, approved_items, is_human_approval, load_request

URL = "https://github.com/o/demo-app"


@pytest.mark.parametrize("ap,human", [
    ({"state": "approved", "actor": "analyst", "reason": "Accepted manually by analyst in Streamlit UI"}, True),
    ({"state": "approved", "actor": "demo-reviewer", "reason": "minor bump"}, True),
    ({"state": "approved", "actor": "SC Guardian Policy Engine", "reason": "Automated policy: MEDIUM severity proposal auto-approved"}, False),
    ({"state": "approved", "actor": "auto-policy", "reason": "Automated Low/Medium severity PR"}, False),
    ({"state": "approved", "actor": "someone", "reason": "Automated policy: LOW"}, False),
    ({"state": "approved", "actor": "", "reason": "x"}, False),
    ({"state": "rejected", "actor": "analyst", "reason": "no"}, False),
    (None, False)])
def test_is_human_approval(ap, human):
    assert is_human_approval(ap) is human


@pytest.fixture
def db(item):
    d = Database(os.path.join(tempfile.mkdtemp(), "t.db"))
    auto = {**item, "id": "REM-002", "fingerprint": "fp-auto"}
    unapproved = {**item, "id": "REM-003", "fingerprint": "fp-none"}
    d.save_scan({"repo": {"scan_id": "s1", "url": URL, "name": "demo-app", "commit_sha": "abc", "scan_timestamp": "2026-11-24T00:00:00Z"},
                 "status": "completed", "summary": {}, "vulnerabilities": [], "remediation": {"items": [item, auto, unapproved]}})
    m = Memory(d)
    m.set_approval(URL, item["fingerprint"], "approved", "looks safe", item["title"], "analyst")
    m.set_approval(URL, "fp-auto", "approved", "Automated policy: MEDIUM severity proposal auto-approved without human intervention", "t", "SC Guardian Policy Engine")
    return d


def test_batch_validates_human_and_reports_auto_approved(db):
    assert approved_items(db, "s1") == (["REM-001"], ["REM-002"])


def test_single_auto_approved_proposal_is_refused(db):
    with pytest.raises(ValidationError, match="approved automatically by 'SC Guardian Policy Engine'"):
        load_request(db, "s1", "REM-002")
    load_request(db, "s1", "REM-001")  # human approval passes the gate


def test_later_human_approval_replaces_auto_approval(db):
    Memory(db).set_approval(URL, "fp-auto", "approved", "reviewed the diff", "t", "analyst")
    assert approved_items(db, "s1") == (["REM-001", "REM-002"], [])
