"""UI smoke tests with Streamlit's AppTest: every page must render for a real stored scan without raising."""
import pytest

from config.settings import get_settings
from storage.database import Database

streamlit_testing = pytest.importorskip("streamlit.testing.v1")
from pathlib import Path
APP = str(Path(__file__).resolve().parents[2] / "app.py")
PAGES = ["Repository Scan", "SBOM Explorer", "Dependency Graph", "Vulnerability Findings", "Suspicious Changes", "Risk & Explainability", "Agent Activity", "Reports"]


def latest_result():
    db = Database(get_settings().db_path)
    scans = [s for s in db.list_scans(50) if s["status"].startswith("completed")]
    return db.load_scan(scans[0]["scan_id"]) if scans else None


@pytest.mark.parametrize("page", PAGES)
def test_page_renders_without_result(page):
    at = streamlit_testing.AppTest.from_file(APP, default_timeout=60)
    at.session_state["page"] = page
    at.run()
    assert not at.exception, [e.value for e in at.exception]


@pytest.mark.parametrize("page", PAGES)
def test_page_renders_with_result(page):
    res = latest_result()
    if res is None:
        pytest.skip("no stored scan available")
    at = streamlit_testing.AppTest.from_file(APP, default_timeout=120)
    at.session_state["result"] = res
    at.session_state["page"] = page
    at.run()
    assert not at.exception, [e.value for e in at.exception]


@pytest.mark.network
def test_submit_scan_form_end_to_end_via_ui(tmp_path, monkeypatch):
    """Drive the real form: submit a URL, observe the scan result in session state and the overview rendered."""
    from tests.integration.conftest import online
    if not online("github.com"):
        pytest.skip("github unreachable")
    monkeypatch.setenv("SCANNER_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setenv("SCANNER_WORKSPACE_DIR", str(tmp_path / "ws"))
    at = streamlit_testing.AppTest.from_file(APP, default_timeout=900)
    at.run()
    at.text_input[0].set_value("https://github.com/OWASP/NodeGoat")
    # keep it fast/deterministic: skip NVD & registry lookups
    for cb in at.checkbox:
        if cb.label.startswith(("NVD", "Registry checks")):
            cb.set_value(False)
    next(b for b in at.button if b.label == "Start scan").click()
    at.run()
    assert not at.exception, [e.value for e in at.exception]
    res = at.session_state["result"]
    assert res["status"].startswith("completed") and res["repo"]["commit_sha"] and res["summary"]["components"] > 400
    assert any("Repository overview" in s.value for s in at.subheader)
    # invalid input is rejected in the UI without a crash
    at2 = streamlit_testing.AppTest.from_file(APP, default_timeout=60)
    at2.run()
    at2.text_input[0].set_value("file:///etc/passwd")
    next(b for b in at2.button if b.label == "Start scan").click()
    at2.run()
    assert not at2.exception and any("Invalid repository URL" in e.value for e in at2.error)
