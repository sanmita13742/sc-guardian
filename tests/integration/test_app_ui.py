"""UI smoke tests with Streamlit's AppTest: every page must render for a real stored scan without raising."""
import pytest

from config.settings import get_settings
from storage.database import Database

streamlit_testing = pytest.importorskip("streamlit.testing.v1")
from pathlib import Path
APP = str(Path(__file__).resolve().parents[2] / "app.py")
PAGES = ["Repository Scan", "SBOM Explorer", "Dependency Graph", "Vulnerability Findings", "Suspicious Changes", "Risk & Explainability", "Reports"]


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
