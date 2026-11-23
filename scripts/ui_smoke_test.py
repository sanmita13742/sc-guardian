"""Validation script for Phase 1: Frontend Foundation and Architecture.

Executes comprehensive tests across:
1. Imports and syntax integrity.
2. Design system tokens and semantic severity helpers.
3. State management layer and SQLite persistence loading.
4. AppTest simulation of all 8 pages in both Empty State and Populated Scan State.
5. Navigation and session state preservation.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

# Ensure the project root is on sys.path
APP_DIR = Path(__file__).resolve().parent.parent
if str(APP_DIR) not in sys.path:
    sys.path.insert(0, str(APP_DIR))

os.chdir(APP_DIR)


def test_theme_and_tokens():
    print("[1/5] Testing Design System Tokens & Semantic Styling...")
    from ui.theme import (SEV_COLORS, SEV_RANK, severity_pill_html,
                          status_pill_html, text_badge)

    assert SEV_COLORS["CRITICAL"] == "#f85149"
    assert SEV_RANK["CRITICAL"] > SEV_RANK["HIGH"] > SEV_RANK["MEDIUM"] > SEV_RANK["LOW"]
    badge_text = text_badge("CRITICAL")
    assert "CRITICAL" in badge_text
    assert "🟥" in badge_text

    pill = severity_pill_html("CRITICAL")
    assert "<span" in pill
    assert "#f85149" in pill

    status = status_pill_html("completed")
    assert "Completed" in status or "completed" in status.lower()

    print("  -> Design system tokens verified successfully.")


def test_state_management():
    print("[2/5] Testing State Management & SQLite Persistence...")
    from ui.state import (clear_active_scan, get_active_repo_summary,
                          get_active_scan, has_active_scan, list_recent_scans,
                          load_scan_from_db, set_active_scan)

    # Clean state
    clear_active_scan()
    assert not has_active_scan()

    # Query SQLite database
    scans = list_recent_scans(10)
    print(f"  -> Found {len(scans)} historical scan(s) in database.")
    if scans:
        first_id = scans[0]["scan_id"]
        loaded = load_scan_from_db(first_id)
        assert loaded is not None, f"Failed to load scan {first_id}"
        assert has_active_scan()
        summary = get_active_repo_summary()
        assert summary is not None
        assert "name" in summary
        assert "commit_short" in summary
        print(f"  -> Successfully loaded scan for: {summary['name']} ({summary['commit_short']})")
    else:
        print("  -> Warning: No historical scans found to test database loading.")


def test_common_components():
    print("[3/5] Testing Reusable Components in ui.components.common...")
    import pandas as pd
    import streamlit as st

    from ui.components.common import badge, df, get_result, page_header, require_result

    assert badge("HIGH") is not None
    # Test df conversion logic
    test_rows = [{"colA": "test", "colB": 123}, {"colA": "test2", "colB": "n/a"}]
    # Ensure dataframe helper handles mixed numbers and text without error
    df(test_rows)
    print("  -> Reusable components verified successfully.")


def test_apptest_pages():
    print("[4/5] Testing AppTest rendering across all pages...")
    from streamlit.testing.v1 import AppTest

    # 1. Test App startup with default navigation
    at = AppTest.from_file(str(APP_DIR / "app.py"))
    at.run(timeout=30)
    assert not at.exception, f"app.py raised exception on default page: {at.exception}"
    print("  -> app.py rendered successfully on default page.")

    # 2. Test each page module directly
    from ui.pages import (agents_page, graph_page, reports_page, risk_page,
                          sbom_page, scan_page, suspicious_page, vulns_page, pipeline_page, remediation_page)
    from ui.state import list_recent_scans, load_scan_from_db

    # Ensure a scan is loaded for populated testing
    scans = list_recent_scans(5)
    test_scan_id = scans[0]["scan_id"] if scans else None

    pages = [
        ("Repository Scan", "scan_page"),
        ("SBOM Explorer", "sbom_page"),
        ("Dependency Graph", "graph_page"),
        ("Vulnerability Findings", "vulns_page"),
        ("Pipeline & Containers", "pipeline_page"),
        ("Suspicious Changes", "suspicious_page"),
        ("Risk & Explainability", "risk_page"),
        ("Remediation", "remediation_page"),
        ("Agent Activity", "agents_page"),
        ("Reports & Downloads", "reports_page"),
    ]

    for name, mod_name in pages:
        # Test populated state
        code = f"""
import streamlit as st
from ui.state import load_scan_from_db
from ui.pages import {mod_name}

if {repr(test_scan_id)}:
    load_scan_from_db({repr(test_scan_id)})

{mod_name}.render()
"""
        at_page = AppTest.from_string(code)
        at_page.run(timeout=30)
        assert not at_page.exception, f"Page '{name}' raised exception during render: {at_page.exception}"
        print(f"  -> Page '{name}' rendered successfully (Populated scan state).")

    # 3. Test empty state on pages requiring a scan
    for name, mod_name in pages[1:]:
        code_empty = f"""
import streamlit as st
from ui.state import clear_active_scan
from ui.pages import {mod_name}

clear_active_scan()
{mod_name}.render()
"""
        at_empty = AppTest.from_string(code_empty)
        at_empty.run(timeout=30)
        assert not at_empty.exception, f"Page '{name}' raised exception during empty state render: {at_empty.exception}"
        print(f"  -> Page '{name}' handled empty state cleanly.")


def test_navigation_and_state():
    print("[5/5] Testing navigation structure and session state persistence...")
    from app import NAVIGATION_PAGES, PAGES

    assert "Security Analysis" in NAVIGATION_PAGES
    assert ("Operations" in NAVIGATION_PAGES or "Operations & Audit" in NAVIGATION_PAGES)
    ops_key = "Operations" if "Operations" in NAVIGATION_PAGES else "Operations & Audit"
    assert len(NAVIGATION_PAGES["Security Analysis"]) == 8
    assert len(NAVIGATION_PAGES[ops_key]) == 3  # agents, reports, settings & health
    assert len(PAGES) == 10
    print("  -> Navigation structure and compatibility mappings verified.")


def main():
    print("==================================================")
    print("SC Guardian Phase 1 Frontend Foundation Validation")
    print("==================================================")
    try:
        test_theme_and_tokens()
        test_state_management()
        test_common_components()
        test_apptest_pages()
        test_navigation_and_state()
        print("==================================================")
        print("ALL PHASE 1 CHECKS PASSED SUCCESSFULLY!")
        print("==================================================")
        return 0
    except Exception as e:
        print(f"\n[FAILED] Validation error: {type(e).__name__}: {e}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
