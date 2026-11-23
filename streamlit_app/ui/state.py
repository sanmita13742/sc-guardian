"""State management access layer for SC Guardian.

Encapsulates interactions with st.session_state and provides type-safe,
graceful fallbacks while leaving backend SQLite storage untouched.
"""
from __future__ import annotations

from typing import Any, Optional

import streamlit as st

from config.settings import get_settings
from storage.database import Database

KEY_RESULT = "result"
KEY_LAST_URL = "last_url"
KEY_GROUND_TRUTH = "gt"


def get_active_scan() -> Optional[dict[str, Any]]:
    """Retrieve the active scan dictionary from session state, if present and non-failed."""
    r = st.session_state.get(KEY_RESULT)
    if not r or not isinstance(r, dict) or r.get("status") == "failed":
        return None
    return r


def get_raw_result() -> Optional[dict[str, Any]]:
    """Retrieve raw result regardless of status (e.g. to inspect failed scan errors)."""
    return st.session_state.get(KEY_RESULT)


def set_active_scan(result: dict[str, Any]) -> None:
    """Store the scan result into session state."""
    st.session_state[KEY_RESULT] = result


def clear_active_scan() -> None:
    """Clear active scan from session state."""
    st.session_state.pop(KEY_RESULT, None)


def has_active_scan() -> bool:
    """Return True if a valid scan is loaded in session state."""
    return get_active_scan() is not None


def get_last_url() -> str:
    """Retrieve the last entered repository URL."""
    return str(st.session_state.get(KEY_LAST_URL, ""))


def set_last_url(url: str) -> None:
    """Store the last entered repository URL."""
    st.session_state[KEY_LAST_URL] = url.strip()


def get_ground_truth() -> Optional[dict[str, Any]]:
    """Retrieve OSV golden-set verification results, if computed."""
    return st.session_state.get(KEY_GROUND_TRUTH)


def set_ground_truth(gt_result: dict[str, Any]) -> None:
    """Store OSV golden-set verification results."""
    st.session_state[KEY_GROUND_TRUTH] = gt_result


def load_scan_from_db(scan_id: str) -> Optional[dict[str, Any]]:
    """Load a scan by scan_id from SQLite into session state.

    Returns the loaded scan dictionary or None if loading fails.
    """
    if not scan_id:
        return None
    try:
        db = Database(get_settings().db_path)
        data = db.load_scan(scan_id)
        if data:
            set_active_scan(data)
            return data
    except Exception:
        pass
    return None


def list_recent_scans(limit: int = 15) -> list[dict[str, Any]]:
    """Retrieve recent scans from the SQLite database."""
    try:
        db = Database(get_settings().db_path)
        return db.list_scans(limit)
    except Exception:
        return []


def get_active_repo_summary() -> Optional[dict[str, Any]]:
    """Extract a lightweight metadata summary of the currently active scan."""
    r = get_active_scan()
    if not r:
        return None
    repo = r.get("repo", {})
    summary = r.get("summary", {})
    return {
        "name": repo.get("name", "Unknown Repository"),
        "url": repo.get("url", ""),
        "commit_sha": repo.get("commit_sha", ""),
        "commit_short": repo.get("commit_sha", "")[:10] if repo.get("commit_sha") else "n/a",
        "branch": repo.get("branch") or repo.get("ref") or "default",
        "timestamp": repo.get("scan_timestamp", ""),
        "status": r.get("status", "unknown"),
        "from_cache": bool(r.get("from_cache")),
        "components_count": summary.get("components", len(r.get("components", []))),
        "confirmed_vulns": summary.get("vulnerabilities_confirmed", 0),
        "critical_vulns": summary.get("by_cvss_severity", {}).get("CRITICAL", 0),
        "high_vulns": summary.get("by_cvss_severity", {}).get("HIGH", 0),
        "services_count": summary.get("services", len(r.get("inspection", {}).get("services", []))),
    }
