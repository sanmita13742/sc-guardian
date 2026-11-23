"""Settings & Health: effective configuration (with sources), tools, database, cache and disk usage."""
from __future__ import annotations

import shutil
import time
from pathlib import Path

import streamlit as st

from config.loader import effective
from config.settings import get_settings
from sbom.syft_runner import resolve_syft, syft_version
from sbom.trivy_runner import resolve_trivy, trivy_version
from storage.cache import Cache
from storage.database import Database
from ui.components.common import df, page_header


def _size(path: Path) -> int:
    total = 0
    try:
        for p in path.rglob("*"):
            if p.is_file():
                total += p.stat().st_size
    except OSError:
        pass
    return total


def _mb(n: int | None) -> str:
    return f"{(n or 0) / 1024 / 1024:.1f} MB"


def render() -> None:
    page_header("Settings & Health", "Effective configuration, external tools, database, cache and disk usage.")
    s = get_settings()
    db = Database(s.db_path)

    if s.problems:
        for p in s.problems:
            st.warning(p)
    else:
        st.success("Configuration is valid.")
    st.caption(f"Config file: `{s.config_file or 'none (scanner.toml not found)'}` · precedence: environment `SCANNER_<NAME>` > `.env` > `scanner.toml` > defaults · secrets only via environment")

    from llm.client import detect_provider
    from sandbox.runner import docker_status
    llm_on = bool(s.llm_api_key)
    st.info(("LLM: **enabled** - " + f"{s.llm_provider or detect_provider(s.llm_api_key)} (model {s.llm_model or 'provider default'}); used only for validated reasoning text. " if llm_on else "LLM: **disabled** - fully deterministic mode (set `LLM_API_KEY` in `.env` to enable optional reasoning). ")
            + "Docker sandbox: " + ("available" if docker_status()["available"] else "not available (optional)"))
    t_cfg, t_tools, t_db, t_cache, t_disk = st.tabs(["Configuration", "Tools", "Database", "Cache", "Disk"])

    with t_cfg:
        df(effective(s), height=520)

    with t_tools:
        rows = []
        git = shutil.which("git")
        rows.append({"Tool": "git", "Status": "found" if git else "MISSING (required)", "Path": git or "", "Version": ""})
        sy, tr = resolve_syft(s), resolve_trivy(s)
        rows.append({"Tool": "Syft", "Status": "found" if sy else "not installed (optional)", "Path": sy or "", "Version": (syft_version(sy) if sy else "") or ""})
        rows.append({"Tool": "Trivy", "Status": "found" if tr else "not installed (optional)", "Path": tr or "", "Version": (trivy_version(tr) if tr else "") or ""})
        rows.append({"Tool": "Built-in rule engine", "Status": "always available", "Path": "sbom/builtin_generator.py", "Version": "1.0"})
        df(rows, height="content")
        st.caption("Auto mode uses Syft, then Trivy, then the built-in rule engine; metadata and transitive resolution use deps.dev, npm, PyPI, crates.io and Maven Central (public, read-only).")

    with t_db:
        h = db.health()
        c = st.columns(4)
        c[0].metric("Schema version", h["schema_version"])
        c[1].metric("Integrity", h["integrity"])
        c[2].metric("Size", _mb(h["size_bytes"]))
        c[3].metric("Journal", h["journal_mode"])
        df([{"Table": k, "Rows": v} for k, v in h["tables"].items()], height="content")
        st.caption(f"`{h['path']}`")
        if st.button("Run VACUUM (reclaim space)"):
            import sqlite3
            con = sqlite3.connect(h["path"])
            con.execute("VACUUM")
            con.close()
            st.success("Done.")

    with t_cache:
        cache = Cache(db)
        stt = cache.stats()
        c = st.columns(3)
        c[0].metric("Rows", f"{stt['total_rows']:,}")
        c[1].metric("Payload", _mb(stt["total_bytes"]))
        c[2].metric("Limits", f"{s.cache_max_age_days} d / {s.cache_max_rows:,} rows")
        now = time.time()
        df([{"Namespace": n["namespace"], "Rows": n["rows"], "Size": _mb(n["bytes"]), "Oldest (days)": round((now - n["oldest"]) / 86400, 1), "Newest (min)": round((now - n["newest"]) / 60, 1)}
            for n in stt["namespaces"]], height="content")
        st.caption("OSV advisories, NVD, CISA KEV, registry metadata (30 days) and deps.dev resolution (7 days) are cached; outages fall back to stale cache and are reported as such.")
        a, b = st.columns(2)
        if a.button("Purge expired / over-limit rows"):
            st.success(str(cache.maintain(s.cache_max_age_days, s.cache_max_rows)))
        ns = b.selectbox("Clear a namespace", [""] + [n["namespace"] for n in stt["namespaces"]], format_func=lambda x: x or "(choose)")
        if ns and b.button(f"Clear '{ns}'"):
            st.success(f"{cache.clear(ns)} rows removed")
            st.rerun()

    with t_disk:
        rows = [{"Location": "Artifacts (SBOMs, reports, graphs)", "Path": str(s.artifacts_dir), "Size": _mb(_size(s.artifacts_dir))},
                {"Location": "Data (databases)", "Path": str(s.data_dir), "Size": _mb(_size(s.data_dir))},
                {"Location": "Temporary clones", "Path": str(s.workspace_dir), "Size": _mb(_size(s.workspace_dir))}]
        df(rows, height="content")
        left = [d for d in s.workspace_dir.iterdir() if d.is_dir()] if s.workspace_dir.exists() else []
        if left:
            st.warning(f"{len(left)} temporary clone folder(s) present (a scan may be running, or a previous one was interrupted; folders older than {s.workspace_max_age_s // 60} min are swept at the next scan).")
