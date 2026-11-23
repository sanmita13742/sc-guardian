"""Page 1: repository submission, progress and repository overview."""
from __future__ import annotations

import streamlit as st

from config.settings import get_settings
from core.scan_orchestrator import ScanOptions, run_scan
from core.url_validator import InvalidRepositoryURL
from storage.database import Database
from ui.components.common import df, get_result, repo_caption
from ui.components.live_progress import LiveProgress


def render() -> None:
    st.header("Repository Scan")
    s = get_settings()
    st.write("Analyse the software supply chain of a **public GitHub repository**. The repository is cloned shallowly into an isolated "
             "temporary folder and inspected statically — no repository code, install script or build is ever executed.")
    with st.form("scan_form"):
        url = st.text_input("GitHub repository URL", placeholder="https://github.com/OWASP/NodeGoat", value=st.session_state.get("last_url", ""))
        c1, c2 = st.columns(2)
        ref = c1.text_input("Branch or tag (optional)", help="Defaults to the repository's default branch.")
        commits = c2.number_input("Lockfile history: recent commits to analyse", 1, 25, 1,
                                  help="Each commit's lockfile changes are compared with its parent.")
        with st.expander("Options"):
            o1, o2, o3 = st.columns(3)
            use_nvd = o1.checkbox("NVD enrichment (CVSS)", True, help="Optional; rate-limited without NVD_API_KEY.")
            use_kev = o1.checkbox("CISA KEV (known exploited)", True)
            registry = o2.checkbox("Registry checks for typosquatting", True)
            enrich = o2.checkbox("Enrich missing SBOM metadata from registries", False)
            reuse = o3.checkbox("Reuse cached scan for identical commit", True)
            keep = o3.checkbox("Keep the cloned repository on disk", False, help="Normally the temporary clone is deleted when the scan ends.")
            llm = o3.checkbox("LLM-written explanations", False, disabled=not s.llm_api_key,
                              help="Requires ANTHROPIC_API_KEY. Output is validated against evidence; templates are used otherwise.")
            baseline = st.text_input("Explicit comparison baseline (commit/ref, optional)", help="Overrides the parent commit for the newest commit.")
        go = st.form_submit_button("Start scan", type="primary")
    if go:
        _run(url, ref, ScanOptions(url=url, ref=ref or None, use_nvd=use_nvd, use_kev=use_kev, registry_checks=registry, enrich_metadata=enrich,
                                   lockfile_commits=int(commits), baseline=baseline or None, reuse_cached=reuse, use_llm=llm, keep_workspace=keep))
    _history()
    r = get_result()
    if r and r.get("status") != "failed":
        _overview(r)


def _run(url: str, ref: str, opts: ScanOptions) -> None:
    st.session_state["last_url"] = url
    st.subheader("Agent pipeline")
    live = LiveProgress()
    try:
        result = run_scan(opts, on_event=live)
    except InvalidRepositoryURL as e:
        live.finish(False)
        st.error(f"Invalid repository URL: {e}")
        return
    except Exception as e:  # last-resort guard: never show a raw crash to the user
        live.finish(False)
        st.error(f"The scan failed unexpectedly: {type(e).__name__}: {e}")
        return
    live.finish(result.get("status") != "failed")
    if result.get("status") == "failed":
        st.error(result.get("error", "Scan failed"))
        return
    st.session_state["result"] = result
    if result.get("from_cache"):
        st.info("An identical commit was scanned before; showing the stored result. Untick 'Reuse cached scan' to rescan.")
    elif result["status"] == "completed_with_errors":
        st.warning("Scan finished with stage errors - see 'Coverage and limitations' below. Results may be incomplete.")
    else:
        st.success("Scan completed. Explore the other pages from the sidebar.")


def _history() -> None:
    try:
        scans = Database(get_settings().db_path).list_scans(15)
    except Exception:
        scans = []
    if scans:
        with st.expander(f"Previous scans ({len(scans)})"):
            df([{"scan": s["scan_id"], "repository": s["repo_url"], "commit": s["commit_sha"][:10], "when": s["scan_timestamp"], "status": s["status"],
                 "findings": (s["summary"] or {}).get("vulnerabilities_confirmed")} for s in scans])
            pick = st.selectbox("Load a scan", [""] + [s["scan_id"] for s in scans], key="hist_pick")
            if pick and st.button("Load selected scan"):
                st.session_state["result"] = Database(get_settings().db_path).load_scan(pick)
                st.rerun()


def _overview(r: dict) -> None:
    repo, insp, sm = r["repo"], r["inspection"], r.get("summary", {})
    st.subheader("Repository overview")
    c = st.columns(4)
    c[0].metric("Repository", repo["name"])
    c[1].metric("Branch", repo.get("branch") or repo.get("ref") or "default")
    c[2].metric("Commit", repo["commit_sha"][:10] if repo["commit_sha"] else "n/a")
    c[3].metric("Scan status", r["status"].replace("_", " "))
    st.write(f"**URL:** {repo['url']}  \n**Full commit SHA:** `{repo['commit_sha']}`  \n**Scan time:** {repo['scan_timestamp']}  \n**Scan ID:** `{repo['scan_id']}`"
             + ("  \n**Clone depth:** shallow" if repo.get("shallow") else ""))
    l, f, e = st.columns(3)
    with l:
        st.markdown("**Languages** (by file extension)")
        df([{"Language": k, "Files": v["files"], "KB": round(v["bytes"] / 1024, 1)} for k, v in insp["languages"].items()][:12])
    with f:
        st.markdown("**Frameworks** (from manifests/config)")
        df([{"Framework": h["name"], "Service": h["service_dir"], "Evidence": h["evidence"]} for h in insp["frameworks"]])
    with e:
        st.markdown("**Ecosystems**")
        st.write(", ".join(insp["ecosystems"]) or "none detected")
        st.markdown("**Services / monorepo roots**")
        df([{"Directory": s_["dir"], "Ecosystems": ", ".join(s_["ecosystems"]), "Frameworks": ", ".join(s_["frameworks"])} for s_ in insp["services"]])
    with st.expander("Manifests, lockfiles and context files"):
        df([{"Path": m["path"], "Kind": m["kind"], "Ecosystem": m["ecosystem"]} for m in insp["manifests"]])
        st.write("**Dockerfiles:**", ", ".join(insp["dockerfiles"]) or "none", " | **Compose/container files:**", ", ".join(insp["container_files"]) or "none")
        st.write("**CI/CD files:**", ", ".join(insp["ci_files"]) or "none")
        st.caption("Container and CI/CD files are recorded as security context only; images are never built or scanned in this MVP.")
    ws = r.get("workspace") or {}
    with st.expander("Where was the repository stored while it was analysed?"):
        st.markdown(f"* Clone location: `{ws.get('clone_path')}`")
        st.markdown(f"* Temporary workspace: `{ws.get('location')}`")
        st.markdown(f"* Kept after the scan: **{ws.get('kept')}** · removed: **{ws.get('removed')}**")
        st.markdown(f"* {ws.get('note', '')}")
        st.caption("The workspace lives under streamlit_app/.workspaces/<scan-id>/ (git-ignored). Only static reads are performed on it.")
    if r.get("analyst"):
        st.subheader("Analyst summary")
        st.markdown(f"**{r['analyst']['headline']}**")
        for p_ in r["analyst"]["paragraphs"]:
            st.markdown(f"- {p_}")
        if r["analyst"]["priorities"]:
            st.markdown("**Prioritised actions**")
            for p_ in r["analyst"]["priorities"]:
                st.markdown(f"1. {p_}")
    st.subheader("Coverage and limitations")
    st.caption("A scan with few or no findings does not prove the repository is safe.")
    for lim in r.get("limitations", []):
        st.markdown(f"- {lim}")
    for k, v in r.get("source_status", {}).items():
        st.markdown(f"- **{k}**: {v.get('state')}" + (f" — {v['errors'][:1]}" if v.get("errors") else ""))
    for err in r.get("errors", []):
        st.error(f"Stage '{err['stage']}' error: {err['error']}")
    with st.expander("Timings and tool versions"):
        st.json({"tool_versions": r.get("tool_versions"), "timings_seconds": r.get("timings")})
