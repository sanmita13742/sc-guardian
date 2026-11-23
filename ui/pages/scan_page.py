"""Page 1: repository submission, progress and repository overview."""
from __future__ import annotations

import streamlit as st

from config.settings import get_settings
from sbom.scanner_engine import SCANNER_CHOICES, SCANNER_LABELS, available_scanners
from core.scan_orchestrator import ScanOptions, run_scan
from core.url_validator import InvalidRepositoryURL
from storage.database import Database
from ui.components.memory_panel import history_banner
from ui.components.common import df, get_result, page_header, repo_caption
from ui.components.live_progress import LiveProgress


def render() -> None:
    page_header("Repository Scan", "Analyze software supply chain security for public GitHub repositories statically.")
    s = get_settings()

    with st.form("scan_form"):
        url = st.text_input("GitHub repository URL", placeholder="https://github.com/OWASP/NodeGoat", value=st.session_state.get("last_url", ""))
        c1, c2 = st.columns(2)
        ref = c1.text_input("Branch or tag (optional)", help="Defaults to default branch.")
        commits = c2.number_input("Lockfile history commits", 1, 25, 1, help="Commits to inspect for lockfile tampering.")
        with st.expander("Scan Options", expanded=False):
            o1, o2, o3 = st.columns(3)
            use_nvd = o1.checkbox("NVD CVSS enrichment", True)
            use_kev = o1.checkbox("CISA KEV known exploited", True)
            registry = o2.checkbox("Typosquatting checks", True)
            enrich = o2.checkbox("Fill missing metadata from registries", True, help="deps.dev, npm, PyPI, crates.io, Maven Central: licenses, hashes, links; also verifies lockfile digests. Cached.")
            reuse = o3.checkbox("Reuse cached scan", True)
            keep = o3.checkbox("Keep clone workspace", False)
            from llm.client import detect_provider
            llm = o3.checkbox("Optional LLM reasoning", False, disabled=not s.llm_api_key, help="Set LLM_API_KEY in .env (Groq, Gemini, Anthropic or OpenAI-compatible). Without it everything runs deterministically. AI output is validated against evidence." + (f" Detected provider: {s.llm_provider or detect_provider(s.llm_api_key)}." if s.llm_api_key else ""))
            investigate = o3.checkbox("Investigator (reachability, EPSS)", True)
            remediate = o3.checkbox("Remediation planning", True)
            sbom_scanner = st.selectbox("SBOM scanner", list(SCANNER_CHOICES), format_func=lambda k: SCANNER_LABELS[k],
                                        help="Auto tries Syft, then Trivy, then the built-in rule engine, so an SBOM is always produced.")
            avail = available_scanners(s)
            st.caption("Detected: " + " · ".join(f"**{k}** {'✓' if v else '✗ not installed'}" for k, v in avail.items() if k != "builtin") + " · **built-in rule engine** ✓")
            baseline = st.text_input("Comparison baseline (optional)")
        go = st.form_submit_button("Start Security Scan", type="primary", use_container_width=True)

    if go:
        _run(url, ref, ScanOptions(
            url=url, ref=ref or None, use_nvd=use_nvd, use_kev=use_kev,
            registry_checks=registry, metadata_registry=enrich,
            lockfile_commits=int(commits), baseline=baseline or None,
            reuse_cached=reuse, use_llm=llm, keep_workspace=keep, sbom_scanner=sbom_scanner, investigate=investigate, remediate=remediate,
        ))

    r = get_result()
    if r and r.get("status") != "failed":
        _overview(r)


def _run(url: str, ref: str, opts: ScanOptions) -> None:
    st.session_state["last_url"] = url
    live = LiveProgress()
    try:
        result = run_scan(opts, on_event=live)
    except InvalidRepositoryURL as e:
        live.finish(False)
        st.error(f"Invalid repository URL: {e}")
        return
    except Exception as e:
        live.finish(False)
        st.error(f"Scan failed unexpectedly: {type(e).__name__}: {e}")
        return

    live.finish(result.get("status") != "failed")
    if result.get("status") == "failed":
        st.error(result.get("error", "Scan failed"))
        return

    st.session_state["result"] = result
    if result.get("from_cache"):
        st.info("Loaded cached scan for this commit.")
    elif result["status"] == "completed_with_errors":
        st.warning("Scan finished with stage warnings - see limitations below.")
    else:
        st.success("Scan completed. Navigate via sidebar to inspect results.")


def _overview(r: dict) -> None:
    repo, insp, sm = r["repo"], r["inspection"], r.get("summary", {})
    st.markdown("#### Scan Summary")

    c = st.columns(4)
    c[0].metric("Repository", repo["name"])
    c[1].metric("Commit", repo["commit_sha"][:8] if repo.get("commit_sha") else "n/a")
    c[2].metric("Components", sm.get("components", 0))
    c[3].metric("Confirmed Vulns", sm.get("vulnerabilities_confirmed", 0))

    history_banner(r)
    col_left, col_right = st.columns([1, 1])

    with col_left:
        st.markdown("**Analyst Assessment**")
        if r.get("analyst"):
            st.markdown(f"_{r['analyst']['headline']}_")
            for pri in r["analyst"].get("priorities", [])[:3]:
                st.markdown(f"• {pri}")
        else:
            st.caption("No analyst assessment generated.")

    with col_right:
        st.markdown("**Detected Ecosystems & Languages**")
        st.markdown(f"**Ecosystems:** {', '.join(insp.get('ecosystems', [])) or 'None'}")
        langs = [f"{k} ({round(v['bytes']/1024, 1)} KB)" for k, v in insp.get("languages", {}).items()][:6]
        st.markdown(f"**Languages:** {', '.join(langs) or 'None'}")

    with st.expander("Manifests & Coverage Details", expanded=False):
        df([{"Path": m["path"], "Kind": m["kind"], "Ecosystem": m["ecosystem"]} for m in insp.get("manifests", [])], height=200)
        for lim in r.get("limitations", [])[:4]:
            st.caption(f"• {lim}")
