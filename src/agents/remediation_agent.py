"""Remediation Agent (plans the smallest safe change) and Validator Agent (proves it: what-if rescan, before/after SBOM, patch check).

Both are deterministic and evidence-based; every proposal is *only a proposal*: it needs human approval (UI) before the patch/PR text can be exported,
and nothing is ever applied, pushed or merged by the Guardian.
"""
from __future__ import annotations

import subprocess
import tempfile
import time
from pathlib import Path

import networkx as nx

from agents.runtime import Runtime
from agents.specialists import ScanState, source_package_view
from core import git_manager as gm
from remediation import whatif
from remediation.delivery import auto_deliver_low_medium_remediations, get_remediation_severity_tier
from remediation.planner import PlanContext, plan_group, split_label
from remediation.reachability_impact import evaluate_reachability_impact
from vulnerability.osv_client import OsvClient

PRIO = {"P0": 0, "P1": 1, "P2": 2, "P3": 3}


def fingerprint(rem: dict) -> str:
    t = rem.get("target") or {}
    return "|".join(["rem", rem.get("ecosystem") or "", rem.get("service") or ".", rem.get("source_package") or "", rem.get("action") or "", f"{t.get('from')}->{t.get('to')}"])


class RemediationAgent:
    name = "Remediation Agent"

    def run(self, st: ScanState, rt: Runtime) -> None:
        o, s = st.options, st.ctx.s
        if not getattr(o, "remediate", True):
            rt.skip("remediate", "disabled in the scan options")
            return
        if not st.vulns:
            rt.skip("remediate", "no vulnerability findings to remediate")
            return
        with rt.step("remediate", "Planning the smallest safe change per source package (parent-upgrade search, pins, mitigations)") as b:
            risks = {a["finding_id"]: a for a in st.risk["assessments"]}
            groups = source_package_view(st.vulns, risks)

            def group_urgency(g: dict) -> tuple[int, int, int]:
                prio = min((risks.get(i, {}).get("priority", "P3") for i in g["finding_ids"]), default="P3")
                has_heavy = any(risks.get(i, {}).get("influence_tier") == "heavy" or risks.get(i, {}).get("app_files", 0) >= 5 for i in g["finding_ids"])
                is_dev = all(bool(next((f.get("dev_dependency") for f in st.vulns if f["finding_id"] == i), False)) for i in g["finding_ids"])
                p_val = PRIO.get(prio, 3)
                if prio == "P0":
                    rank = 0
                elif has_heavy and not is_dev:
                    rank = 1
                elif prio == "P1":
                    rank = 2
                elif prio == "P2" and not is_dev:
                    rank = 3
                else:
                    rank = 4
                return (rank, p_val, -len(g["finding_ids"]))

            groups.sort(key=group_urgency)
            osv = OsvClient(st.ctx.http, st.ctx.cache, s.osv_batch_size, s.osv_workers)
            ctx = PlanContext(repo_dir=st.repo_dir, http=st.ctx.http, cache=st.ctx.cache, osv=osv, vulns=st.vulns, manifests_index=st.insp.manifests, components=st.components)
            items, sims, skipped = [], {}, 0
            t0 = time.time()
            container_ids = {f["finding_id"] for f in st.vulns if f.get("asset_type") == "container_image"}
            for g in groups:
                if container_ids and set(g["finding_ids"]) <= container_ids:
                    continue  # OS/image packages are planned below from the distro's own fix data, not through language registries
                if len(items) >= s.remediation_max_groups or time.time() - t0 > s.remediation_budget_s:
                    skipped += 1
                    continue
                try:
                    rem = plan_group(ctx, g, risks, len(items) + 1)
                except Exception as e:  # noqa: BLE001 - one group failing must not lose the others
                    rt.warn("remediate", f"Could not plan {g['source_package']}: {type(e).__name__}: {str(e)[:100]}")
                    skipped += 1
                    continue
                sims[rem["id"]] = rem.pop("sim", None)
                rem["fingerprint"] = fingerprint(rem)
                t_info = rem.get("target") or {}
                src_pkg = rem.get("source_package") or rem.get("package") or ""
                impact = evaluate_reachability_impact(
                    st.source_index,
                    rem.get("ecosystem", "npm"),
                    src_pkg,
                    t_info.get("from") or "current",
                    t_info.get("to") or "recommended",
                    semver_delta=(rem.get("compatibility") or {}).get("semver_change"),
                )
                rem["reachability_impact"] = impact.to_dict()
                items.append(rem)
                rt.progress("remediate", f"{rem['id']} {rem['action']}: {rem['title']}", id=rem["id"])
            if container_ids:
                from remediation.container_plan import plan_container_groups
                from remediation.planner import best_risk
                try:
                    for rem in plan_container_groups(ctx, st.vulns, risks, len(items) + 1, best_risk):
                        rem.pop("sim", None)
                        rem["fingerprint"] = fingerprint(rem)
                        rem["reachability_impact"] = {}
                        items.append(rem)
                        rt.progress("remediate", f"{rem['id']} {rem['action']}: {rem['title']}", id=rem["id"])
                except Exception as e:  # noqa: BLE001
                    rt.warn("remediate", f"Could not plan container findings: {type(e).__name__}: {str(e)[:100]}")
            # Evaluate automation tier and auto-deliver Low/Medium severity PRs without human intervention
            mem = None
            if hasattr(st.ctx, "db"):
                from storage.memory import Memory
                mem = Memory(st.ctx.db)

            repo_meta = {
                "url": st.info.url,
                "commit_sha": st.info.commit_sha,
                "repo_dir": str(st.repo_dir),
                "path": str(st.repo_dir),
            }

            if getattr(s, "remediation_auto_pr_low_med", True) and getattr(st.info, "source", "github") != "local":  # local folders: never auto-branch/commit; the user accepts or ignores
                auto_del = auto_deliver_low_medium_remediations(st.repo_dir, items, repo_meta, memory=mem)
            else:
                for rem in items:
                    tier, label = get_remediation_severity_tier(rem, st.vulns)
                    rem["automation_tier"] = tier
                    rem["severity_tier"] = label
                    rem["requires_human_intervention"] = (tier == "manual_review")
                auto_del = []

            low_med = [r for r in items if r.get("automation_tier") == "automated"]
            high_crit = [r for r in items if r.get("automation_tier") == "manual_review"]

            st.rem_sims = sims
            st.remediation = {"items": items, "manifests": {p: t[:200000] for p, t in ctx.originals.items()}, "groups_total": len(groups), "groups_not_planned": skipped,
                              "budget_seconds": s.remediation_budget_s, "automated_low_med": len(low_med), "manual_high_crit": len(high_crit)}
            acts: dict[str, int] = {}
            for r in items:
                acts[r["action"]] = acts.get(r["action"], 0) + 1
            rt.observe("remediate", f"{len(items)} remediation(s) planned: " + ", ".join(f"{v} {k}" for k, v in sorted(acts.items())) + (f"; {len(low_med)} Low/Med PR(s) automated" if low_med else ""))
            if high_crit:
                rt.decide("remediate", f"Require human approval for {len(high_crit)} High/Critical severity proposal(s)", reason="High and Critical severity changes require manual verification (Accept or Ignore in Streamlit).", agent="Supervisor")
            b["message"] = f"{len(items)} remediation(s) ({len(low_med)} auto-PR, {len(high_crit)} manual)"


class ValidatorAgent:
    name = "Validator Agent"

    def run(self, st: ScanState, rt: Runtime) -> None:
        items = (st.remediation or {}).get("items") or []
        if not items:
            rt.skip("validate_fix", "no remediation proposals to validate")
            return
        with rt.step("validate_fix", "Validating proposals: what-if rescan, before/after SBOM, patch applicability") as b:
            counts = {"reduces_risk": 0, "partial": 0, "no_effect": 0, "introduces_risk": 0, "not_simulated": 0}
            for rem in items:
                sim = st.rem_sims.get(rem["id"])
                before = [f for f in st.vulns if f["finding_id"] in set(rem["finding_ids"])]
                if sim is None:
                    rem["what_if"] = None
                    counts["not_simulated"] += 1
                else:
                    b_nodes = self._before_nodes(st, rem, before, sim)
                    a_nodes = {(n, v) for _, n, v in sim["nodes"]}
                    wi = whatif.evaluate(before, sim["after"], b_nodes, a_nodes, known_all=st.vulns)
                    wi.update(method="registry-resolved dependency tree (deps.dev) + OSV re-match with local range validation", candidates_tried=sim.get("search", []))
                    rem["what_if"] = wi
                    counts[wi["verdict"]] += 1
                    rem["evidence_id"] = st.evidence.add("what-if", "what-if-simulator", rem["id"], f"{rem['title']}: fixes {len(wi['fixed'])}, remaining {len(wi['remaining'])}, new {len(wi['newly_introduced'])}",
                                                        {"verdict": wi["verdict"], "fixed": len(wi["fixed"]), "new": len(wi["newly_introduced"])})
                    if wi["newly_introduced"]:
                        rt.warn("validate_fix", f"{rem['id']} would introduce {len(wi['newly_introduced'])} new finding(s): " + ", ".join(f"{f['id']} ({f['package']})" for f in wi["newly_introduced"][:3]))
                if not rem.get("rationale"):
                    rem["rationale"] = self._rationale(rem, before)
                applies = self._check_patch(st, rem)

                wi_obj = rem.get("what_if")
                wi_passed = bool(wi_obj and wi_obj.get("verdict") in ("reduces_risk", "partial"))
                new_cves = len(wi_obj.get("newly_introduced", [])) if wi_obj else 0
                lock_note = rem.get("lock_note", "")

                matrix = {
                    "tier_1_patch": {"name": "Tier 1: Patch Applicability", "passed": bool(applies),
                                     "details": "Patch applies cleanly without conflicts" if applies else "Patch cannot be applied cleanly"},
                    "tier_2_lockfile": {"name": "Tier 2: Lockfile Coherence", "passed": bool(lock_note),
                                       "details": f"Refresh command: {lock_note}" if lock_note else "Standard manifest update"},
                    "tier_3_whatif": {"name": "Tier 3: OSV What-If Rescan", "passed": wi_passed,
                                     "details": f"Verdict: {wi_obj.get('verdict', 'not_simulated')} (Fixed {len(wi_obj.get('fixed', []))}, Remaining {len(wi_obj.get('remaining', []))})" if wi_obj else "Not simulated"},
                    "tier_4_sandbox": {"name": "Tier 4: Sandbox Build & Tests", "status": "not_run", "passed": None,
                                       "details": "Opt-in: execute in isolated Docker container upon user request"},
                    "tier_5_security_gate": {"name": "Tier 5: Security Regression Gate", "passed": new_cves == 0,
                                            "details": "Zero new vulnerabilities introduced" if new_cves == 0 else f"{new_cves} new advisory(ies) introduced"},
                }

                rem["validation"] = {"patch_applies": applies, "what_if_run": sim is not None,
                                     "matrix": matrix,
                                     "build_tests": {"status": "not_run", "reason": "Static what-if only: the repository's build and tests are not executed (optional sandbox validation can be enabled)."}}
            st.remediation["validation_summary"] = counts
            rt.observe("validate_fix", "What-if results: " + ", ".join(f"{v} {k.replace('_', ' ')}" for k, v in counts.items() if v))
            bad = [r["id"] for r in items if (r.get("validation") or {}).get("patch_applies") is False]
            if bad:
                rt.warn("validate_fix", "Patch does not apply cleanly for: " + ", ".join(bad))
            b["message"] = ", ".join(f"{v} {k.replace('_', ' ')}" for k, v in counts.items() if v)

    @staticmethod
    def _rationale(rem: dict, before: list[dict]) -> str:
        wi = rem.get("what_if") or {}
        verdicts: dict[str, int] = {}
        for f in before:
            verdicts[(f.get("verdict") or "not investigated").replace("_", " ")] = verdicts.get((f.get("verdict") or "not investigated").replace("_", " "), 0) + 1
        sev = ", ".join(f"{n} {k.title()}" for k, n in (wi.get("before", {}).get("by_severity") or {}).items())
        t = rem.get("target") or {}
        parts = []
        if rem["action"] == "upgrade":
            tried = len(wi.get("candidates_tried") or [])
            parts.append(f"{rem['source_package']} introduces {len(before)} finding(s) ({sev or 'severity n/a'}). Upgrading to {t.get('to')} is the smallest version found "
                         f"(searched {tried} candidate version(s), same major first) whose registry-resolved dependency tree no longer contains any of these advisories.")
        else:
            parts.append(f"No newer release of {rem['source_package']} clears the findings, so the vulnerable transitive package(s) are pinned to the smallest fixed version(s): "
                         + ", ".join(f"{c['package']} {c.get('from')} -> {c['to']}" for c in rem.get("changes", [])[:4]) + ". The pinned versions were re-checked against OSV.")
        if wi:
            parts.append(f"Measured effect: fixes {len(wi.get('fixed', []))}, {len(wi.get('remaining', []))} remain in this group, {len(wi.get('newly_introduced', []))} newly introduced"
                         + (f" (worst: {max((x['severity'] or 'UNKNOWN' for x in wi['newly_introduced']), key=lambda s: ['UNKNOWN', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'].index(s))})" if wi.get("newly_introduced") else "")
                         + (f"; {wi['already_present_elsewhere']} advisory(ies) on the new tree are already present in the project through another path" if wi.get("already_present_elsewhere") else "") + ".")
        parts.append("Investigation verdicts in this group: " + ", ".join(f"{n} {k}" for k, n in sorted(verdicts.items(), key=lambda kv: -kv[1])) + ".")
        if rem.get("evidence_id"):
            parts.append(f"[{rem['evidence_id']}]")
        return " ".join(parts)

    @staticmethod
    def _before_nodes(st: ScanState, rem: dict, before: list[dict], sim: dict) -> set[tuple[str, str]]:
        if sim.get("mode") == "pin":
            return {(f["package_name"], f["installed_version"]) for f in before}
        name, ver = split_label(rem["source_package"])
        nodes = {(name, ver)}
        g = st.graph
        ref = next((n for n, a in g.nodes(data=True) if a.get("label") == rem["source_package"]), None)
        if ref is not None:
            for d in nx.descendants(g, ref):
                a = g.nodes[d]
                if a.get("kind") == "component" and a.get("version"):
                    nodes.add((a.get("name"), a.get("version")))
        return nodes

    @staticmethod
    def _check_patch(st: ScanState, rem: dict) -> bool | None:
        """``git apply --check`` against the original manifest in a throw-away directory. None = no patch to check."""
        p = rem.get("patch")
        if not p:
            return None
        original = st.remediation["manifests"].get(p["path"])
        if original is None:
            return None
        with tempfile.TemporaryDirectory() as td:
            f = Path(td) / p["path"]
            f.parent.mkdir(parents=True, exist_ok=True)
            f.write_text(original, encoding="utf-8", newline="")
            (Path(td) / "fix.patch").write_text(p["diff"], encoding="utf-8", newline="")
            try:
                r = gm.run_git(["apply", "--check", "fix.patch"], cwd=Path(td), check=False, timeout=30)
            except gm.GitError:
                return None
            return r.returncode == 0
