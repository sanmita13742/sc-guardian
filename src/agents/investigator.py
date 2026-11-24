"""Investigator Agent: turns a raw CVE match into an evidence-backed judgement of whether it matters for *this* application.

For every confirmed finding it runs a short, bounded tool loop (advisory facts -> dependency path -> import evidence -> EPSS) and derives a
verdict with a confidence score and the list of evidence ids it relied on.

* Deterministic planner (default, always runs): fixed rule table, reproducible, no network beyond the EPSS batch.
* LLM planner (optional, only when ``LLM_API_KEY`` is configured and "LLM" is ticked): for the highest-risk findings the model may call
  the same read-only tools (<= N steps) and propose a verdict plus a rationale. The proposal passes a *grounding gate* and is accepted only if
  it cites real evidence ids, mentions only facts present in the evidence, and does not contradict hard evidence (e.g. "not reachable" while an
  import was found). Otherwise the deterministic verdict stays and the rejection reason is recorded. The LLM can therefore never lower
  a finding below what the evidence supports, and every AI-assisted conclusion is labelled as such.

Verdicts never claim safety: ``no_import_evidence`` means "no static import found", not "not exploitable".
"""
from __future__ import annotations

import json
import re
from typing import Any, Optional

from agents.runtime import Runtime
from agents.specialists import ScanState
from intel.epss import EpssClient
from llm.client import LLMError, extract_json, from_settings
from tools import builtin  # noqa: F401  (registers the tools)
from tools.registry import ToolContext, call, catalogue

VERDICTS = ("exploitable_likely", "reachable", "possibly_reachable", "test_only", "no_import_evidence", "needs_review")
LLM_TOOLS = ("advisory_facts", "dependency_path", "find_imports", "package_meta", "epss", "read_snippet")
SEV_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, None: 0}
VERDICT_TEXT = {
    "exploitable_likely": "likely exploitable: the application imports the package and exploitation signals are strong",
    "reachable": "reachable: the application's own code imports the vulnerable package",
    "possibly_reachable": "possibly reachable: a direct dependency that pulls it in is imported by the application (exact use of the vulnerable code is unknown)",
    "test_only": "used only by tests in the analysed source",
    "no_import_evidence": "no import found in the analysed source (the package may still be used through configuration, plugins or a CLI)",
    "needs_review": "insufficient evidence to judge automatically",
}


def _name_of(label: str) -> str:
    return label.rsplit("@", 1)[0] if "@" in label[1:] else label


def confidence(f: dict, reach: dict, epss: Optional[dict]) -> dict:
    basis, score = [], 0
    for ok, pts, txt in ((f["affected_status"] == "confirmed_affected", 30, "affected range confirmed by local version matching"),
                         (bool(f.get("cross_verified")), 20, "independently reproduced by a second OSV query route"),
                         (f.get("cvss_score") is not None, 10, "CVSS score available"),
                         (reach.get("status") not in (None, "unknown"), 20, "static import evidence available"),
                         (reach.get("confidence") == "high", 5, "import matching is exact for this ecosystem"),
                         (bool(f.get("fixed_versions")), 5, "fixed version known"),
                         (epss is not None, 10, "EPSS score available")):
        if ok:
            score += pts
            basis.append(txt)
    return {"score": score, "label": "High" if score >= 75 else "Medium" if score >= 45 else "Low", "basis": basis}


def decide(f: dict, reach: dict, epss: Optional[dict]) -> str:
    e = (epss or {}).get("epss") or 0.0
    hard = bool(f.get("kev")) or e >= 0.5
    severe = (f.get("cvss_score") or 0) >= 7 or f.get("severity") in ("CRITICAL", "HIGH")
    st = reach.get("status")
    if f["affected_status"] != "confirmed_affected":
        return "needs_review"
    if st == "used_by_app":
        return "exploitable_likely" if (hard or (severe and e >= 0.1)) else "reachable"
    if st == "reachable_via_dependency":
        return "possibly_reachable"
    if st == "used_in_tests_only":
        return "test_only"
    if st == "not_imported":
        return "no_import_evidence"
    return "needs_review"


def rationale(f: dict, reach: dict, epss: Optional[dict], verdict: str, ev: dict) -> str:
    parts = [f"{f['package_name']}@{f['installed_version']} ({f['primary_id']}): {VERDICT_TEXT[verdict]}."]
    if reach.get("locations"):
        loc = reach["locations"][0]
        via = f" (via {reach['via'][0]})" if reach.get("via") else ""
        parts.append(f"Import evidence: {loc['path']}:{loc['line']}{via} [{ev.get('reach')}].")
    elif reach.get("status") not in (None, "unknown"):
        parts.append(f"No import evidence in {reach.get('files_analysed', 0)} analysed source file(s) [{ev.get('reach')}].")
    parts.append(f"Dependency: {f['dependency_type']}" + (f" via {', '.join(f['source_packages'][:2])}" if f["source_packages"] else "") + f" [{ev.get('path')}].")
    sev = f"{f['severity']} (CVSS {f['cvss_score']})" if f.get("cvss_score") is not None else (f["severity"] or "severity unavailable")
    parts.append(f"{sev}; " + ("listed in CISA KEV; " if f.get("kev") else "not in CISA KEV; ") + (f"EPSS {epss['epss']:.1%} [{ev.get('epss')}]." if epss else "EPSS unavailable."))
    return " ".join(p for p in parts if p)


class InvestigatorAgent:
    name = "Investigator Agent"

    # ------------------------------------------------------------------ entry
    def run(self, st: ScanState, rt: Runtime) -> None:
        o, s = st.options, st.ctx.s
        if not getattr(o, "investigate", True):
            rt.skip("investigate", "disabled in the scan options")
            return
        if not st.vulns:
            rt.skip("investigate", "no vulnerability findings to investigate")
            return
        with rt.step("investigate", f"Investigating {len(st.vulns)} finding(s) with read-only tools (import evidence, EPSS, dependency path)") as b:
            ctx = ToolContext(repo_dir=st.repo_dir, evidence=st.evidence, http=st.ctx.http, cache=st.ctx.cache, state=st)
            epss_client = EpssClient(st.ctx.http, st.ctx.cache)
            cves = sorted({c for f in st.vulns for c in f["cve_ids"]})
            st.epss = epss_client.get_many(cves)
            st.result["epss_status"] = epss_client.status
            rt.observe("investigate", f"EPSS: {len(st.epss)}/{len(cves)} CVEs scored ({epss_client.status['state']})")
            if epss_client.status["state"] in ("unavailable", "partial"):
                st.result["limitations"].append("EPSS exploitation probabilities were not fully available; exploitability scoring used KEV/CVSS only for the missing CVEs.")
            results: dict[str, dict] = {}
            for i, f in enumerate(st.vulns, 1):
                results[f["finding_id"]] = self._investigate(ctx, f)
                if i % 40 == 0:
                    rt.progress("investigate", f"{i}/{len(st.vulns)} findings investigated")
            st.investigations = results
            idx = st.source_index
            if idx is not None:
                rt.observe("investigate", f"Source index: {sum(idx.files_by_lang.values())} source file(s) analysed ({', '.join(idx.languages) or 'none'})" + ("; truncated at the file limit" if idx.truncated else ""))
            counts: dict[str, int] = {}
            for r in results.values():
                counts[r["verdict"]] = counts.get(r["verdict"], 0) + 1
            rt.observe("investigate", "Verdicts: " + ", ".join(f"{k} {v}" for k, v in sorted(counts.items(), key=lambda kv: VERDICTS.index(kv[0]))))
            client = from_settings(s) if o.use_llm else None
            if o.use_llm and not client:
                rt.warn("investigate", "LLM reasoning requested but LLM_API_KEY is not set - deterministic investigation only")
            if client:
                self._llm_pass(st, rt, ctx, client)
            st.result["investigations"] = results
            b["message"] = ", ".join(f"{v} {k}" for k, v in sorted(counts.items(), key=lambda kv: VERDICTS.index(kv[0]))[:4])

    # ------------------------------------------------------------------ deterministic planner
    def _investigate(self, ctx: ToolContext, f: dict) -> dict:
        fid = f["finding_id"]
        steps: list[dict] = []

        def use(tool: str, **args) -> dict:
            r = call(ctx, tool, args)
            steps.append({"tool": tool, "args": args, "evidence_id": r.get("evidence_id"), "error": r.get("error")})
            return r

        facts = use("advisory_facts", finding_id=fid)
        path = use("dependency_path", finding_id=fid)
        eco = f["ecosystem"]
        if f["dependency_type"] in ("direct", "direct_inferred"):
            r = use("find_imports", package=f["package_name"], ecosystem=eco)
            reach = {**r, "package": f["package_name"], "via": []}
            reach_ev = r.get("evidence_id")
        else:
            srcs = [_name_of(x) for x in f["source_packages"][:3]] or []
            rs = [use("find_imports", package=n, ecosystem=eco) for n in srcs]
            used = [(n, r) for n, r in zip(srcs, rs) if r.get("status") == "used_by_app"]
            tests = [(n, r) for n, r in zip(srcs, rs) if r.get("status") == "used_in_tests_only"]
            if used:
                n, r = used[0]
                reach = {**r, "status": "reachable_via_dependency", "package": n, "via": [x[0] for x in used]}
            elif tests:
                n, r = tests[0]
                reach = {**r, "status": "used_in_tests_only", "package": n, "via": [x[0] for x in tests]}
            elif rs and all(r.get("status") == "not_imported" for r in rs):
                reach = {**rs[0], "status": "not_imported", "package": srcs[0], "via": []}
            else:
                reach = {"status": "unknown", "reason": "source packages could not be traced to application imports", "locations": [], "via": [], "confidence": "none"}
            reach_ev = (rs[0].get("evidence_id") if rs else None)
        epss = None
        for c in f["cve_ids"]:
            e = use("epss", cve=c)
            if e.get("available") and (epss is None or e["epss"] > epss["epss"]):
                epss = {k: e[k] for k in ("epss", "percentile", "date")}
                epss["evidence_id"] = e.get("evidence_id")
        ev = {"reach": reach_ev, "path": path.get("evidence_id"), "osv": facts.get("evidence_id"), "epss": (epss or {}).get("evidence_id")}
        verdict = decide(f, reach, epss)
        conf = confidence(f, reach, epss)
        f["reachability"] = {k: reach.get(k) for k in ("status", "package", "via", "locations", "app_files", "test_files", "confidence", "reason", "files_analysed", "import_density", "import_ratio", "influence_tier")}
        f["epss"], f["epss_percentile"] = (epss or {}).get("epss"), (epss or {}).get("percentile")
        f["verdict"], f["verdict_confidence"] = verdict, conf
        app_cnt = reach.get("app_files", 0)
        dens = reach.get("import_density") or reach.get("influence_tier") or "unknown"
        sev = f.get("severity")
        if sev in ("CRITICAL", "HIGH") and reach.get("status") in ("not_imported", "used_in_tests_only") and not f.get("kev"):
            prio_shift = {"shift": "deprioritized", "reason": f"Deprioritized: no production imports detected despite {sev} advisory severity", "influence_tier": dens}
        elif sev in ("MEDIUM", "LOW") and (dens == "heavy" or app_cnt >= 5):
            prio_shift = {"shift": "elevated", "reason": f"Elevated: heavy application imports across {app_cnt} files in production codebase", "influence_tier": "heavy"}
        else:
            prio_shift = {"shift": "standard", "reason": "Consistent with advisory severity and codebase reachability", "influence_tier": dens}
        f["prioritization"] = prio_shift
        return {"finding_id": fid, "verdict": verdict, "confidence": conf, "reachability": f["reachability"], "epss": epss, "steps": steps, "evidence_ids": [v for v in ev.values() if v],
                "rationale": rationale(f, reach, epss, verdict, ev), "prioritization": prio_shift, "ai_assisted": False, "planner": "deterministic"}

    # ------------------------------------------------------------------ optional LLM planner
    def _llm_pass(self, st: ScanState, rt: Runtime, ctx: ToolContext, client) -> None:
        s = st.ctx.s
        ranked = sorted(st.vulns, key=lambda f: (-(f.get("kev") or 0), -SEV_RANK.get(f["severity"], 0), -(f.get("epss") or 0)))
        pick = [f for f in ranked if f["affected_status"] == "confirmed_affected"][:s.investigator_llm_max]
        if not pick:
            return
        rt.decide("investigate", f"Let {client.label} investigate the {len(pick)} highest-risk finding(s)", reason="Bounded by max steps and a grounding gate; the model may only call read-only tools and cannot "
                  "lower a verdict below what the evidence supports. Only package names, advisory facts and <=11-line import snippets are sent (secrets redacted).", agent="Supervisor")
        accepted = rejected = errors = 0
        for f in pick:
            inv = st.investigations[f["finding_id"]]
            try:
                prop = self._llm_loop(ctx, client, f, inv, s.investigator_max_steps)
            except LLMError as e:
                errors += 1
                inv["llm"] = {"status": "error", "error": str(e)[:160]}
                if errors >= 2:
                    rt.warn("investigate", f"LLM unavailable ({str(e)[:100]}); continuing deterministically")
                    break
                continue
            except Exception as e:  # noqa: BLE001
                inv["llm"] = {"status": "error", "error": f"{type(e).__name__}: {str(e)[:120]}"}
                continue
            problems = self.guard(prop, f, inv, ctx)
            if problems:
                rejected += 1
                inv["llm"] = {"status": "rejected", "problems": problems[:4], "proposal": {"verdict": prop.get("verdict")}}
                continue
            accepted += 1
            inv["llm"] = {"status": "accepted", "model": client.label}
            inv.update(verdict=prop["verdict"], rationale=prop["rationale"], ai_assisted=True, planner=f"llm:{client.label}", steps=inv["steps"] + prop["steps"],
                       evidence_ids=sorted(set(inv["evidence_ids"]) | set(prop["cites"])))
            f["verdict"] = prop["verdict"]
        rt.observe("investigate", f"LLM investigations: {accepted} accepted, {rejected} rejected by the grounding gate, {errors} error(s)")

    def _llm_loop(self, ctx: ToolContext, client, f: dict, inv: dict, max_steps: int) -> dict:
        system = ("You are a supply-chain security investigator. Decide whether a vulnerability in a dependency matters for THIS application. "
                  "Reply with exactly ONE JSON object per turn, either {\"tool\": <name>, \"args\": {...}} to gather evidence, or "
                  "{\"final\": {\"verdict\": <one of " + json.dumps(list(VERDICTS)) + ">, \"rationale\": <=500 characters of plain text that cites evidence ids in square brackets, \"cites\": [evidence ids]}}. "
                  "Rules: use only facts present in tool results; never invent versions, CVE ids, file names, numbers or evidence ids; imports are package-level evidence, not proof of exploitability; "
                  "if the evidence is insufficient answer needs_review. Tools: " + json.dumps([t for t in catalogue() if t["name"] in LLM_TOOLS]))
        have = ctx.evidence.many(inv["evidence_ids"])
        transcript: list[dict] = []
        steps: list[dict] = []
        brief = {"finding_id": f["finding_id"], "package": f"{f['package_name']}@{f['installed_version']}", "ecosystem": f["ecosystem"], "advisory": f["primary_id"], "severity": f["severity"], "cvss": f["cvss_score"],
                 "dependency": f["dependency_type"], "source_packages": f["source_packages"][:3], "kev": f["kev"], "epss": f.get("epss"), "baseline_verdict": inv["verdict"]}
        for _ in range(max_steps):
            user = json.dumps({"finding": brief, "evidence": [{"id": e.id, "summary": e.summary} for e in have], "transcript": transcript}, default=str)
            msg = extract_json(client.complete(system, user, max_tokens=700, json_mode=True))
            if "final" in msg:
                fin = msg["final"]
                return {"verdict": str(fin.get("verdict", "")), "rationale": str(fin.get("rationale", "")).strip(), "cites": [str(c) for c in fin.get("cites", []) if isinstance(c, str)], "steps": steps}
            name, args = msg.get("tool"), msg.get("args") or {}
            if name not in LLM_TOOLS:
                transcript.append({"tool": name, "error": "tool not allowed"})
                continue
            res = call(ctx, name, args)
            steps.append({"tool": name, "args": args, "evidence_id": res.get("evidence_id"), "error": res.get("error"), "by": "llm"})
            if res.get("evidence_id"):
                e = ctx.evidence.get(res["evidence_id"])
                if e and all(x.id != e.id for x in have):
                    have.append(e)
            transcript.append({"tool": name, "args": args, "result": {k: v for k, v in res.items() if k != "snippet"} | ({"snippet": res["snippet"]} if "snippet" in res else {})})
        raise LLMError("no final answer within the step limit")

    @staticmethod
    def guard(prop: dict, f: dict, inv: dict, ctx: ToolContext) -> list[str]:
        """Grounding gate for an LLM proposal. Returns the list of problems (empty = accepted)."""
        problems: list[str] = []
        if prop.get("verdict") not in VERDICTS:
            problems.append(f"verdict '{prop.get('verdict')}' is not an allowed verdict")
            return problems
        text = prop.get("rationale", "")
        if not text or len(text) > 700:
            problems.append("rationale is empty or longer than 700 characters")
        known = set(ctx.evidence._items)
        cites = set(prop.get("cites", []))
        bad = [c for c in cites if c not in known]
        if bad:
            problems.append(f"cites unknown evidence id(s): {', '.join(bad[:3])}")
        if not cites:
            problems.append("no evidence ids cited")
        mentioned = set(re.findall(r"\[([a-z\-]+:[^\]\s]+#[0-9a-f]{6})\]", text))
        if any(m not in known for m in mentioned):
            problems.append("the text references an evidence id that does not exist")
        allowed_ids = set(f["vulnerability_ids"]) | set(f["cve_ids"])
        for cid in set(re.findall(r"\b(?:CVE-\d{4}-\d{4,}|GHSA-[0-9a-z\-]{14,}|PYSEC-\d{4}-\d+)\b", text)):
            if cid not in allowed_ids:
                problems.append(f"mentions advisory id {cid} that is not part of this finding")
        st = inv["reachability"].get("status")
        v = prop["verdict"]
        epss = (inv.get("epss") or {}).get("epss") or 0.0
        hard = bool(f.get("kev")) or epss >= 0.5 or ((f.get("cvss_score") or 0) >= 7 and epss >= 0.1)
        if v in ("no_import_evidence", "test_only") and st in ("used_by_app", "reachable_via_dependency"):
            problems.append("contradicts import evidence (the application imports the package or its parent)")
        if v in ("reachable", "exploitable_likely") and st in ("not_imported", "used_in_tests_only", "unknown"):
            problems.append("claims reachability without import evidence")
        if v == "exploitable_likely" and not hard:
            problems.append("claims likely exploitation without KEV/EPSS/CVSS support")
        if f["affected_status"] != "confirmed_affected" and v != "needs_review":
            problems.append("the affected range is not confirmed; only needs_review is allowed")
        return problems
