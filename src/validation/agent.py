"""Fix Validation Agent: owns the validation workflow and makes its decisions explicitly.

The code owns the workflow; a typed-decision model (``validation.decider``) only answers narrow questions at four points.
Each answer is used only if it is one of the allowed options *and* its probability reaches the threshold; otherwise the agent's
rule decides. Every decision is logged with its source (``rule`` or ``model``), the probability and the reason.

    load + approval gate (rule only, never delegated)
    -> prepare (clone at the scanned commit, apply patch)
    -> install --(failed)--> D1 "environment or real failure?" --(environment)--> retry once --(still failed)--> baseline install
    -> test    --(failed)--> baseline test --(baseline also fails)--> D2 "same failures or new ones?"
    -> lockfile regeneration in the sandbox when nothing was installed (npm: --package-lock-only --ignore-scripts, no package code runs)
    -> rescan (isolated DB, warm cache) -> compare
    -> D3 "why is the planned version missing?"   (feedback for the remediation engine; never changes the verdict)
    -> verdict (rules) -> model may only make it MORE cautious (D2 -> inconclusive), never less
    -> D4 "would a careful reviewer merge this?"   (advisory, recorded only)
    -> provenance -> reports -> audit
"""
from __future__ import annotations

import json
import shutil
import threading
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Callable, Optional

from config.settings import Settings, get_settings
from core import git_manager as gm
from sandbox import runner as sbx
from storage.cache import Cache
from storage.database import Database
from storage.memory import Memory
from validation import comparison, provenance, report, test_evidence, verdict
from validation.contracts import ApprovedRemediation, Comparison, FinalAssessment, PhaseRun, SandboxOutcome
from validation.decider import Decider

TOOL_VERSION = "0.3.0"
BASELINE_NS, BASELINE_TTL_S = "sandbox-baseline", 7 * 86400
_LOCKS: dict[str, threading.Lock] = {}
_LOCKS_GUARD = threading.Lock()


def _lock_for(key: str) -> threading.Lock:
    """One lock per baseline key, so parallel validations of the same commit compute the baseline once."""
    with _LOCKS_GUARD:
        return _LOCKS.setdefault(key, threading.Lock())
LOCK_RECIPES = {  # lockfile-only resolution: fetches metadata, never runs package code
    "npm": {"image": "node:22-bookworm-slim", "lockfile": "package-lock.json", "lock": "npm install --package-lock-only --ignore-scripts --no-audit --no-fund"},
}
NETWORK_MARKERS = ("ETIMEDOUT", "ENOTFOUND", "ECONNRESET", "EAI_AGAIN", "socket hang up", "Temporary failure in name resolution", "Could not resolve host",
                   "Read timed out", " 429 ", " 503 ", "TLS handshake timeout")


@dataclass
class Decision:
    step: str
    question: str
    answer: Any
    source: str  # rule | model
    probability: Optional[float] = None
    reason: str = ""


@dataclass
class _Run:
    before: dict = field(default_factory=dict)
    rem: Optional[ApprovedRemediation] = None
    approval: dict = field(default_factory=dict)
    ws: Optional[Path] = None
    clone: Optional[Path] = None
    sandbox: SandboxOutcome = field(default_factory=lambda: SandboxOutcome(status="skipped", reason="sandbox not run"))
    docker: dict = field(default_factory=dict)
    after: Optional[dict] = None
    cmp: Optional[Comparison] = None
    subjects: list = field(default_factory=list)
    limitations: list = field(default_factory=list)
    notes: list = field(default_factory=list)
    lock_run: Optional[dict] = None
    cache: Optional[dict] = None  # package-cache volume (sandbox.runner.cache_volume)


class FixValidationAgent:
    name = "Fix Validation Agent"

    def __init__(self, settings: Optional[Settings] = None, db: Optional[Database] = None, decider: Optional[Decider] = None, *, actor: str = "cli",
                 progress: Optional[Callable[[str], None]] = None, use_sandbox: bool = True, threshold: float = 0.7):
        self.s = settings or get_settings()  # also loads .env, so OPENROUTER_API_KEY is visible to the decider
        self.db = db or Database(self.s.db_path)
        self.decider = decider if decider is not None else Decider()
        self.actor, self.use_sandbox, self.threshold = actor, use_sandbox, threshold
        self.say = progress or (lambda m: None)
        self.decisions: list[Decision] = []
        self.timings: dict[str, float] = {}

    # ------------------------------------------------------------------ decisions

    def _ask(self, step: str, key: str, q: dict, state: list, rule_answer: Any, rule_reason: str) -> Decision:
        ans = self.decider.ask(state, {key: q}) if self.decider.enabled else None
        a = (ans or {}).get(key) or {}
        why = "decider disabled (no OPENROUTER_API_KEY)" if not self.decider.enabled else "decider unavailable or malformed answer" if not a else ""
        if a and q["type"] == "choice":
            c, p = a.get("choice"), (a.get("probabilities") or {}).get(a.get("choice"))
            if c in q["criteria"] and isinstance(p, (int, float)) and p >= self.threshold:
                return self._log(Decision(step, q["instructions"], c, "model", round(float(p), 3), f"model choice above threshold {self.threshold}"))
            why = f"model answer '{c}' (p={p}) below threshold {self.threshold} or not allowed"
        if a and q["type"] == "noul":
            p = a.get("noul")
            if isinstance(p, (int, float)):
                return self._log(Decision(step, q["instructions"], p >= 0.5, "model", round(float(p), 3), "model probability"))
        return self._log(Decision(step, q["instructions"], rule_answer, "rule", None, f"{rule_reason} ({why})" if why else rule_reason))

    def _log(self, d: Decision) -> Decision:
        self.decisions.append(d)
        self.say(f"decision [{d.step}] {d.answer} via {d.source}" + (f" p={d.probability}" if d.probability is not None else ""))
        return d

    def _timed(self, step: str, fn: Callable, *a, **kw):
        t0 = time.time()
        try:
            return fn(*a, **kw)
        finally:
            self.timings[step] = round(self.timings.get(step, 0) + time.time() - t0, 1)

    # ------------------------------------------------------------------ workflow

    def run(self, scan_id: str, remediation_id: str) -> dict[str, Any]:
        from validation.fix_validator import _changed_files, _rescan, load_request
        r = _Run()
        t0, started = time.time(), _now()
        r.before, r.rem, r.approval = self._timed("load", load_request, self.db, scan_id, remediation_id)  # hard gate: raises if not approved
        repo, rem = r.before["repo"], r.rem
        mem = Memory(self.db)
        mem.audit(repo["url"], self.actor, "fix_validation_started", f"{rem.id} {rem.source_package}", f"agent; approved by {r.approval.get('actor')}")
        out_dir = report.output_dir(self.s.artifacts_dir, scan_id, rem.id)
        try:
            self.say("Cloning at the scanned commit and applying the patch ...")
            try:
                r.ws, r.clone = self._timed("prepare", sbx.prepare_workspace, self.s, repo, rem.patch_diff)
            except gm.GitError as e:
                r.sandbox = SandboxOutcome(status="error", reason=f"patch could not be applied: {str(e)[:200]}")
                raise
            if self.use_sandbox:
                self._sandbox(r, repo)
            self._lockfile(r)
            if r.sandbox.install_ok or (r.lock_run and r.lock_run.get("exit_code") == 0):
                r.limitations.append("Inventory taken after dependency resolution in the sandbox: it reflects the regenerated lockfile.")
            else:
                r.limitations.append("Dependencies were not resolved: the lockfile was not regenerated, so the rescan sees the patched manifests only.")
            shutil.rmtree(r.clone / ".scg-venv", ignore_errors=True)  # sandbox-only environment, not part of the project inventory
            r.subjects += [provenance.subject(f, r.clone / f) for f in _changed_files(r.clone)]
            self.say("Rescanning the patched tree ...")
            r.after = self._timed("rescan", _rescan, r.clone, r.ws, self.s, self.db)
            if r.after.get("status") == "failed":
                r.limitations.append(f"Rescan failed: {r.after.get('error', '')[:200]}")
            else:
                r.cmp = self._timed("compare", comparison.compare, r.before, r.after, rem)
                if r.after.get("sbom_path") and Path(r.after["sbom_path"]).exists():
                    kept = out_dir / "after_sbom.cdx.json"
                    shutil.copyfile(r.after["sbom_path"], kept)
                    r.subjects.append(provenance.subject("after_sbom.cdx.json", kept))
                if r.cmp.target_versions_present is False:
                    self._explain_missing_target(r)
        except gm.GitError as e:
            r.limitations.append(f"Git error during validation: {str(e)[:200]}")
        finally:
            if r.ws:
                gm.cleanup(r.ws)
            if r.cache and r.cache["scope"] == "run":
                sbx.remove_volume(r.cache["volume"])
        return self._finish(r, scan_id, out_dir, started, t0, mem)

    # ------------------------------------------------------------------ steps

    def _sandbox(self, r: _Run, repo: dict) -> None:
        rem = r.rem
        r.docker = sbx.docker_status()
        if not r.docker["available"]:
            r.sandbox = SandboxOutcome(status="skipped", reason=r.docker["reason"])
            return
        recipe = sbx.detect_recipe(r.clone, rem.ecosystem, rem.service)
        if not recipe:
            r.sandbox = SandboxOutcome(status="skipped", reason=f"No recognised build/test recipe for {rem.ecosystem} in this repository.", docker_version=r.docker["version"])
            return
        recipe["cache"] = r.cache = sbx.cache_volume(rem.ecosystem, repo["url"], rem.id.lower())
        exe = r.docker["exe"]
        out = SandboxOutcome(status="error", recipe=recipe, docker_version=r.docker["version"], cache={"volume": r.cache["volume"], "scope": r.cache["scope"]},
                             isolation="cap-drop ALL, no-new-privileges, 2 CPU / 2 GB / 512 pids, tests without network, no host env or secrets")
        r.sandbox = out
        self.say(f"Installing dependencies in {recipe['image']} (cache volume {r.cache['volume']}) ...")
        inst = self._timed("install", sbx.run_phase, exe, r.clone, recipe, "install")
        out.runs.append(PhaseRun.model_validate(inst))
        if inst["exit_code"] != 0:
            log = inst.get("log_tail", "")
            net = any(m in log for m in NETWORK_MARKERS)
            d = self._ask("install", "install_failure", {"type": "choice", "instructions": "Why did dependency installation fail after a dependency version change?",
                                                         "criteria": {"environment": "Network, registry, rate limit, timeout or container problem unrelated to the change",
                                                                      "dependency_conflict": "The new version conflicts with other dependencies or cannot be resolved",
                                                                      "build_broken": "The project's own build/install is broken independently of this change",
                                                                      "unclear": "The log does not show the cause"}},
                          [f"Change: {rem.source_package} -> {', '.join(f'{c.package} {c.to_version}' for c in rem.changes)} ({rem.ecosystem})", f"Install log tail:\n{log}"],
                          "environment" if net else "unclear", "network error markers in the log" if net else "no network markers")
            if d.answer == "environment":
                self.say("Retrying the install once (environment failure) ...")
                inst = self._timed("install", sbx.run_phase, exe, r.clone, recipe, "install")
                out.runs.append(PhaseRun.model_validate(inst))
            if inst["exit_code"] != 0:
                self.say("Install failed: checking the unpatched baseline install ...")
                base = self._baseline(repo, recipe, exe, need_test=False)
                bi = base["install"]
                out.baseline_cached = base["cached"]
                out.baseline = {"install_ok": bi["exit_code"] == 0, "status": "passed" if bi["exit_code"] == 0 else "failed", "runs": [bi], "cached": base["cached"]}
                out.reason = "dependency installation failed with the patch" + (" and also without it (cannot attribute)" if bi["exit_code"] != 0 else "; the unpatched install succeeds")
                return
        self.say("Running the tests with the network disabled ...")
        test = self._timed("test", sbx.run_phase, exe, r.clone, recipe, "test")
        out.runs.append(PhaseRun.model_validate(test))
        out.test_evidence = test_evidence.summarize(test.get("log_tail", ""))
        out.status = "passed" if test["exit_code"] == 0 else "failed"
        if out.status == "passed":
            ev = out.test_evidence
            if not ev.get("executed"):
                if ev.get("executed") == 0:
                    out.reason = "tests exited 0 but no test was executed" + (f" (log: '{ev['zero_marker']}')" if ev.get("zero_marker") else "")
                else:
                    out.reason = "tests exited 0 but the log shows no recognisable test summary, so execution is unconfirmed"
                r.limitations.append(f"Test evidence: {out.reason}.")
            return
        self.say("Tests failed: checking the unpatched baseline ...")
        base = self._baseline(repo, recipe, exe, need_test=True)
        bi, bt = base["install"], base.get("test")
        out.baseline_cached = base["cached"]
        out.baseline = {"install_ok": bi["exit_code"] == 0, "status": "passed" if bt and bt["exit_code"] == 0 else "failed", "runs": [bi] + ([bt] if bt else []),
                        "cached": base["cached"]}
        if out.baseline["status"] == "passed":
            out.attribution = "the baseline passes: the patch likely broke a test"
            return
        d = self._ask("test", "failure_comparison", {"type": "choice", "instructions": "Comparing the two test logs, does the patched run fail in the same way as the unpatched run?",
                                                     "criteria": {"same_failures": "The same tests fail for the same reasons in both runs",
                                                                  "new_failures": "The patched run has additional or different failures",
                                                                  "unclear": "Cannot tell from the logs"}},
                      [f"Unpatched (baseline) test log tail:\n{(bt or bi).get('log_tail', '')}", f"Patched test log tail:\n{test.get('log_tail', '')}"],
                      "same_failures", "baseline also fails; treat as pre-existing")
        out.attribution = {"same_failures": "the same failure occurs without the patch (pre-existing)", "new_failures": "the patched run shows new failures (model)",
                           "unclear": "both runs fail; the logs do not show whether the patch added failures"}[d.answer]

    def _baseline(self, repo: dict, recipe: dict, exe: str, need_test: bool) -> dict:
        """Unpatched install (+ tests) for this commit and recipe. Memoised: every proposal of the same scan shares one baseline,
        so validating N proposals costs at most one baseline run instead of N. Keyed by commit, recipe and image digest."""
        digest = provenance.docker_image_digest(exe, recipe["image"])
        key = provenance.sha256_text(json.dumps([repo["url"], repo.get("commit_sha"), recipe["image"], digest, recipe["workdir"], recipe["install"], recipe["test"]]))
        cache = Cache(self.db)
        with _lock_for(key):
            hit = cache.get(BASELINE_NS, key, ttl=BASELINE_TTL_S)
            if hit and (hit.get("test") is not None or not need_test or hit["install"]["exit_code"] != 0):
                return {**hit, "cached": True}
            ws_b, base = sbx.prepare_workspace(self.s, repo, None)
            try:
                bi = self._timed("baseline", sbx.run_phase, exe, base, recipe, "install")
                bt = self._timed("baseline", sbx.run_phase, exe, base, recipe, "test") if need_test and bi["exit_code"] == 0 else None
            finally:
                gm.cleanup(ws_b)
            val = {"install": bi, "test": bt}
            if need_test or bi["exit_code"] != 0:  # store only results that fully answer a later question
                cache.set(BASELINE_NS, key, val)
            return {**val, "cached": False}

    def _lockfile(self, r: _Run) -> None:
        """When nothing was installed, regenerate the lockfile inside the sandbox so the rescan sees the patched resolution."""
        rem = r.rem
        if r.sandbox.install_ok:
            return
        lr = LOCK_RECIPES.get(rem.ecosystem)
        svc = r.clone / (rem.service if rem.service not in (".", "") else "")
        if not lr or not (svc / lr["lockfile"]).exists():
            return
        ds = r.docker or sbx.docker_status()
        if not ds.get("available") or not self.use_sandbox:
            r.limitations.append(f"{lr['lockfile']} could not be regenerated: {ds.get('reason') or 'sandbox disabled'}.")
            return
        self.say(f"Regenerating {lr['lockfile']} in the sandbox (no install scripts run) ...")
        recipe = {"image": lr["image"], "workdir": rem.service if rem.service not in ("", None) else ".", "lock": lr["lock"],
                  "cache": r.cache or sbx.cache_volume(rem.ecosystem, r.before["repo"]["url"], rem.id.lower())}
        r.cache = recipe["cache"]
        r.lock_run = self._timed("lockfile", sbx.run_phase, ds["exe"], r.clone, recipe, "lock", 600)
        r.lock_run["image"] = lr["image"]
        if r.lock_run.get("exit_code") != 0:
            r.limitations.append(f"Lockfile regeneration failed (exit {r.lock_run.get('exit_code')}); the rescan sees the stale lockfile.")

    def _explain_missing_target(self, r: _Run) -> None:
        rem = r.rem
        pk = {c.package for c in rem.changes}
        locks = [{"name": d.get("name"), "version": d.get("version"), "direct": d.get("direct"), "lockfile": d.get("lockfile")}
                 for d in r.before.get("lockfile_dependencies") or [] if d.get("name") in pk][:20]
        resolved = bool(r.sandbox.install_ok or (r.lock_run and r.lock_run.get("exit_code") == 0))
        nested = any(d["direct"] is False and d["version"] == c.from_version for d in locks for c in rem.changes)
        rule = "nested_copy" if resolved and nested else "lockfile_stale" if not resolved else "unclear"
        d = self._ask("compare", "missing_target", {"type": "choice", "instructions": "The planned dependency version is not in the rescanned inventory. What is the most likely cause?",
                                                    "criteria": {"lockfile_stale": "Only the manifest changed; the lockfile still pins the old version",
                                                                 "nested_copy": "The vulnerable copy is a nested/transitive one that this manifest entry does not control",
                                                                 "wrong_manifest": "The patch edits a manifest that does not declare the vulnerable copy",
                                                                 "unclear": "The evidence does not show the cause"}},
                      [f"Planned changes: {[c.model_dump(by_alias=True) for c in rem.changes]}", f"Patch:\n{rem.patch_diff or ''}",
                       f"Lockfile records before the change: {locks}", f"Lockfile regenerated before rescan: {resolved}"], rule,
                      "lockfile not regenerated" if rule == "lockfile_stale" else "old version is recorded as a non-direct lockfile entry" if rule == "nested_copy" else "no rule matched")
        r.notes.append({"for": "remediation engine", "finding": d.answer, "source": d.source,
                        "detail": {"lockfile_stale": "Regenerate the lockfile as part of the change (the proposal's lock_note is not applied by the patch).",
                                   "nested_copy": "The vulnerable copy is nested; target its parent or add an override/resolution instead of the root manifest entry.",
                                   "wrong_manifest": "The patch targets a manifest that does not control the vulnerable copy.",
                                   "unclear": "Cause not determined; review the lockfile tree."}[d.answer]})

    def _finish(self, r: _Run, scan_id: str, out_dir: Path, started: str, t0: float, mem: Memory) -> dict[str, Any]:
        rem, repo = r.rem, r.before["repo"]
        rescan_ok = r.after is not None and r.after.get("status") != "failed"
        v, reasons, checks = verdict.decide(r.cmp, r.sandbox, rescan_ok)
        if v in ("verified_fixed", "fixed_untested") and r.sandbox.attribution == "the patched run shows new failures (model)":
            v, reasons = "inconclusive", reasons + ["Downgraded: the decision model judged the patched test failures to differ from the baseline (the model may only make verdicts more cautious)."]
        if r.cmp is not None:
            self._ask("verdict", "reviewer_would_merge", {"type": "noul", "instructions": "Based only on this evidence, would a careful reviewer merge this dependency change?",
                                                          "criteria": {"true": "The evidence supports merging", "false": "The evidence does not support merging yet"}},
                      [f"Verdict: {v}", f"Reasons: {reasons}", f"Checks: {checks}", f"Limitations: {r.limitations}",
                       f"Fixed: {[f.advisory for f in r.cmp.targeted_fixed]}, remaining: {[f.advisory for f in r.cmp.targeted_remaining]}, new: {[(f.advisory, f.severity) for f in r.cmp.newly_introduced][:10]}"],
                      v == "verified_fixed", "merge only on verified_fixed")
        images = [x for x in ((r.sandbox.recipe or {}).get("image"), (r.lock_run or {}).get("image")) if x]
        exe = shutil.which("docker")
        img, digest = next(((i, d) for i, d in ((i, provenance.docker_image_digest(exe, i)) for i in images) if d), (None, None))
        stmt = provenance.statement(r.subjects, repo_url=repo["url"], commit_sha=repo.get("commit_sha") or "", patch_sha256=provenance.sha256_text(rem.patch_diff or ""),
                                    remediation_id=rem.id, recipe=r.sandbox.recipe or ({"lock": (LOCK_RECIPES.get(rem.ecosystem) or {}).get("lock")} if r.lock_run else None),
                                    image_digest=digest, image=img, started_on=started, finished_on=_now(), tool_version=TOOL_VERSION)
        final = FinalAssessment(remediation_id=rem.id, fingerprint=rem.fingerprint, scan_id=scan_id, verdict=v, reasons=reasons, checks=checks,
                                limitations=r.limitations, provenance_ref=str(out_dir / "provenance.intoto.json"), created_at=_now(), approved_by=r.approval.get("actor"))
        self.timings["total"] = round(time.time() - t0, 1)
        validation_report = {"remediation": rem.model_dump(mode="json", by_alias=True, exclude={"patch_diff"}), "sandbox": r.sandbox.model_dump(mode="json"),
                             "lockfile_regeneration": r.lock_run,
                             "rescan": {"ok": rescan_ok, "scan_id": (r.after or {}).get("repo", {}).get("scan_id"), "status": (r.after or {}).get("status"), "errors": (r.after or {}).get("errors", [])},
                             "agent": {"name": self.name, "version": TOOL_VERSION, "decider": {"enabled": self.decider.enabled, "model": self.decider.model, "threshold": self.threshold, "calls": self.decider.calls},
                                       "decisions": [asdict(d) for d in self.decisions], "notes": r.notes, "timings_seconds": self.timings},
                             "signature": provenance.signature_status(), "seconds": self.timings["total"], "tool_version": TOOL_VERSION}
        paths = report.write_outputs(out_dir, comparison=r.cmp.model_dump(mode="json") if r.cmp else {"available": False}, validation_report=validation_report,
                                     final_assessment=final, provenance=stmt)
        mem.audit(repo["url"], self.actor, f"fix_validation_{v}", f"{rem.id} {rem.source_package}", "; ".join(reasons)[:1000])
        return {"final_assessment": final.model_dump(mode="json"), "files": paths, "decisions": [asdict(d) for d in self.decisions], "notes": r.notes, "timings": self.timings}


def _now() -> str:
    from validation.fix_validator import _now as now
    return now()
