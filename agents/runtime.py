"""Agent runtime: shared scan state, a step catalogue with weighted progress, and an append-only decision trace.

Every agent reports through ``Runtime`` so the UI can show a live progress bar, per-agent activity and every
decision (what was observed, what was decided and why). The trace is stored with the scan result.
"""
from __future__ import annotations

import threading
import time
import traceback
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import Any, Callable, Optional

# (step id, owning agent, label) - the full pipeline. Progress = finished steps / total.
STEPS: list[tuple[str, str, str]] = [
    ("validate", "Supervisor", "Validate the repository URL"),
    ("clone", "Recon Agent", "Clone the repository into an isolated workspace"),
    ("discover", "Recon Agent", "Find manifest, lock and configuration files"),
    ("classify", "Recon Agent", "Detect languages, frameworks and services"),
    ("plan", "Supervisor", "Plan the analysis strategy"),
    ("lockfiles", "SBOM Agent", "Parse lockfiles (independent inventory)"),
    ("sbom_generate", "SBOM Agent", "Generate the CycloneDX SBOM (Syft, Trivy or built-in rule engine)"),
    ("sbom_validate", "SBOM Agent", "Validate the SBOM"),
    ("pipeline", "Pipeline Agent", "Analyse Dockerfiles, compose files and CI/CD workflows"),
    ("quality", "SBOM Agent", "Assess SBOM quality and completeness"),
    ("metadata", "SBOM Agent", "Fuse metadata (lockfile + scanner + registries) and verify integrity"),
    ("graph", "Graph Agent", "Build the dependency graph"),
    ("osv", "Vulnerability Agent", "Query OSV and validate affected version ranges"),
    ("enrich", "Vulnerability Agent", "Enrich with NVD (CVSS) and CISA KEV"),
    ("trace", "Vulnerability Agent", "Trace each vulnerable component to its source package"),
    ("verify", "Verification Agent", "Cross-check findings against OSV by PURL (ground truth)"),
    ("investigate", "Investigator Agent", "Investigate findings: reachability, EPSS exploitability, evidence-backed verdict"),
    ("typosquat", "Threat Agent", "Typosquatting analysis"),
    ("lockfile_history", "Threat Agent", "Compare lockfiles against Git history"),
    ("risk", "Risk Agent", "Deterministic risk scoring and correlation"),
    ("explain", "Risk Agent", "Evidence-grounded explanations"),
    ("memory", "Memory Agent", "Compare with previous scans and record finding history"),
    ("summary", "Analyst Agent", "Executive summary and prioritised actions"),
    ("export", "Analyst Agent", "Write reports and save to SQLite"),
    ("cleanup", "Supervisor", "Clean up the temporary workspace"),
]
STEP_INDEX = {s[0]: i for i, s in enumerate(STEPS)}
AGENTS = list(dict.fromkeys(s[1] for s in STEPS))

AGENT_ROLES = {
    "Supervisor": "Plans the run, observes every agent's result, and adapts (fallbacks, retries, triage) - owns the decision trace.",
    "Recon Agent": "Acquires the repository safely and discovers what it contains (config files, ecosystems, frameworks, services).",
    "SBOM Agent": "Builds the software inventory: lockfile parsing, CycloneDX generation (Syft / Trivy / built-in rule engine), validation and quality assessment.",
    "Investigator Agent": "Investigates each finding with read-only tools (import/reachability evidence, EPSS, dependency path) and issues a verdict with confidence and cited evidence; optional LLM reasoning behind a grounding gate.",
    "Pipeline Agent": "Analyses Dockerfiles, docker-compose and CI/CD definitions (GitHub Actions, GitLab, Jenkins, ...) for unsafe or unpinned components; images and actions join the SBOM.",
    "Graph Agent": "Builds the directed dependency graph and checks its integrity.",
    "Vulnerability Agent": "Correlates components with OSV, validates ranges, enriches with NVD/KEV, traces findings to source packages.",
    "Verification Agent": "Independently re-checks findings against the ground-truth database via a second query route.",
    "Threat Agent": "Detects suspicious dependency changes: typosquatting and modified lockfiles in Git history.",
    "Risk Agent": "Scores risk with transparent rules, correlates detections and writes evidence-grounded explanations.",
    "Memory Agent": "Remembers every scan: tells new findings from persisting and fixed ones, keeps analyst decisions with reasons and expiry.",
    "Analyst Agent": "Summarises results, prioritises actions, and produces reports.",
}


@dataclass
class Event:
    ts: float
    agent: str
    step: str
    kind: str  # start | progress | done | skip | decision | observation | warning | error
    message: str
    progress: float  # overall 0..1 after this event
    detail: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {"t": round(self.ts, 2), "agent": self.agent, "step": self.step, "kind": self.kind, "message": self.message,
                "progress": round(self.progress, 3), "detail": self.detail}


class Runtime:
    """Collects events, computes overall progress, isolates step failures."""

    def __init__(self, on_event: Optional[Callable[[dict], None]] = None):
        self.t0 = time.time()
        self.on_event = on_event
        self.events: list[Event] = []
        self.status: dict[str, str] = {s[0]: "pending" for s in STEPS}  # pending|running|done|skipped|error
        self.timings: dict[str, float] = {}
        self.errors: list[dict] = []
        self._started: dict[str, float] = {}
        self._lock = threading.RLock()  # agents on parallel graph branches share this runtime
        self.callback_errors = 0

    # ---------------------------------------------------------------- progress
    def overall(self) -> float:
        done = sum(1 for v in self.status.values() if v in ("done", "skipped", "error"))
        running = sum(1 for v in self.status.values() if v == "running")
        return min((done + 0.5 * running) / len(STEPS), 1.0)

    def _emit(self, step: str, kind: str, message: str, detail: Optional[dict] = None, agent: Optional[str] = None) -> None:
        agent = agent or (STEPS[STEP_INDEX[step]][1] if step in STEP_INDEX else "Supervisor")
        with self._lock:
            ev = Event(time.time() - self.t0, agent, step, kind, message, self.overall(), detail or {})
            self.events.append(ev)
            payload = {**ev.to_dict(), "label": STEPS[STEP_INDEX[step]][2] if step in STEP_INDEX else step, "status": dict(self.status)}
        if self.on_event:
            try:
                self.on_event(payload)
            except Exception:
                self.callback_errors += 1  # UI callback problems must never break a scan (counted, surfaced in the result)

    # ---------------------------------------------------------------- step lifecycle
    def begin(self, step: str, message: str = "") -> None:
        with self._lock:
            if self.status[step] == "running":
                self._emit(step, "progress", message)
                return
            self.status[step] = "running"
            self._started[step] = time.time()
            self._emit(step, "start", message or STEPS[STEP_INDEX[step]][2])

    def progress(self, step: str, message: str, **detail: Any) -> None:
        self._emit(step, "progress", message, detail)

    def done(self, step: str, message: str = "", **detail: Any) -> None:
        with self._lock:
            if self.status[step] == "pending":
                self._started[step] = time.time()
            self.status[step] = "done"
            self.timings[step] = round(time.time() - self._started.get(step, time.time()), 2)
            self._emit(step, "done", message or "done", detail)

    def skip(self, step: str, reason: str) -> None:
        with self._lock:
            self.status[step] = "skipped"
            self._emit(step, "skip", reason)

    def fail(self, step: str, err: str) -> None:
        with self._lock:
            self.status[step] = "error"
            self.errors.append({"stage": step, "error": err})
            self._emit(step, "error", err)

    def finish_open(self, step: str, message: str = "done") -> None:
        if self.status[step] == "running":
            self.done(step, message)

    # ---------------------------------------------------------------- agent reasoning
    def observe(self, step: str, message: str, agent: Optional[str] = None, **detail: Any) -> None:
        self._emit(step, "observation", message, detail, agent)

    def decide(self, step: str, message: str, reason: str = "", agent: Optional[str] = None, **detail: Any) -> None:
        self._emit(step, "decision", message, {"reason": reason, **detail}, agent)

    def warn(self, step: str, message: str, agent: Optional[str] = None, **detail: Any) -> None:
        self._emit(step, "warning", message, detail, agent)

    @contextmanager
    def step(self, step: str, message: str = ""):
        """Run a step; an exception is recorded as a step error and swallowed so independent steps continue."""
        self.begin(step, message)
        box: dict[str, Any] = {"ok": True}
        try:
            yield box
        except Exception as e:
            box["ok"] = False
            self.fail(step, f"{type(e).__name__}: {str(e)[:300]}")
            self.errors[-1]["trace"] = traceback.format_exc()[-500:]
        else:
            if self.status[step] == "running":
                self.done(step, box.get("message", "done"), **box.get("detail", {}))

    def trace(self) -> list[dict]:
        return [e.to_dict() for e in self.events]
