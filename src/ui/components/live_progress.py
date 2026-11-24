"""Minimalist live progress UI for the agent pipeline.

Drastically minimizes screen clutter:
- Consolidates 28 granular steps into 5 high-level milestones.
- Filters out verbose internal telemetry, debug statistics, and noisy observations.
- Displays only the most recent meaningful agent actions (max 4 lines).
- Cleanly collapses upon scan completion.
"""
from __future__ import annotations

import streamlit as st

from agents.runtime import STEPS

# 5 High-level architectural pipeline stages
STAGES = [
    ("Reconnaissance", ["validate", "clone", "discover", "classify", "plan"]),
    ("SBOM & Infrastructure", ["lockfiles", "sbom_generate", "sbom_validate", "pipeline", "quality", "metadata"]),
    ("Vulnerability & Graph", ["graph", "osv", "enrich", "trace", "verify", "investigate"]),
    ("Threat & Contextual Risk", ["typosquat", "package_risk", "lockfile_history", "risk", "explain"]),
    ("Remediation & Assembly", ["remediate", "validate_fix", "memory", "summary", "export", "cleanup"]),
]

# Telemetry patterns to suppress from live display to eliminate petty noise
NOISY_PATTERNS = (
    "licenses 0->",
    "hashes 0->",
    "supplier 0->",
    "description 0->",
    "external_refs",
    "published_at",
    "registries:",
    "0 fetched",
    "from cache",
    "integrity: absent",
    "avg completeness",
    "coverage (scanner",
    "install-time scripts",
    "unique packages queried",
    "advisories returned",
    "package names compared",
    "similarity candidates",
    "source file(s) analysed",
    "routes_agree",
    "disagreement_count",
    "attested of",
    "verdicts: ",
)


def _is_noisy(msg: str) -> bool:
    """Filter out verbose debugging/telemetry metrics."""
    m = msg.lower()
    return any(p in m for p in NOISY_PATTERNS)


def _clean_message(msg: str, max_len: int = 65) -> str:
    """Clean and condense messages to a concise single line."""
    clean = " ".join(msg.split())
    if len(clean) > max_len:
        return clean[:max_len - 3] + "..."
    return clean


class LiveProgress:
    """Minimalist live progress indicator for the agent pipeline."""

    def __init__(self) -> None:
        self.bar = st.progress(0.0, text="Initializing agent pipeline...")
        left, right = st.columns([5, 7])
        self.steps_ph = left.empty()
        self.log_ph = right.empty()
        self.log: list[str] = []
        self.status = {s[0]: "pending" for s in STEPS}
        self._render_milestones(None, 0)

    def __call__(self, e: dict) -> None:
        self.status = e.get("status", self.status)
        done = sum(1 for v in self.status.values() if v in ("done", "skipped", "error"))
        running = [s for s, v in self.status.items() if v == "running"]
        cur = running[-1] if running else None

        active_label = (
            next((lab for sid, _, lab in STEPS if sid == cur), e.get("message", "finishing"))
            if cur
            else "finishing"
        )
        active_agent = e.get("agent", "")

        progress_pct = int(min(max(e.get("progress", 0.0), 0.0), 1.0) * 100)
        self.bar.progress(
            min(max(e.get("progress", 0.0), 0.0), 1.0),
            text=f"{progress_pct}% · {active_agent} · {active_label}",
        )

        # Filter out noisy petty telemetry: only display high-signal decisions, warnings, errors, and key milestones
        msg = e.get("message", "")
        kind = e.get("kind", "progress")

        # Suppress internal debug observations and raw counter metrics
        is_high_signal = kind in ("decision", "warning", "error") or (
            kind in ("done", "start") and not _is_noisy(msg) and len(msg) < 60
        )

        if is_high_signal and not _is_noisy(msg):
            t_str = f"{e.get('t', 0.0):4.1f}s"
            if kind == "decision":
                icon = "🧭"
            elif kind in ("warning", "error"):
                icon = "⚠️"
            elif kind == "done":
                icon = "✓"
            else:
                icon = "•"

            clean_msg = _clean_message(msg)
            entry = f"`{t_str}` {icon} **{active_agent}** · {clean_msg}"
            # Keep log strictly capped at 3 entries to maintain minimalism
            if not self.log or self.log[-1] != entry:
                self.log.append(entry)

        self._render_milestones(cur, done)
        self._render_log()

    def _render_milestones(self, cur_step: str | None, done_count: int) -> None:
        lines = ["**Pipeline**"]
        for stage_name, steps in STAGES:
            stage_done = all(self.status.get(s) in ("done", "skipped", "error") for s in steps)
            stage_active = any(self.status.get(s) == "running" for s in steps) or (
                cur_step in steps
            )

            if stage_done:
                lines.append(f"✅ {stage_name}")
            elif stage_active:
                lines.append(f"🔵 **{stage_name}**")
                # Show subtle active step
                step_label = next((lab for sid, _, lab in STEPS if sid == cur_step), None)
                if step_label:
                    lines.append(f"&nbsp;&nbsp;&nbsp;&nbsp;↳ _{_clean_message(step_label, 36)}_")
            else:
                lines.append(f"⚪ <span style='color: #888;'>{stage_name}</span>")

        self.steps_ph.markdown("\n\n".join(lines), unsafe_allow_html=True)

    def _render_log(self) -> None:
        recent = self.log[-3:] if self.log else ["_Awaiting agent observations..._"]
        self.log_ph.markdown("**Activity**\n\n" + "\n\n".join(recent))

    def finish(self, ok: bool = True) -> None:
        if ok:
            self.bar.progress(1.0, text="100% · Analysis completed successfully")
        else:
            self.bar.progress(1.0, text="Pipeline stopped")
        # Drastically minimize post-scan clutter
        self.steps_ph.empty()
        self.log_ph.empty()
