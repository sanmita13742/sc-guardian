"""Live progress UI for the agent pipeline: overall bar, per-step checklist grouped by agent, and a streaming activity log."""
from __future__ import annotations

import streamlit as st

from agents.runtime import AGENTS, STEPS

ICON = {"pending": "⚪", "running": "🔵", "done": "✅", "skipped": "⏭️", "error": "❌"}
KIND_ICON = {"start": "▶", "progress": "•", "done": "✔", "skip": "⏭", "decision": "🧭", "observation": "👁", "warning": "⚠️", "error": "❌"}


class LiveProgress:
    """Callable passed as ``on_event`` to the scan; re-renders the placeholders on every agent event."""

    def __init__(self) -> None:
        self.title = st.empty()
        self.bar = st.progress(0.0, text="Starting the agent pipeline...")
        left, right = st.columns([5, 7])
        self.steps_ph = left.empty()
        self.log_ph = right.empty()
        self.log: list[str] = []
        self.status = {s[0]: "pending" for s in STEPS}
        self._render_steps()

    def __call__(self, e: dict) -> None:
        self.status = e.get("status", self.status)
        done = sum(1 for v in self.status.values() if v in ("done", "skipped", "error"))
        running = [s for s, v in self.status.items() if v == "running"]
        cur = running[-1] if running else None
        label = next((f"{a}: {lab}" for sid, a, lab in STEPS if sid == cur), e["message"][:60]) if cur else "finishing"
        self.bar.progress(min(max(e["progress"], 0.0), 1.0), text=f"{int(e['progress'] * 100)}%  -  step {min(done + 1, len(STEPS))}/{len(STEPS)}  -  {label}")
        self.title.caption(f"Agent activity: **{e['agent']}**")
        self.log.append(f"`{e['t']:6.1f}s` {KIND_ICON.get(e['kind'], '•')} **{e['agent']}** · {e['message']}"
                        + (f"  \n   _why: {e['detail']['reason']}_" if e["kind"] == "decision" and e["detail"].get("reason") else ""))
        self._render_steps()
        self.log_ph.markdown("**Live activity** (🧭 decision · 👁 observation · ⚠️ warning)\n\n" + "\n\n".join(self.log[-14:]))

    def _render_steps(self) -> None:
        lines = []
        for a in AGENTS:
            steps = [(sid, lab) for sid, ag, lab in STEPS if ag == a]
            lines.append(f"**{a}**")
            lines += [f"{ICON[self.status[sid]]} {lab}" for sid, lab in steps]
        self.steps_ph.markdown("\n\n".join(lines[:0]) or "  \n".join(lines))

    def finish(self, ok: bool = True) -> None:
        self.bar.progress(1.0, text="100%  -  pipeline finished" if ok else "pipeline stopped")
        self.title.empty()
