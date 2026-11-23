"""Design tokens and semantic theme helpers for SC Guardian.

Provides consistent severity styling, status indicators, and design tokens
strictly aligned with the design system in .streamlit/config.toml.
"""
from __future__ import annotations

from typing import Optional

# Semantic Severity Palette (Aligned with CVSS tiers and WCAG 2.1 AA contrast)
SEV_COLORS: dict[Optional[str], str] = {
    "CRITICAL": "#f85149",
    "HIGH": "#f0883e",
    "MEDIUM": "#d29922",
    "LOW": "#58a6ff",
    "INFORMATIONAL": "#8b949e",
    "UNKNOWN": "#8b949e",
    None: "#8b949e",
}

SEV_BG_COLORS: dict[Optional[str], str] = {
    "CRITICAL": "rgba(248, 81, 73, 0.15)",
    "HIGH": "rgba(240, 136, 62, 0.15)",
    "MEDIUM": "rgba(210, 153, 34, 0.15)",
    "LOW": "rgba(88, 166, 255, 0.15)",
    "INFORMATIONAL": "rgba(139, 148, 158, 0.15)",
    "UNKNOWN": "rgba(139, 148, 158, 0.15)",
    None: "rgba(139, 148, 158, 0.15)",
}

SEV_BORDER_COLORS: dict[Optional[str], str] = {
    "CRITICAL": "rgba(248, 81, 73, 0.35)",
    "HIGH": "rgba(240, 136, 62, 0.35)",
    "MEDIUM": "rgba(210, 153, 34, 0.35)",
    "LOW": "rgba(88, 166, 255, 0.35)",
    "INFORMATIONAL": "rgba(139, 148, 158, 0.35)",
    "UNKNOWN": "rgba(139, 148, 158, 0.35)",
    None: "rgba(139, 148, 158, 0.35)",
}

SEV_RANK: dict[str, int] = {
    "CRITICAL": 4,
    "HIGH": 3,
    "MEDIUM": 2,
    "LOW": 1,
    "INFORMATIONAL": 0,
    "UNKNOWN": 0,
}

RISK_ICON: dict[Optional[str], str] = {
    "CRITICAL": "🟥",
    "HIGH": "🟧",
    "MEDIUM": "🟨",
    "LOW": "🟦",
    "INFORMATIONAL": "⬜",
    "UNKNOWN": "⬜",
    None: "⬜",
}

STATUS_COLORS: dict[str, tuple[str, str, str]] = {
    # status -> (text_color, bg_color, border_color)
    "completed": ("#3fb950", "rgba(63, 185, 80, 0.15)", "rgba(63, 185, 80, 0.35)"),
    "completed_with_errors": ("#d29922", "rgba(210, 153, 34, 0.15)", "rgba(210, 153, 34, 0.35)"),
    "failed": ("#f85149", "rgba(248, 81, 73, 0.15)", "rgba(248, 81, 73, 0.35)"),
    "running": ("#58a6ff", "rgba(88, 166, 255, 0.15)", "rgba(88, 166, 255, 0.35)"),
    "cache": ("#a371f7", "rgba(163, 113, 247, 0.15)", "rgba(163, 113, 247, 0.35)"),
    "default": ("#8b949e", "rgba(139, 148, 158, 0.15)", "rgba(139, 148, 158, 0.35)"),
}


def text_badge(label: Optional[str]) -> str:
    """Plain-text emoji badge safe for widgets that do not render raw HTML (st.expander, st.metric, st.selectbox)."""
    return f"{RISK_ICON.get(label, '⬜')} {label or 'n/a'}"


def severity_pill_html(label: Optional[str]) -> str:
    """HTML pill badge for rendering inside markdown or HTML contexts."""
    key = (label or "UNKNOWN").upper()
    color = SEV_COLORS.get(key, "#8b949e")
    bg = SEV_BG_COLORS.get(key, "rgba(139, 148, 158, 0.15)")
    border = SEV_BORDER_COLORS.get(key, "rgba(139, 148, 158, 0.35)")
    return (
        f'<span style="display:inline-block; font-size:11px; font-weight:600; line-height:1; '
        f'padding:3px 8px; border-radius:12px; color:{color}; background-color:{bg}; '
        f'border:1px solid {border}; vertical-align:middle; letter-spacing:0.3px;">'
        f'{key}</span>'
    )


def status_pill_html(status: str, display_name: Optional[str] = None) -> str:
    """HTML status pill badge (e.g. completed, with errors, from cache)."""
    clean_key = status.lower().replace(" ", "_")
    color, bg, border = STATUS_COLORS.get(clean_key, STATUS_COLORS["default"])
    text = display_name or status.replace("_", " ").title()
    return (
        f'<span style="display:inline-block; font-size:11px; font-weight:600; line-height:1; '
        f'padding:3px 8px; border-radius:12px; color:{color}; background-color:{bg}; '
        f'border:1px solid {border}; vertical-align:middle;">'
        f'{text}</span>'
    )
