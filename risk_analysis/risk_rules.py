"""Configurable, documented risk rules (rule set version is recorded on every assessment).

Points are additive; the label is derived from the total via THRESHOLDS. CVSS severity is displayed separately from
the project-specific risk label. See docs/RISK_SCORING.md for the rationale.
"""
from __future__ import annotations

import copy
import json
from pathlib import Path

RULES_VERSION = "1.0"

DEFAULT_RULES: dict = {
    "thresholds": {"CRITICAL": 70, "HIGH": 45, "MEDIUM": 25, "LOW": 10},  # score >= threshold -> label
    "vulnerability": {
        "severity_points": {"CRITICAL": 55, "HIGH": 40, "MEDIUM": 22, "LOW": 8, "UNAVAILABLE": 12},
        "kev": 30,
        "kev_ransomware": 5,
        "exposure": {"direct": 8, "direct_inferred": 6, "transitive": 0, "unknown": 0},
        "multiple_roots": 5,
        "no_fix_recorded": 5,
        "dev_dependency": -10,
        "unconfirmed_applicability_cap": "MEDIUM",
        "correlated_lockfile_change": 5,
    },
    "typosquatting": {
        "strength_points": {"high": 45, "medium": 30, "low": 15},
        "exposure": {"direct": 5, "direct_inferred": 4, "transitive": 0, "unknown": 0},
        "correlated_lockfile_addition": 10,
        "correlated_vulnerability": 5,
        "cap": "HIGH",  # similarity is a signal, never proof
    },
    "lockfile_change": {
        "classification_points": {"potentially_suspicious": 30, "unexplained_change": 12, "normal_update": 0, "insufficient_baseline": 0},
        "strength_bonus": {"high": 20, "medium": 8, "low": 0},
        "correlated_vulnerability": 10,
        "correlated_typosquat": 10,
        "cap": "HIGH",  # a lockfile change never proves compromise
    },
}


def load_rules(path: str | Path | None = None) -> dict:
    rules = copy.deepcopy(DEFAULT_RULES)
    if path and Path(path).exists():
        override = json.loads(Path(path).read_text(encoding="utf-8"))

        def merge(a, b):
            for k, v in b.items():
                if isinstance(v, dict) and isinstance(a.get(k), dict):
                    merge(a[k], v)
                else:
                    a[k] = v
        merge(rules, override)
    return rules
