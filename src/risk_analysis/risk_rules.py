"""Configurable, documented risk rules (rule set version is recorded on every assessment).

Contextual Vulnerability Risk Scoring v2.0 linear model:
    R = 0.15*C + 0.20*A + 0.35*P + 0.30*I
Points are normalized 0-100; threat intelligence (CISA KEV, EPSS) is decoupled as an independent priority escalation layer.
"""
from __future__ import annotations

import copy
import json
from pathlib import Path

RULES_VERSION = "2.2-contextual"

DEFAULT_RULES: dict = {
    "thresholds": {"CRITICAL": 70, "HIGH": 45, "MEDIUM": 25, "LOW": 10},  # score >= threshold -> label
    "contextual_v2": {
        "weights": {"C": 0.15, "A": 0.20, "P": 0.35, "I": 0.30},
        "thresholds": {"CRITICAL": 70, "HIGH": 45, "MEDIUM": 25, "LOW": 10},
        "impact_subfactor_weights": {"F": 0.25, "S": 0.25, "B": 0.20, "D": 0.20, "X": 0.10},
    },
    "vulnerability": {
        "severity_points": {"CRITICAL": 55, "HIGH": 40, "MEDIUM": 22, "LOW": 8, "UNAVAILABLE": 12},
        "kev": 30,
        "kev_ransomware": 5,
        "exposure": {"direct": 8, "direct_inferred": 6, "transitive": 0, "unknown": 0},
        "multiple_roots": 5,
        "no_fix_recorded": 5,
        "dev_dependency": -10,
        "unconfirmed_applicability_cap": "MEDIUM",
        "unreachable_cap": "MEDIUM",
        "test_only_cap": "MEDIUM",
        "correlated_lockfile_change": 5,
        "epss": [[0.5, 20], [0.1, 10], [0.01, 3]],
        "reachability": {
            "used_by_app_heavy": 35,
            "used_by_app_moderate": 20,
            "used_by_app_single": 12,
            "used_by_app": 20,
            "reachable_via_dependency_heavy": 18,
            "reachable_via_dependency": 8,
            "used_in_tests_only": -10,
            "not_imported": -25,
            "unknown": 0,
        },
    },
    "pipeline": {
        "severity_points": {"CRITICAL": 75, "HIGH": 50, "MEDIUM": 28, "LOW": 12, "INFO": 4},
        "heuristic_penalty": -8,
        "third_party_unpinned_action": 5,
    },
    "typosquatting": {
        "strength_points": {"high": 45, "medium": 30, "low": 15},
        "exposure": {"direct": 5, "direct_inferred": 4, "transitive": 0, "unknown": 0},
        "correlated_lockfile_addition": 10,
        "correlated_vulnerability": 5,
        "cap": "HIGH",
    },
    "lockfile_change": {
        "classification_points": {"potentially_suspicious": 30, "unexplained_change": 12, "normal_update": 0, "insufficient_baseline": 0},
        "strength_bonus": {"high": 20, "medium": 8, "low": 0},
        "correlated_vulnerability": 10,
        "correlated_typosquat": 10,
        "cap": "HIGH",
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
