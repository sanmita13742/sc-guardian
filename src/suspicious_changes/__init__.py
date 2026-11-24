"""Suspicious changes detection and evidence correlation package."""
from suspicious_changes.change_correlation import (
    ChangeCorrelator,
    CompositeFinding,
    correlate_suspicious_changes,
)

__all__ = [
    "ChangeCorrelator",
    "CompositeFinding",
    "correlate_suspicious_changes",
]
