"""Findings produced by the Pipeline Agent (container and CI/CD hygiene)."""
from __future__ import annotations

import re
from typing import Any, Optional

from pydantic import BaseModel, Field

SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")
# secret-looking literals; the matched value is NEVER stored or shown (only the rule and the redacted line)
SECRET_LITERAL = re.compile(r"(gsk_[A-Za-z0-9]{20,}|AIza[0-9A-Za-z_\-]{30,}|sk-ant-[A-Za-z0-9_\-]{20,}|sk-[A-Za-z0-9]{32,}|ghp_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{30,}|"
                            r"AKIA[0-9A-Z]{16}|xox[baprs]-[A-Za-z0-9\-]{10,}|-----BEGIN [A-Z ]*PRIVATE KEY-----)")


def redact_line(s: str) -> str:
    return SECRET_LITERAL.sub("[REDACTED]", s)


class PipelineFinding(BaseModel):
    finding_id: str = ""
    kind: str = "pipeline"
    rule_id: str  # e.g. DF003, GHA001
    category: str  # container | ci
    ecosystem: str  # Docker | GitHub Actions | CI (generic)
    title: str
    severity: str  # CRITICAL | HIGH | MEDIUM | LOW | INFO
    file: str
    line: int = 0
    snippet: str = ""
    subject: str = ""  # image reference / action reference / command, used for dedup + memory fingerprint
    why: str = ""
    remediation: str = ""
    evidence_strength: str = "high"  # high = directly visible in the file; medium = heuristic
    references: list[str] = Field(default_factory=list)
    evidence_id: Optional[str] = None
    scan_timestamp: str = ""
    extra: dict[str, Any] = Field(default_factory=dict)
