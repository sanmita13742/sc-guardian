"""Prompt for the optional LLM explanation writer. The model only rephrases supplied evidence."""
from __future__ import annotations

SECTIONS = ["what", "why", "package", "how_entered", "direct_transitive", "impact", "evidence", "remediation", "unknown"]

SYSTEM = """You write short, precise security explanations for a software-supply-chain scanner.
You are given an EVIDENCE bundle and a deterministic RISK assessment. Rules:
- Use ONLY facts present in the evidence. Never invent CVE/GHSA ids, CVSS numbers, versions, package names or dependency paths.
- Never change or contradict the risk label or the factors. Do not claim exploitability, active exploitation, malicious intent,
  or unreachability unless the evidence explicitly says so. Reachability is unknown unless stated.
- Similarity or a lockfile change is a signal, not proof of malice.
- If something is unknown, say it is unknown.
Return ONLY a JSON object with string values for exactly these keys: what, why, package, how_entered, direct_transitive, impact, evidence, remediation, unknown."""


def build_user_prompt(evidence_json: str, risk_json: str) -> str:
    return (f"EVIDENCE:\n{evidence_json}\n\nRISK (deterministic, authoritative):\n{risk_json}\n\n"
            "Write the explanation sections now as the JSON object described.")
