"""Ground-truth checks for explanation text: every identifier, number and risk label must come from the evidence."""
from __future__ import annotations

import re

ID_RE = re.compile(r"\b(CVE-\d{4}-\d{4,}|GHSA-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}|PYSEC-\d+-\d+|GO-\d+-\d+|RUSTSEC-\d+-\d+|OSV-\d+-\d+)\b", re.I)
NUM_RE = re.compile(r"(?<![\w.])(?:v)?\d+\.\d+(?:\.\d+)*(?:[-+][0-9A-Za-z.]+)?(?![\w])")
LABEL_RE = re.compile(r"\b(CRITICAL|HIGH|MEDIUM|LOW|INFORMATIONAL)\b")
CERTAINTY = [
    (re.compile(r"\b(actively|currently)\s+exploited|exploited in the wild", re.I), "kev", "claims active exploitation without a KEV entry"),
    (re.compile(r"\b(is|are|was|confirmed|definitely|certainly)\s+(a\s+)?(malicious|compromised|backdoored)\b", re.I), None, "asserts maliciousness/compromise as fact"),
    (re.compile(r"\bremote code execution|\bRCE\b|arbitrary code execution", re.I), "text:remote code execution|arbitrary code execution|rce", "claims code-execution impact not present in the advisory evidence"),
    (re.compile(r"\b(is|are) (trivially |easily )?exploitable\b|will be exploited", re.I), None, "claims exploitability without evidence"),
    (re.compile(r"\bunreachable\b|\bnot reachable\b|\bcannot be reached\b", re.I), None, "claims unreachability (reachability is unknown)"),
]


def build_allowed_text(bundle_corpus: str, risk: dict) -> str:
    extra = [str(risk.get("score", "")), risk.get("label", ""), str(risk.get("cvss_severity") or "")]
    for f in risk.get("factors", []):
        extra += [f["factor"], f["detail"], str(f["points"])]
    extra += risk.get("unknowns", []) + [str(v) for v in risk.get("thresholds", {}).values()]
    return (bundle_corpus + "\n" + "\n".join(extra)).lower()


def validate_text(text: str, bundle: dict, risk: dict) -> list[str]:
    """Return a list of problems (empty list = grounded)."""
    problems: list[str] = []
    allowed = build_allowed_text(bundle.get("corpus", ""), risk)
    for m in ID_RE.findall(text):
        if m.lower() not in allowed:
            problems.append(f"identifier '{m}' is not in the evidence")
    for m in NUM_RE.findall(text):
        tok = m.lstrip("v").lower()
        if tok not in allowed:
            problems.append(f"number/version '{m}' is not in the evidence")
    allowed_labels = {risk.get("label")}
    if risk.get("cvss_severity"):
        allowed_labels.add(risk["cvss_severity"])
    for fct in risk.get("factors", []):
        allowed_labels.update(LABEL_RE.findall(fct["detail"]))
    allowed_labels |= {"INFORMATIONAL"} if risk.get("label") == "INFORMATIONAL" else set()
    for lab in set(LABEL_RE.findall(text)):
        if lab not in allowed_labels and lab not in bundle.get("corpus", "").upper():
            problems.append(f"risk/severity label '{lab}' contradicts the deterministic assessment")
    kev = "true" in str(bundle.get("advisory", {}).get("kev", "")).lower()
    for rx, need, msg in CERTAINTY:
        if rx.search(text):
            if need == "kev" and kev:
                continue
            if need and need.startswith("text:") and re.search(need[5:], bundle.get("corpus", ""), re.I):
                continue
            problems.append(msg)
    return problems
