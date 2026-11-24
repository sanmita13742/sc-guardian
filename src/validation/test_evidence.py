"""How many tests actually ran? Parsed from the test log tail, framework by framework.

An exit code of 0 is not evidence that the change was tested: NodeGoat's ``npm test`` exits 0 after "No files to check...OK".
``verified_fixed`` therefore requires at least one executed test. Unknown formats return ``executed=None`` (unconfirmed), which the
verdict treats like "not tested": the evidence must show tests ran, it is never assumed.
"""
from __future__ import annotations

import re
from typing import Optional

# (framework, pattern, group names in order) - counts are summed per framework, the framework with most executed tests wins
_COUNTS: list[tuple[str, re.Pattern, tuple[str, ...]]] = [
    ("mocha", re.compile(r"^\s*(\d+) passing\b", re.M), ("passed",)),
    ("mocha", re.compile(r"^\s*(\d+) failing\b", re.M), ("failed",)),
    ("jest", re.compile(r"^Tests:\s+(?:(\d+) failed, )?(?:\d+ skipped, )?(?:\d+ todo, )?(\d+) passed, \d+ total", re.M), ("failed", "passed")),
    ("pytest", re.compile(r"^=*\s*((?:\d+ (?:passed|failed|errors?|skipped|deselected|xfailed|xpassed|warnings?)(?:, )?)+) in [\d.]+s", re.M), ()),
    ("cargo", re.compile(r"test result: \w+\. (\d+) passed; (\d+) failed", re.M), ("passed", "failed")),
    ("maven", re.compile(r"Tests run: (\d+), Failures: (\d+), Errors: (\d+)", re.M), ("run", "failed", "errors")),
    ("tap", re.compile(r"^# pass\s+(\d+)", re.M), ("passed",)),
    ("tap", re.compile(r"^# fail\s+(\d+)", re.M), ("failed",)),
    ("go", re.compile(r"^(?:ok|FAIL)\s+\S+\s+[\d.]+s", re.M), ()),  # one match = one tested package
]
_ZERO = [re.compile(p, re.I | re.M) for p in (
    r"No files to check", r"^\s*0 passing\b", r"no tests ran", r"collected 0 items", r"No tests found", r"\[no test files\]",
    r"running 0 tests", r"Tests run: 0,", r"No test files found", r"Error: no test specified", r"^# tests\s+0\b")]


def summarize(log: str) -> dict:
    """{framework, executed, passed, failed, zero_marker}. executed: int >= 0, or None when the log shows no recognisable summary."""
    log = log or ""
    per: dict[str, dict[str, int]] = {}
    for fw, rx, names in _COUNTS:
        for m in rx.finditer(log):
            d = per.setdefault(fw, {"passed": 0, "failed": 0, "executed": 0})
            if fw == "pytest":
                s = m.group(1)
                n = {k: sum(int(x) for x in re.findall(rf"(\d+) {k}", s)) for k in ("passed", "failed", "error")}
                d["passed"] += n["passed"]
                d["failed"] += n["failed"] + n["error"]
                d["executed"] += n["passed"] + n["failed"] + n["error"]
                continue
            if fw == "go":
                d["executed"] += 1
                d["failed"] += m.group(0).startswith("FAIL")
                d["passed"] += m.group(0).startswith("ok")
                continue
            vals = dict(zip(names, (int(g) if g else 0 for g in m.groups())))
            if fw == "maven":
                d["executed"] += vals["run"]
                d["failed"] += vals["failed"] + vals["errors"]
                d["passed"] += max(vals["run"] - vals["failed"] - vals["errors"], 0)
            else:
                d["passed"] += vals.get("passed", 0)
                d["failed"] += vals.get("failed", 0)
                d["executed"] += vals.get("passed", 0) + vals.get("failed", 0)
    zero = next((z.pattern for z in _ZERO if z.search(log)), None)
    best: Optional[tuple[str, dict]] = max(per.items(), key=lambda kv: kv[1]["executed"], default=None)
    if best and best[1]["executed"] > 0:
        return {"framework": best[0], **best[1], "zero_marker": zero}
    if zero or best:
        return {"framework": best[0] if best else None, "executed": 0, "passed": 0, "failed": 0, "zero_marker": zero}
    return {"framework": None, "executed": None, "passed": None, "failed": None, "zero_marker": None}
