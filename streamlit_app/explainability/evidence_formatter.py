"""Human-readable formatting of evidence bundles and risk factors."""
from __future__ import annotations


def fmt_factors(risk: dict) -> list[str]:
    out = []
    for f in risk.get("factors", []):
        sign = f"+{f['points']}" if f["points"] > 0 else str(f["points"])
        out.append(f"{f['factor']} ({sign}): {f['detail']}")
    return out


def fmt_path(path: list[str]) -> str:
    return " -> ".join(path)


def fmt_exposures(exposures: list[dict]) -> list[str]:
    lines = []
    for e in exposures:
        rel = {"direct": "a DIRECT dependency", "direct_inferred": "a direct dependency (inferred, no recorded parent)",
               "transitive": "a TRANSITIVE dependency"}.get(e["relationship"], e["relationship"])
        line = f"Relative to '{e['root']}' it is {rel}"
        if e.get("depth"):
            line += f" (depth {e['depth']})"
        if e.get("immediate_parents"):
            line += f"; immediate parent: {', '.join(e['immediate_parents'])}"
        lines.append(line + ".")
        for p in e.get("paths", [])[:3]:
            lines.append("    path: " + fmt_path(p))
    return lines
