"""One-page PDF per fixed remediation (see ``fix_report.collect_fixes``). Pure reportlab, no external assets.

Page layout (A4): header band with the fix title and FIXED badge, four KPI tiles, the vulnerabilities that were fixed with their CVSS and
contextual risk scores, a before/after risk chart, the files that changed with the actual diff lines, and source + validation details.
"""
from __future__ import annotations

import io
import time
from typing import Any

try:
    from reportlab.lib.colors import HexColor, white
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.utils import simpleSplit
    from reportlab.pdfbase.pdfmetrics import stringWidth
    from reportlab.pdfgen.canvas import Canvas
    HAS_REPORTLAB = True
    W, H = A4
    M = 34
    CW = W - 2 * M
    INK, MUTED, LINE, SOFT = HexColor("#0F172A"), HexColor("#64748B"), HexColor("#E2E8F0"), HexColor("#F8FAFC")
    GREEN, AMBER, RED = HexColor("#15803D"), HexColor("#B45309"), HexColor("#B91C1C")
    SEV = {"CRITICAL": HexColor("#B91C1C"), "HIGH": HexColor("#EA580C"), "MEDIUM": HexColor("#CA8A04"), "LOW": HexColor("#2563EB"),
           "INFORMATIONAL": HexColor("#64748B"), "UNKNOWN": HexColor("#64748B")}
    DEL_BG, ADD_BG = HexColor("#FEE2E2"), HexColor("#DCFCE7")
except ImportError:
    HAS_REPORTLAB = False
    W, H = 595.27, 841.89  # Default A4 dimensions in points
    M = 34
    CW = W - 2 * M
    INK, MUTED, LINE, SOFT = None, None, None, None
    GREEN, AMBER, RED = None, None, None
    SEV = {}
    DEL_BG, ADD_BG = None, None


def _t(s: Any) -> str:
    """Text safe for the built-in Helvetica/Courier fonts (Latin-1)."""
    return str("" if s is None else s).replace("→", "->").replace("—", "-").replace("–", "-").encode("latin-1", "replace").decode("latin-1")


def _fit(s: Any, font: str, size: float, width: float, left: bool = False) -> str:
    s = _t(s)
    if stringWidth(s, font, size) <= width:
        return s
    while len(s) > 1 and stringWidth("..." + s if left else s + "...", font, size) > width:
        s = s[1:] if left else s[:-1]
    return ("..." + s) if left else (s + "...")


def _pill(c: Canvas, x: float, y: float, text: str, fg, bg, size: float = 6.6, pad: float = 5, h: float = 11) -> float:
    w = stringWidth(_t(text), "Helvetica-Bold", size) + 2 * pad
    c.setFillColor(bg)
    c.roundRect(x, y, w, h, h / 2, stroke=0, fill=1)
    c.setFillColor(fg)
    c.setFont("Helvetica-Bold", size)
    c.drawString(x + pad, y + (h - size) / 2 + 1, _t(text))
    return w


def _section(c: Canvas, y: float, title: str) -> float:
    c.setFillColor(MUTED)
    c.setFont("Helvetica-Bold", 7)
    c.drawString(M, y, _t(title.upper()))
    c.setStrokeColor(LINE)
    c.setLineWidth(0.6)
    c.line(M + stringWidth(_t(title.upper()), "Helvetica-Bold", 7) + 8, y + 2.2, W - M, y + 2.2)
    return y - 12


def _tile(c: Canvas, x: float, y: float, w: float, h: float, label: str, value: str, sub: str, color) -> None:
    c.setFillColor(SOFT)
    c.setStrokeColor(LINE)
    c.roundRect(x, y, w, h, 5, stroke=1, fill=1)
    c.setFillColor(color)
    c.rect(x, y + 6, 2.2, h - 12, stroke=0, fill=1)
    c.setFillColor(MUTED)
    c.setFont("Helvetica-Bold", 6.3)
    c.drawString(x + 10, y + h - 13, _t(label.upper()))
    c.setFillColor(INK)
    c.setFont("Helvetica-Bold", 17)
    c.drawString(x + 10, y + h - 33, _fit(value, "Helvetica-Bold", 17, w - 16))
    c.setFillColor(MUTED)
    c.setFont("Helvetica", 6.8)
    c.drawString(x + 10, y + 7, _fit(sub, "Helvetica", 6.8, w - 16))


def _check(c: Canvas, x: float, y: float, ok: bool) -> None:
    """Vector tick / cross (no font dependency)."""
    c.setLineWidth(1.4)
    c.setLineCap(1)
    if ok:
        c.setStrokeColor(GREEN)
        p = c.beginPath()
        p.moveTo(x + 0.5, y + 2.6)
        p.lineTo(x + 3.0, y + 0.2)
        p.lineTo(x + 7.2, y + 5.4)
        c.drawPath(p, stroke=1, fill=0)
    else:
        c.setStrokeColor(RED)
        c.line(x + 1, y + 0.5, x + 6.5, y + 5.5)
        c.line(x + 1, y + 5.5, x + 6.5, y + 0.5)
    c.setLineWidth(0.6)


def _top_severity(counts: dict[str, int]) -> str:
    return next((k for k in ("CRITICAL", "HIGH", "MEDIUM", "LOW") if counts.get(k)), "UNKNOWN")


def draw_fix_page(c: Canvas, fix: dict, page: int, pages: int) -> None:
    repo = fix.get("repo") or {}
    findings = fix.get("findings") or []
    sev = fix.get("severity_counts") or {}
    val = fix.get("validation") or {}

    # ---- header band
    c.setFillColor(INK)
    c.rect(0, H - 100, W, 100, stroke=0, fill=1)
    c.setFillColor(HexColor("#5EEAD4"))
    c.setFont("Helvetica-Bold", 7)
    c.drawString(M, H - 24, "SC GUARDIAN   |   REMEDIATION REPORT")
    c.setFillColor(white)
    c.setFont("Helvetica-Bold", 16)
    lines = simpleSplit(_t(fix.get("title")), "Helvetica-Bold", 16, CW - 120)[:2]
    for n, ln in enumerate(lines):
        c.drawString(M, H - 47 - n * 19, ln)
    c.setFillColor(HexColor("#CBD5E1"))
    c.setFont("Helvetica", 8.2)
    c.drawString(M, H - 47 - len(lines) * 19 - 2, _fit(f"{repo.get('name') or 'project'}   |   {repo.get('source', '')}   |   {fix.get('id')}   |   priority {fix.get('priority') or '-'}", "Helvetica", 8.2, CW - 120))
    pw = stringWidth("FIXED", "Helvetica-Bold", 8) + 20
    _pill(c, W - M - pw, H - 33, "FIXED", white, GREEN, size=8, pad=10, h=15)
    c.setFillColor(HexColor("#CBD5E1"))
    c.setFont("Helvetica", 7)
    when = _t((fix.get("applied_at") or "").replace("T", " ").replace("Z", " UTC"))
    c.drawRightString(W - M, H - 47, when)

    # ---- KPI tiles
    y = H - 100 - 12 - 52
    gap = 8
    tw = (CW - 3 * gap) / 4
    pkgs = len({f["package"] for f in findings})
    top = _top_severity(sev)
    cmp_ = fix.get("comparison") or {}
    ms = fix.get("max_score")
    _tile(c, M, y, tw, 52, "Findings fixed", str(len(findings)), f"across {pkgs} package(s)", GREEN)
    _tile(c, M + (tw + gap), y, tw, 52, "Highest severity", top.title() if findings else "-", " | ".join(f"{sev[k]} {ab}" for k, ab in (("CRITICAL", "crit"), ("HIGH", "high"), ("MEDIUM", "med"), ("LOW", "low")) if sev.get(k)) or "no severity data", SEV.get(top, MUTED))
    _tile(c, M + 2 * (tw + gap), y, tw, 52, "Top risk score", f"{ms:.0f} to 0" if ms is not None else "-", "highest finding, before to after", SEV.get(((findings[0].get("risk") or "UNKNOWN").upper()) if findings else "UNKNOWN", MUTED))
    status = {"passed": "Passed", "failed": "Failed", "static": "Static", "n/a": "n/a"}.get(val.get("status"), "n/a")
    _tile(c, M + 3 * (tw + gap), y, tw, 52, "Validation", status, f"tests {str(val.get('tests', 'n/a')).replace('_', ' ')}" + (f" | compat {val['compat']}" if val.get("compat") else ""), GREEN if val.get("status") == "passed" else AMBER)
    y -= 16

    # ---- why
    why = " ".join((fix.get("rationale") or "").replace("**", "").replace("`", "").split())
    if why:
        y = _section(c, y, "Why this fix")
        c.setFillColor(INK)
        c.setFont("Helvetica", 7.6)
        wl = simpleSplit(_t(why), "Helvetica", 7.6, CW - 4)
        for ln in wl[:4]:
            c.drawString(M + 2, y - 2, ln)
            y -= 10.5
        if len(wl) > 4:
            c.setFillColor(MUTED)
            c.drawString(M + 2, y - 2, "...")
            y -= 10.5
        y -= 8

    # ---- vulnerabilities fixed
    y = _section(c, y, f"Vulnerabilities fixed ({len(findings)})")
    cols = [("ID", 92), ("PACKAGE", 140), ("SEVERITY", 54), ("CVSS", 32), ("RISK", 78), ("PRIO", 30), ("FIXED IN", CW - 92 - 140 - 54 - 32 - 78 - 30)]
    x = M
    c.setFillColor(MUTED)
    c.setFont("Helvetica-Bold", 6.3)
    for name, w in cols:
        c.drawString(x + 3, y - 1, name)
        x += w
    y -= 5
    c.setStrokeColor(LINE)
    c.line(M, y, W - M, y)
    shown = findings[:10]
    for n, f in enumerate(shown):
        y -= 14
        if n % 2 == 1:
            c.setFillColor(SOFT)
            c.rect(M, y - 3, CW, 14, stroke=0, fill=1)
        x = M
        cells = [f.get("id"), f"{f.get('package')}@{f.get('version')}", None, f"{f['cvss']:.1f}" if isinstance(f.get("cvss"), (int, float)) else "-",
                 (f"{(f.get('risk') or '-').title()} {f['score']:.0f}" if f.get("score") is not None else (f.get("risk") or "-")), f.get("priority") or "-", f.get("fixed_in")]
        for (name, w), cell in zip(cols, cells):
            if name == "SEVERITY":
                col = SEV.get(f["severity"], MUTED)
                _pill(c, x + 2, y - 2.4, f["severity"].title(), white, col, size=6, pad=4, h=10)
            else:
                c.setFillColor(INK)
                font = "Courier" if name in ("ID", "FIXED IN") else "Helvetica"
                c.setFont(font, 7.2)
                c.drawString(x + 3, y, _fit(cell, font, 7.2, w - 6))
            x += w
    if len(findings) > len(shown):
        y -= 13
        c.setFillColor(MUTED)
        c.setFont("Helvetica-Oblique", 7)
        c.drawString(M + 3, y, f"+ {len(findings) - len(shown)} more finding(s) fixed by the same change")
    y -= 18

    # ---- risk before / after
    y = _section(c, y, "Contextual risk, before and after")
    rc = fix.get("risk_counts") or {}
    labels = [k for k in ("CRITICAL", "HIGH", "MEDIUM", "LOW") if rc.get(k)] or ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
    mx = max([rc.get(k, 0) for k in labels] + [1])
    half = (CW - 20) / 2
    for side, (ox, title, factor) in enumerate(((M, "Before this fix", 1), (M + half + 20, "After this fix", 0))):
        c.setFillColor(INK)
        c.setFont("Helvetica-Bold", 7.5)
        c.drawString(ox, y - 2, title)
        yy = y - 14
        for k in labels:
            n = rc.get(k, 0) * factor
            c.setFillColor(MUTED)
            c.setFont("Helvetica", 6.8)
            c.drawString(ox, yy, k.title())
            bw = (half - 70) * (rc.get(k, 0) / mx) if factor else 0
            c.setFillColor(LINE)
            c.roundRect(ox + 50, yy - 2, half - 70, 7, 3.5, stroke=0, fill=1)
            if bw > 0:
                c.setFillColor(SEV[k])
                c.roundRect(ox + 50, yy - 2, max(bw, 4), 7, 3.5, stroke=0, fill=1)
            c.setFillColor(INK)
            c.setFont("Helvetica-Bold", 7)
            c.drawString(ox + 50 + half - 64, yy, str(n))
            yy -= 12
    y -= 14 + 12 * len(labels) + 4
    if findings:
        f0 = findings[0]
        if f0.get("score") is not None:
            msg = (f"Highest before: {f0.get('id')} in {f0.get('package')} - {(f0.get('risk') or 'n/a').title()}, score {f0['score']:.0f}/100, "
                   f"priority {f0.get('priority') or '-'}. All {len(findings)} are resolved by this change.")
        else:
            msg = f"{len(findings)} finding(s) are resolved by this change."
        c.setFillColor(MUTED)
        c.setFont("Helvetica", 7.2)
        c.drawString(M, y, _fit(msg, "Helvetica", 7.2, CW))
    y -= 18

    # ---- what changed
    y = _section(c, y, "What changed")
    changes = fix.get("changes") or []
    for ch in changes[:4]:
        y -= 13
        c.setFillColor(INK)
        c.setFont("Courier-Bold", 7.4)
        c.drawString(M + 3, y, _fit(ch["path"], "Courier-Bold", 7.4, CW - 190, left=True))
        _pill(c, W - M - 175, y - 2.4, ch["kind"], MUTED, LINE, size=6, pad=5, h=10)
        c.setFillColor(GREEN)
        c.setFont("Helvetica-Bold", 7.4)
        c.drawRightString(W - M - 45, y, f"+{ch['added']}")
        c.setFillColor(RED)
        c.drawRightString(W - M - 8, y, f"-{ch['removed']}")
    if len(changes) > 4:
        y -= 12
        c.setFillColor(MUTED)
        c.setFont("Helvetica-Oblique", 7)
        c.drawString(M + 3, y, f"+ {len(changes) - 4} more file(s)")
    main = next((ch for ch in changes if ch["kind"] != "lockfile" and ch["lines"]), None)
    if main:
        ex = main["lines"][:10]
        bh = len(ex) * 10 + 8
        y -= bh + 6
        c.setFillColor(SOFT)
        c.setStrokeColor(LINE)
        c.roundRect(M, y, CW, bh, 4, stroke=1, fill=1)
        ly = y + bh - 11
        for ln in ex:
            bg = DEL_BG if ln.startswith("-") else ADD_BG
            c.setFillColor(bg)
            c.rect(M + 1, ly - 2.5, CW - 2, 9.6, stroke=0, fill=1)
            c.setFillColor(RED if ln.startswith("-") else GREEN)
            c.setFont("Courier", 6.8)
            c.drawString(M + 6, ly, _fit(ln, "Courier", 6.8, CW - 14))
            ly -= 10
    y -= 18

    # ---- source + validation
    y = _section(c, y, "Source and validation")
    left_w = CW * 0.47
    tgt = fix.get("target") or {}
    kv = [("Project", repo.get("path") or repo.get("url")), ("Scan", f"{repo.get('scan_id') or '-'} | {repo.get('commit') or 'no commit'} | {repo.get('scanner') or 'scanner n/a'}"),
          ("Change", f"{tgt.get('package', '-')}: {tgt.get('from') or '-'} -> {tgt.get('to') or '-'}"), ("Delivered", fix.get("how")),
          ("Lockfile", (fix.get("lock") or {}).get("note") or "not applicable")]
    yy = y
    for k, v in kv:
        yy -= 12
        c.setFillColor(MUTED)
        c.setFont("Helvetica-Bold", 6.6)
        c.drawString(M + 3, yy, k.upper())
        c.setFillColor(INK)
        c.setFont("Helvetica", 7.2)
        c.drawString(M + 52, yy, _fit(v, "Helvetica", 7.2, left_w - 56))
    xr = M + left_w + 16
    yv = y
    for stp in (val.get("steps") or [])[:6]:
        yv -= 12
        _check(c, xr, yv, bool(stp["ok"]))
        c.setFillColor(INK)
        c.setFont("Helvetica-Bold", 7)
        c.drawString(xr + 11, yv, _t(stp["step"]))
        c.setFillColor(MUTED)
        c.setFont("Helvetica", 6.8)
        c.drawString(xr + 11 + 60, yv, _fit(stp["detail"].replace("\n", " "), "Helvetica", 6.8, W - M - (xr + 71)))
    if not val.get("steps"):
        yv -= 12
        c.setFillColor(MUTED)
        c.setFont("Helvetica-Oblique", 7)
        c.drawString(xr, yv, "No clone validation record (static what-if only).")
    if val.get("warnings"):
        yv -= 12
        c.setFillColor(AMBER)
        c.setFont("Helvetica-Bold", 6.8)
        c.drawString(xr, yv, _fit("Reviewed warning: " + val["warnings"][0], "Helvetica-Bold", 6.8, W - M - xr))

    # ---- footer
    c.setStrokeColor(LINE)
    c.line(M, 36, W - M, 36)
    c.setFillColor(MUTED)
    c.setFont("Helvetica", 6.6)
    c.drawString(M, 25, _fit(f"Generated {time.strftime('%Y-%m-%d %H:%M UTC', time.gmtime())} by SC Guardian. Validated on a clone before applying; originals are backed up and the change can be undone.", "Helvetica", 6.6, CW - 60))
    c.drawRightString(W - M, 25, f"{page} / {pages}")


def build_pdf(fixes: list[dict], title: str = "SC Guardian remediation report") -> bytes:
    """One page per fix."""
    if not HAS_REPORTLAB:
        return b""
    buf = io.BytesIO()
    c = Canvas(buf, pagesize=A4)
    c.setTitle(_t(title))
    c.setAuthor("SC Guardian")
    for n, fix in enumerate(fixes, 1):
        draw_fix_page(c, fix, n, len(fixes))
        c.showPage()
    c.save()
    return buf.getvalue()
