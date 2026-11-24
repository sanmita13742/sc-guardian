"""Pure before/after comparison of two scan results. No I/O, so it is fully unit-testable with fixture dicts.

Findings are matched on a natural key (ecosystem, service, package, advisory) instead of ``finding_id``, because ids are
assigned per scan and are not guaranteed to be stable across two scans of different trees.
"""
from __future__ import annotations

from collections import Counter
from typing import Any, Optional

from validation.contracts import ApprovedRemediation, Comparison, ComponentChange, FindingRef

SEVERITY_ORDER = ["UNKNOWN", "LOW", "MEDIUM", "HIGH", "CRITICAL"]


def _norm(eco: Optional[str], name: str) -> str:
    n = (name or "").strip()
    return n.lower().replace("_", "-") if eco == "PyPI" else n


def _svc(v: Optional[str]) -> str:
    return v if v not in (None, "") else "."


def finding_key(f: dict[str, Any]) -> str:
    eco = f.get("ecosystem") or ""
    return "|".join([eco, _svc(f.get("service_dir")), _norm(eco, f.get("package_name") or ""), f.get("primary_id") or (f.get("vulnerability_ids") or [""])[0]])


def component_key(c: dict[str, Any]) -> str:
    eco = c.get("ecosystem") or ""
    return "|".join([eco, _svc(c.get("service_dir")), _norm(eco, c.get("name") or "")])


def severity_rank(s: Optional[str]) -> int:
    return SEVERITY_ORDER.index(s) if s in SEVERITY_ORDER else 0


def _risk_index(result: dict[str, Any]) -> dict[str, dict]:
    return {a.get("finding_id"): a for a in result.get("risk_assessments") or [] if a.get("finding_id")}


def _ref(f: dict[str, Any], risks: dict[str, dict]) -> FindingRef:
    r = risks.get(f.get("finding_id")) or {}
    return FindingRef(key=finding_key(f), advisory=f.get("primary_id") or "", package=f.get("package_name") or "", version=f.get("installed_version"),
                      service=_svc(f.get("service_dir")), severity=f.get("severity"), risk_label=r.get("label"), priority=r.get("priority"))


def _versions(result: dict[str, Any]) -> dict[str, set[str]]:
    out: dict[str, set[str]] = {}
    for c in result.get("components") or []:
        if c.get("is_self"):
            continue
        out.setdefault(component_key(c), set()).add(c.get("version") or "")
    return out


def _suspicious_count(result: dict[str, Any]) -> int:
    return len(result.get("typosquatting") or []) + len(result.get("lockfile_changes") or []) + len((result.get("package_risk") or {}).get("findings") or [])


def compare(before: dict[str, Any], after: dict[str, Any], rem: ApprovedRemediation) -> Comparison:
    rb, ra = _risk_index(before), _risk_index(after)
    b_vulns, a_vulns = before.get("vulnerabilities") or [], after.get("vulnerabilities") or []
    # The same advisory can hit several installed copies of a package (e.g. underscore 1.8.3 nested + 1.9.1 top level), so findings are
    # grouped by the version-less key and matched copy by copy: same version first, then any version (an upgraded copy that is still
    # affected by the same advisory is "remaining", not "fixed" + "new").
    def by_key(vs: list[dict]) -> dict[str, list[dict]]:
        out: dict[str, list[dict]] = {}
        for f in vs:
            out.setdefault(finding_key(f), []).append(f)
        return out

    def match(b: list[dict], a: list[dict]) -> tuple[list[tuple[dict, dict]], list[dict], list[dict]]:
        b, a, pairs = list(b), list(a), []
        for exact in (True, False):
            for f in list(b):
                g = next((x for x in a if not exact or x.get("installed_version") == f.get("installed_version")), None)
                if g is not None:
                    pairs.append((f, g))
                    b.remove(f)
                    a.remove(g)
        return pairs, b, a  # matched, only-before (resolved), only-after (new)

    bk, ak = by_key(b_vulns), by_key(a_vulns)
    tids = set(rem.finding_ids)
    cmp = Comparison(before_scan_id=(before.get("repo") or {}).get("scan_id"), after_scan_id=(after.get("repo") or {}).get("scan_id"))
    for k in sorted(set(bk) | set(ak)):
        bs = bk.get(k, [])
        # targeted copies are matched first so a remaining advisory is attributed to them, not to an untargeted copy
        bs = sorted(bs, key=lambda f: f.get("finding_id") not in tids)
        pairs, gone, new = match(bs, ak.get(k, []))
        for f, _ in pairs:
            if f.get("finding_id") in tids:
                cmp.targeted_remaining.append(_ref(f, rb))
        for f in gone:
            (cmp.targeted_fixed if f.get("finding_id") in tids else cmp.other_resolved).append(_ref(f, rb))
        cmp.newly_introduced += [_ref(f, ra) for f in new]

    vb, va = _versions(before), _versions(after)
    for k in sorted(set(vb) | set(va)):
        b, a = sorted(vb.get(k, set())), sorted(va.get(k, set()))
        if not b:
            cmp.components_added.append(ComponentChange(key=k, after=a))
        elif not a:
            cmp.components_removed.append(ComponentChange(key=k, before=b))
        elif b != a:
            cmp.components_changed.append(ComponentChange(key=k, before=b, after=a))

    if rem.changes:
        missing = []
        for ch in rem.changes:
            k = "|".join([rem.ecosystem, _svc(rem.service), _norm(rem.ecosystem, ch.package)])
            if ch.to_version and ch.to_version not in va.get(k, set()):
                missing.append(f"{ch.package}=={ch.to_version}")
        cmp.target_versions_present = not missing
        cmp.missing_target_versions = missing

    cmp.risk_before = dict(Counter(a.get("label") or "UNKNOWN" for a in before.get("risk_assessments") or []))
    cmp.risk_after = dict(Counter(a.get("label") or "UNKNOWN" for a in after.get("risk_assessments") or []))
    cmp.suspicious_before, cmp.suspicious_after = _suspicious_count(before), _suspicious_count(after)

    if rem.predicted:
        p = rem.predicted
        cmp.predicted_vs_observed = {
            "predicted_verdict": p.get("verdict"),
            "predicted_fixed": len(p.get("fixed") or []), "observed_fixed": len(cmp.targeted_fixed),
            "predicted_remaining": len(p.get("remaining") or []), "observed_remaining": len(cmp.targeted_remaining),
            "predicted_new": len(p.get("newly_introduced") or []), "observed_new": len(cmp.newly_introduced),
        }
    return cmp
