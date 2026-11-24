"""Evidence-grounded explanations. Deterministic templates are always available; an LLM may rephrase them only if every
claim validates against the evidence (otherwise the offending section falls back to the template)."""
from __future__ import annotations

import json
from typing import Callable, Optional

from explainability.evidence_formatter import fmt_exposures, fmt_factors, fmt_path
from explainability.explanation_validator import validate_text
from explainability.prompt_templates import SECTIONS, SYSTEM, build_user_prompt
from risk_analysis.evidence_normalizer import compact_for_llm


def _vuln_template(b: dict, risk: dict, f: dict) -> dict[str, str]:
    adv, comp, dep = b["advisory"], b["component"], b["dependency"]
    ids = ", ".join(adv["ids"])
    sev = adv["severity"] or "unavailable"
    cvss = f"CVSS {adv['cvss_score']}" + (f" ({adv['cvss_vector']})" if adv.get("cvss_vector") else "") if adv.get("cvss_score") is not None else "no CVSS score available"
    status = {"confirmed_affected": f"The installed version {comp['version']} falls inside the affected range",
              "unknown": f"The advisory was returned for this package but its affected range could not be validated locally for {comp['version']}",
              }.get(adv["affected_status"], adv["affected_status"])
    ranges = f" ({'; '.join(adv['affected_ranges'])})" if adv.get("affected_ranges") else ""
    reach = f.get("reachability") or {}
    rst = reach.get("status")
    app_files = reach.get("app_files", 0)
    density = reach.get("import_density") or reach.get("influence_tier")
    if rst == "used_by_app":
        reach_txt = f" Application imports {comp['name']} across {app_files} file(s)" + (", indicating heavy codebase influence and broad runtime exposure." if (density == "heavy" or app_files >= 5) else ".")
    elif rst == "reachable_via_dependency":
        reach_txt = f" Reached via dependency {', '.join(reach.get('via') or [reach.get('package')])}, which is imported by application source."
    elif rst == "used_in_tests_only":
        reach_txt = f" Imported only by test code ({reach.get('test_files', 0)} files); does not run in the production execution path."
    elif rst == "not_imported":
        reach_txt = " No static import found in application source; practical risk is deprioritized."
    else:
        reach_txt = " Whether the vulnerable code is reachable in this application has not been assessed."

    s = {
        "what": f"{adv['primary_id']} ({ids}) affects {comp['name']} {comp['version']}." + (f" Advisory summary: {adv['summary']}" if adv.get("summary") else ""),
        "why": f"{status}{ranges}. Version matching used {comp['ecosystem']} version semantics. Source(s): {', '.join(adv['sources'])}.",
        "package": f"{comp['name']} {comp['version']} ({comp['ecosystem']}" + (f", {comp['purl']}" if comp.get('purl') else "") + f") in service '{comp.get('service_dir')}'; SBOM component reference: {comp['bom_ref']}.",
        "how_entered": ("\n".join("path: " + fmt_path(p) for e in dep["exposures"] for p in e["paths"][:3]) or "No dependency path from a service root is recorded in the graph."),
        "direct_transitive": ("\n".join(fmt_exposures(dep["exposures"])) or "Direct/transitive status is unknown because the component is not reachable from any root."),
        "impact": f"Severity: {sev}; {cvss}." + (" Listed in the CISA KEV catalog (known exploited)." if adv.get("kev") else " Not listed in the CISA KEV catalog.") + reach_txt,
        "evidence": f"Advisory source(s): {', '.join(adv['sources'])}; retrieved {adv.get('retrieved_at')}. References: " + (", ".join(adv["urls"][:3]) or "none recorded") + ".",
        "remediation": f["remediation"],
        "unknown": " ".join(risk.get("unknowns", [])) or "No additional unknowns recorded.",
    }
    return s


def _typo_template(b: dict, risk: dict, f: dict) -> dict[str, str]:
    d, comp = b["detection"], b["component"]
    reg = d.get("registry") or {}
    reg_txt = "; ".join(d["evidence"][1:]) if len(d["evidence"]) > 1 else "no registry corroboration"
    return {
        "what": f"The package '{d['package']}' has a name very similar to the well-known {d['ecosystem']} package '{d['similar_to']}' "
                f"(similarity {d['similarity_score']}%, edit distance {d['edit_distance']}).",
        "why": f"Techniques: {', '.join(d['techniques'])}. Evidence strength: {d['evidence_strength']}. Reference set: {d['reference_source']}.",
        "package": f"{d['package']} versions {', '.join(comp['versions']) or 'unknown'} in service(s) {', '.join(comp['services']) or 'unknown'}.",
        "how_entered": f"Dependency type: {b['dependency']['type']}." + (f" Roots: {', '.join(b['dependency']['roots'])}." if b['dependency'].get('roots') else ""),
        "direct_transitive": f"The package is classified as {b['dependency']['type']} in the dependency graph.",
        "impact": "If this is a typosquat, it could execute attacker-controlled code at install or run time; this has NOT been established. "
                  "Name similarity is a signal, not proof of malicious intent.",
        "evidence": f"Registry/similarity evidence: {reg_txt}.",
        "remediation": f"Verify that '{d['package']}' is the intended dependency (compare with '{d['similar_to']}'), check its publisher and history on the registry, "
                       "and replace it if it was added by mistake.",
        "unknown": " ".join(risk.get("unknowns", [])),
    }


def _lock_template(b: dict, risk: dict, f: dict) -> dict[str, str]:
    c, g = b["change"], b["git"]
    prev, new = c.get("previous") or {}, c.get("new") or {}
    return {
        "what": f"Lockfile {c['file']} changed for '{c['package']}' ({c['change_type'].replace('_', ' ')})"
                + (f": {prev.get('version')} -> {new.get('version')}" if prev.get("version") or new.get("version") else "") + ".",
        "why": " ".join(c["reasons"]) or "See classification.",
        "package": f"{c['package']} ({c['ecosystem']}) in {c['file']}.",
        "how_entered": f"Commit {g['commit']} compared with baseline {g['baseline']} ({g['baseline_mode']})"
                       + (f"; subject: {g['commit_info'].get('subject')}; author: {g['commit_info'].get('author')}; date: {g['commit_info'].get('date')}" if g.get("commit_info") else "") + ".",
        "direct_transitive": f"Manifest changed in the same commit: {'yes (' + ', '.join(c['manifest_files_changed']) + ')' if c['manifest_changed'] else 'no'}.",
        "impact": f"Classification: {c['classification']}. A lockfile change alone does not prove compromise.",
        "evidence": ("Diff excerpt: " + " | ".join(c["diff_excerpt"][:6])) if c.get("diff_excerpt") else "No diff excerpt available.",
        "remediation": "Review the commit and the changed entry; confirm the update was intended (e.g. via the PR), and verify integrity hashes against the registry before trusting the change.",
        "unknown": " ".join(risk.get("unknowns", [])),
    }


TEMPLATES = {"vulnerability": _vuln_template, "typosquatting": _typo_template, "lockfile_change": _lock_template}


def explain_deterministic(bundle: dict, risk: dict, finding: dict) -> dict:
    sections = TEMPLATES[bundle["kind"]](bundle, risk, finding)
    return {"finding_id": bundle["finding_id"], "kind": bundle["kind"], "source": "template", "sections": sections,
            "risk_label": risk["label"], "risk_factors": fmt_factors(risk), "validation": {"grounded": True, "removed_sections": [], "checked": "template"},
            "headline": _headline(bundle, risk)}


def _headline(b: dict, risk: dict) -> str:
    k = b["kind"]
    if k == "vulnerability":
        return f"{risk['label']} risk - {b['advisory']['primary_id']} in {b['component']['name']} {b['component']['version']}"
    if k == "typosquatting":
        return f"{risk['label']} risk - '{b['detection']['package']}' resembles '{b['detection']['similar_to']}'"
    return f"{risk['label']} risk - {b['change']['classification'].replace('_', ' ')}: {b['change']['package']}"


def explain(bundle: dict, risk: dict, finding: dict, llm: Optional[Callable[[str, str], str]] = None) -> dict:
    """Deterministic explanation, optionally rephrased by ``llm(system, user) -> str`` with per-section validation."""
    base = explain_deterministic(bundle, risk, finding)
    if llm is None:
        return base
    try:
        raw = llm(SYSTEM, build_user_prompt(compact_for_llm(bundle), json.dumps({k: risk[k] for k in ("label", "score", "factors", "unknowns", "cvss_severity")}, default=str)))
        start, end = raw.find("{"), raw.rfind("}")
        data = json.loads(raw[start:end + 1])
    except Exception as e:
        base["validation"] = {"grounded": True, "removed_sections": [], "checked": "template", "llm_error": f"{type(e).__name__}: {str(e)[:120]}"}
        return base
    sections, removed = {}, []
    for name in SECTIONS:
        txt = data.get(name)
        problems = validate_text(txt, bundle, risk) if isinstance(txt, str) and txt.strip() else ["missing or empty section"]
        if problems:
            sections[name] = base["sections"][name]
            removed.append({"section": name, "problems": problems[:4]})
        else:
            sections[name] = txt.strip()
    used = len(removed) < len(SECTIONS)
    return {**base, "sections": sections, "source": "llm+template" if removed and used else "llm" if used else "template",
            "validation": {"grounded": True, "removed_sections": removed, "checked": "llm-validated"}}
