"""Write the fused inventory as a CycloneDX document: the canonical document with every fused field added in native CycloneDX form.

* licenses  -> ``licenses`` (SPDX id when recognised, expression for compound ones, otherwise name)
* hashes    -> ``hashes`` (hex), supplier -> ``supplier.name``, description, scope (required|optional)
* links     -> ``externalReferences`` (website, vcs, issue-tracker, documentation, distribution)
* provenance and integrity verdicts -> ``properties`` (``sc-guardian:*``) so nothing is hidden in the file
The original scanner file is never modified; this is a separate, self-describing document.
"""
from __future__ import annotations

import copy
import re
import time
import uuid
from typing import Any

from core.models import Component
from sbom.fusion import ledger

_SPDX = {
    "0BSD", "AGPL-3.0-only", "AGPL-3.0-or-later", "Apache-1.1", "Apache-2.0", "Artistic-2.0", "BlueOak-1.0.0", "BSD-2-Clause", "BSD-3-Clause", "BSD-3-Clause-Clear", "BSL-1.0",
    "CC-BY-3.0", "CC-BY-4.0", "CC0-1.0", "CDDL-1.0", "EPL-1.0", "EPL-2.0", "EUPL-1.2", "GPL-2.0-only", "GPL-2.0-or-later", "GPL-3.0-only", "GPL-3.0-or-later", "ISC", "LGPL-2.1-only",
    "LGPL-2.1-or-later", "LGPL-3.0-only", "LGPL-3.0-or-later", "MIT", "MIT-0", "MPL-1.1", "MPL-2.0", "MS-PL", "OFL-1.1", "PSF-2.0", "Python-2.0", "Unlicense", "Zlib", "WTFPL", "Unicode-DFS-2016",
    "GPL-2.0", "GPL-3.0", "LGPL-2.1", "LGPL-3.0", "AGPL-3.0", "BSD-4-Clause", "Apache-1.0", "CC-BY-SA-4.0", "Artistic-1.0", "JSON", "NCSA", "OpenSSL", "Ruby", "X11",
}
_EXPR = re.compile(r"\s(OR|AND|WITH)\s|[()]", re.I)


def license_entry(s: str) -> dict:
    s = s.strip()
    if _EXPR.search(s):
        return {"expression": s}
    if s in _SPDX:
        return {"license": {"id": s}}
    for cand in _SPDX:  # case-insensitive match, e.g. "mit" or "Apache-2.0 "
        if cand.lower() == s.lower():
            return {"license": {"id": cand}}
    return {"license": {"name": s}}


def _props(c: Component) -> list[dict]:
    out = []
    for f, p in c.provenance.items():
        if f.startswith("_") or not isinstance(p, dict) or not p.get("source"):
            continue
        out.append({"name": f"sc-guardian:provenance:{f}", "value": p["source"]})
        if p.get("confidence") and p["confidence"] != "high":
            out.append({"name": f"sc-guardian:confidence:{f}", "value": p["confidence"]})
        for cf in p.get("conflicts", [])[:3]:
            out.append({"name": f"sc-guardian:conflict:{f}", "value": f"{cf['source']}={cf['value']}"})
    lk = c.integrity.get("lockfile") or {}
    if lk.get("kind") == "tree":  # Go h1: digest of the module tree - not a file hash, so not a CycloneDX hash; kept verbatim as a property
        out.append({"name": "sc-guardian:digest:go-h1", "value": f"sha256:{lk.get('hex')}"})
    st = c.integrity.get("status")
    if st:
        out.append({"name": "sc-guardian:integrity", "value": st})
    if c.install_script:
        out.append({"name": "sc-guardian:install-script", "value": "true"})
    if c.deprecated:
        out.append({"name": "sc-guardian:deprecated", "value": "true"})
    if c.published_at:
        out.append({"name": "sc-guardian:published", "value": str(c.published_at)})
    if c.source_type:
        out.append({"name": "sc-guardian:source-type", "value": c.source_type})
    if c.resolved_url:
        out.append({"name": "sc-guardian:resolved", "value": c.resolved_url[:300]})
    if c.resolution != "scanner":
        out.append({"name": "sc-guardian:resolution", "value": c.resolution})
    out.append({"name": "sc-guardian:completeness", "value": str(ledger.completeness(c))})
    return out


def write_fused(doc: dict, components: list[Component], report: dict, requested_tool: str) -> dict:
    d = copy.deepcopy(doc)
    d["serialNumber"] = f"urn:uuid:{uuid.uuid4()}"
    d["version"] = 1
    by_ref = {c.bom_ref: c for c in components}
    for entry in d.get("components") or []:
        c = by_ref.get(entry.get("bom-ref"))
        if not c or c.is_self:
            continue
        if c.licenses:
            entry["licenses"] = [license_entry(x) for x in c.licenses]
        if c.hashes:
            have = {(h.get("alg"), h.get("content")) for h in entry.get("hashes", []) or []}
            entry["hashes"] = list(entry.get("hashes") or []) + [h for h in c.hashes if (h.get("alg"), h.get("content")) not in have]
        if c.supplier and not entry.get("supplier"):
            entry["supplier"] = {"name": c.supplier}
        if c.description and not entry.get("description"):
            entry["description"] = c.description
        if c.scope in ("required", "optional"):
            entry["scope"] = c.scope
        elif c.scope == "dev":
            entry["scope"] = "optional"
        if c.external_refs:
            have = {r.get("url") for r in entry.get("externalReferences", []) or []}
            entry["externalReferences"] = list(entry.get("externalReferences") or []) + [{"type": r["type"], "url": r["url"]} for r in c.external_refs if r["url"] not in have]
        entry["properties"] = [p for p in entry.get("properties", []) or [] if not str(p.get("name", "")).startswith(("sc-guardian:provenance", "sc-guardian:confidence",
                                                                                                                       "sc-guardian:conflict", "sc-guardian:integrity", "sc-guardian:completeness",
                                                                                                                       "sc-guardian:resolved", "sc-guardian:source-type"))] + _props(c)
        if c.scope == "dev":
            entry["properties"].append({"name": "sc-guardian:dev", "value": "true"})
    md = d.setdefault("metadata", {})
    md["timestamp"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    tools = md.setdefault("tools", {})
    if isinstance(tools, dict):
        tools.setdefault("components", []).append({"type": "application", "name": "sc-guardian-metadata-fusion", "version": "1.0",
                                                    "description": "Field-level provenance fusion of lockfile, scanner and registry metadata"})
    md.setdefault("properties", []).extend([
        {"name": "sc-guardian:fused-from", "value": requested_tool},
        {"name": "sc-guardian:average-completeness", "value": str(report.get("average_completeness"))},
        {"name": "sc-guardian:integrity-summary", "value": ",".join(f"{k}={v}" for k, v in sorted((report.get("integrity") or {}).items()))},
    ])
    return d
