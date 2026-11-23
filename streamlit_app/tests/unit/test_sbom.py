import json
from pathlib import Path

import pytest

from config.settings import Settings
from core.models import Component
from core.repository_inspector import inspect_repository
from sbom.cyclonedx_validator import normalize_components, validate_cyclonedx
from sbom.lockfile_analyzer import analyze_repository
from sbom.metadata_enricher import enrich_components
from sbom.quality_analyzer import analyze_quality
from sbom.syft_runner import build_command, resolve_syft, run_syft

FIX = Path(__file__).resolve().parent.parent / "fixtures"


def make_sbom(components, deps=None):
    return {"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
            "metadata": {"component": {"bom-ref": "root", "type": "application", "name": "app"}},
            "components": components, "dependencies": deps if deps is not None else []}


def comp(name, version, eco="npm", ref=None, loc="package-lock.json", **kw):
    purl = f"pkg:{ {'npm':'npm','PyPI':'pypi'}[eco] }/{name}@{version}" if version else None
    c = {"bom-ref": ref or f"{name}@{version}", "type": "library", "name": name, "properties": [
        {"name": "syft:location:0:path", "value": loc}, {"name": "syft:package:foundBy", "value": "test"}]}
    if version:
        c["version"] = version
    if purl:
        c["purl"] = purl
    c.update(kw)
    return c


def test_validator_accepts_good_and_rejects_bad():
    doc = make_sbom([comp("a", "1.0.0")], [{"ref": "a@1.0.0", "dependsOn": []}])
    r = validate_cyclonedx(doc)
    assert r["valid"] and r["stats"]["components"] == 1
    assert not validate_cyclonedx([])["valid"]
    assert not validate_cyclonedx({"bomFormat": "SPDX", "specVersion": "1.6"})["valid"]
    dup = make_sbom([comp("a", "1.0.0", ref="x"), comp("b", "1.0.0", ref="x")])
    assert any("duplicate bom-ref" in e for e in validate_cyclonedx(dup)["errors"])
    bad = make_sbom([{"type": "library", "name": "z", "purl": "notapurl", "bom-ref": "z"}])
    assert not validate_cyclonedx(bad)["valid"]


def test_validator_flags_dangling_refs():
    doc = make_sbom([comp("a", "1.0.0")], [{"ref": "a@1.0.0", "dependsOn": ["ghost"]}])
    r = validate_cyclonedx(doc)
    assert r["valid"] and any("unknown components" in w for w in r["warnings"])


def test_normalize_components_maps_service(tmp_path):
    doc = make_sbom([comp("a", "1.0.0", loc=str(tmp_path / "frontend" / "package-lock.json").replace("\\", "/")),
                     {"bom-ref": "f", "type": "file", "name": "x"}])
    comps = normalize_components(doc, tmp_path, [".", "frontend"])
    a = next(c for c in comps if c.name == "a")
    assert a.service_dir == "frontend" and a.ecosystem == "npm" and a.locations == ["frontend/package-lock.json"]


def test_quality_reports_gaps_without_claiming_complete():
    insp = inspect_repository(FIX / "monorepo")
    deps, errs = analyze_repository(FIX / "monorepo", insp)
    # SBOM that has only lodash from the frontend lockfile, no relationships, missing license
    doc = make_sbom([comp("lodash", "4.17.15", loc="frontend/package-lock.json")])
    comps = normalize_components(doc, FIX / "monorepo", [s["dir"] for s in insp.services])
    q = analyze_quality(comps, doc, deps, insp, True, errs)
    assert q["inventory_status"] == "incomplete"
    names = {m["package"] for m in q["lockfile_missing_from_sbom"]}
    assert {"mkdirp", "minimist", "flask"} <= names
    assert q["missing_metadata"]["license"] == 1 and q["dependency_relationships"] == "absent"
    assert q["inventory_status"] != "complete"


def test_quality_consistent_status_and_limitation():
    insp = inspect_repository(FIX / "monorepo")
    deps, errs = analyze_repository(FIX / "monorepo", insp)
    cs = []
    for d in deps:
        loc = d.lockfile
        cs.append({"bom-ref": f"{d.name}@{d.version}@{d.service_dir}", "type": "library", "name": d.name, "version": d.version,
                   "purl": d.purl, "licenses": [{"license": {"id": "MIT"}}], "supplier": {"name": "x"},
                   "hashes": [{"alg": "SHA-256", "content": "a"}],
                   "properties": [{"name": "syft:location:0:path", "value": loc}]})
    doc = make_sbom(cs, [{"ref": cs[0]["bom-ref"], "dependsOn": [cs[1]["bom-ref"]]}])
    comps = normalize_components(doc, FIX / "monorepo", [s["dir"] for s in insp.services])
    q = analyze_quality(comps, doc, deps, insp, True, errs)
    assert q["lockfile_missing_from_sbom_count"] == 0
    assert q["inventory_status"] in ("consistent_with_lockfiles", "partial")
    assert any("does not prove completeness" in l for l in q["limitations"]) or q["inventory_status"] == "partial"


def test_quality_scope_awareness():
    """OS packages / other scopes must not be reported as missing from a lockfile."""
    insp = inspect_repository(FIX / "monorepo")
    deps, errs = analyze_repository(FIX / "monorepo", insp)
    deb = {"bom-ref": "deb1", "type": "library", "name": "curl", "version": "7.0", "purl": "pkg:deb/debian/curl@7.0"}
    doc = make_sbom([deb])
    comps = normalize_components(doc, FIX / "monorepo", ["."])
    q = analyze_quality(comps, doc, deps, insp, True, errs)
    assert q["sbom_absent_from_lockfile_count"] == 0
    assert q["unresolved_components"] == 1  # no OSV ecosystem mapping -> unresolved identity


def test_quality_syft_failure():
    insp = inspect_repository(FIX / "monorepo")
    q = analyze_quality([], {}, [], insp, syft_ok=False)
    assert q["inventory_status"] == "unavailable"


def test_syft_command_is_argument_list(tmp_path):
    cmd = build_command("syft", tmp_path, tmp_path / "o.json")
    assert isinstance(cmd, list) and cmd[1] == "scan" and cmd[2].startswith("dir:") and "cyclonedx-json=" in cmd[4]


def test_syft_missing_binary_reported(tmp_path):
    s = Settings(syft_bin="definitely-not-syft")
    r = run_syft(tmp_path, tmp_path / "o.json", s)
    assert not r.ok and "not found" in r.error


@pytest.mark.syft
@pytest.mark.skipif(resolve_syft() is None, reason="syft not installed")
def test_real_syft_on_monorepo(tmp_path):
    r = run_syft(FIX / "monorepo", tmp_path / "sbom.json")
    assert r.ok, r.error
    assert r.version
    doc = json.loads((tmp_path / "sbom.json").read_text())
    v = validate_cyclonedx(doc)
    assert v["valid"], v
    insp = inspect_repository(FIX / "monorepo")
    comps = normalize_components(doc, FIX / "monorepo", [s["dir"] for s in insp.services])
    names = {c.name for c in comps}
    assert {"lodash", "minimist", "flask", "requests"} <= names
    svc = {c.name: c.service_dir for c in comps}
    assert svc["lodash"] == "frontend" and svc["flask"] == "backend"


class FakeHttp:
    def get_json(self, url, **kw):
        if "registry.npmjs.org" in url:
            return {"license": "MIT", "maintainers": [{"name": "dev"}]}
        from core.http import NotFound
        raise NotFound(url)


def test_enrichment_records_provenance():
    c1 = Component(bom_ref="a", name="a", version="1.0.0", ecosystem="npm")
    c2 = Component(bom_ref="b", name="b", version="1.0.0", ecosystem="PyPI")
    stats = enrich_components([c1, c2], FakeHttp())  # type: ignore[arg-type]
    assert c1.licenses == ["MIT"] and c1.enriched["license"]["source"].startswith("https://registry.npmjs.org")
    assert c2.licenses == [] and stats["not_found"] == 1  # nothing invented when registry has no record
