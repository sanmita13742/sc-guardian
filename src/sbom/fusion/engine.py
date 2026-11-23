"""Metadata fusion engine.

Pipeline (all deterministic, no code of the scanned repository is run):

1. LOCKFILE  - apply what the native lockfile parsers recorded (exact pin: digest, resolved URL, scope, install-script flag, license, ...)
2. SCANNER   - remember what the SBOM scanner already put in its entry (provenance only; lower trust than the lockfile)
3. REGISTRY  - for fields still empty (and for integrity verification) ask the package registries, in parallel, cached, within a time budget,
               with a circuit breaker per host so an outage costs seconds, not minutes
4. INTEGRITY - compare the lockfile digest with the digest the registry publishes today:
                 verified      same artifact digest
                 mismatch      different digest for the same name@version  -> alert (possible tampered lockfile / republished artifact)
                 unverifiable  lockfile has a digest, the registry offers nothing comparable
                 absent        the lockfile records no digest (the registry digest, if any, is used as a *lower-confidence* hash)
5. REPORT    - per-field coverage before/after, conflicts, missing-reason per field, completeness score per component

Fields are never invented and a less trusted source never overwrites a more trusted one (see ledger.py).
"""
from __future__ import annotations

import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Callable, Optional

from core.http import HttpClient, NotFound, SourceUnavailable
from core.models import Component, LockDependency
from sbom.fusion import ledger
from sbom.fusion.hashes import parse_digest, to_cyclonedx
from sbom.fusion.registries import FETCHERS, supported
from sbom.package_extractors.common import normalize_name
from storage.cache import Cache

TTL = 30 * 24 * 3600  # a published name@version is immutable; descriptive data changes rarely
NEG_TTL = 24 * 3600
FIELDS_REPORTED = ("licenses", "hashes", "supplier", "description", "external_refs", "scope", "published_at")


def _key(eco: Optional[str], name: str, version: Optional[str], svc: Optional[str] = None) -> tuple:
    return (eco or "", normalize_name(eco or "", name), version or "", svc if svc is not None else "")


def apply_lockfile(components: list[Component], lock_deps: list[LockDependency]) -> dict[str, int]:
    """Phase 1: native lockfile facts onto matching components (service-scoped first, then any service)."""
    by_svc: dict[tuple, list[LockDependency]] = {}
    by_any: dict[tuple, list[LockDependency]] = {}
    for d in lock_deps:
        if d.derived or not d.version:
            continue
        by_svc.setdefault(_key(d.ecosystem, d.name, d.version, d.service_dir), []).append(d)
        by_any.setdefault(_key(d.ecosystem, d.name, d.version), []).append(d)
    hit = 0
    for c in components:
        if c.is_self or c.type == "file" or not c.ecosystem:
            continue
        cands = by_svc.get(_key(c.ecosystem, c.name, c.version, c.service_dir)) or by_any.get(_key(c.ecosystem, c.name, c.version)) or []
        if not cands:
            continue
        hit += 1
        c.sources = sorted(set(c.sources) | {"lockfile"})
        for d in cands:
            ev = f"{d.lockfile} {d.record or ''}".strip()
            if d.license:
                ledger.set_field(c, "licenses", [d.license], "lockfile", ev)
            dig = parse_digest(d.integrity, (d.meta or {}).get("hash_alg"))
            hashes = []
            for raw in [d.integrity] + list((d.meta or {}).get("hashes") or []):
                p = parse_digest(raw, (d.meta or {}).get("hash_alg"))
                ch = to_cyclonedx(p) if p else None
                if ch and ch not in hashes:
                    hashes.append(ch)
            if hashes:
                ledger.set_field(c, "hashes", hashes, "lockfile", ev)
            if dig:
                c.integrity.setdefault("lockfile", {"alg": dig["alg"], "hex": dig["hex"], "kind": dig["kind"], "file": d.lockfile})
            if d.resolved:
                ledger.set_field(c, "resolved_url", d.resolved, "lockfile", ev)
            if d.source_type:
                ledger.set_field(c, "source_type", d.source_type, "lockfile", ev)
            if d.direct is not None:
                ledger.set_field(c, "direct_declared", d.direct, "lockfile", ev)
            scope = "dev" if d.dev else "optional" if (d.meta or {}).get("optional") or (d.meta or {}).get("peer") else ("required" if d.dev is None and d.direct is not None else None)
            if d.dev is True:
                scope = "dev"
            if scope:
                ledger.set_field(c, "scope", scope, "lockfile", ev)
            m = d.meta or {}
            if m.get("install_script"):
                ledger.set_field(c, "install_script", True, "lockfile", ev)
            if m.get("deprecated"):
                ledger.set_field(c, "deprecated", True, "lockfile", ev)
            if m.get("description"):
                ledger.set_field(c, "description", str(m["description"])[:300], "lockfile", ev)
            if m.get("published"):
                ledger.set_field(c, "published_at", m["published"], "lockfile", ev)
            if m.get("authors"):
                ledger.set_field(c, "supplier", ", ".join(m["authors"][:2]), "lockfile", ev)
            refs = [{"type": t, "url": m[k], "source": "lockfile"} for t, k in (("website", "homepage"), ("vcs", "vcs")) if m.get(k)]
            if refs:
                ledger.set_field(c, "external_refs", refs, "lockfile", ev)
    return {"components_matched_to_lockfile": hit}


class _Breaker:
    """Per-host circuit breaker: after N consecutive outages a host is skipped for the rest of the run."""

    def __init__(self, limit: int = 4):
        self.limit, self.fails, self.open = limit, {}, set()
        self.lock = threading.Lock()

    def ok(self, host: str) -> bool:
        return host not in self.open

    def failure(self, host: str) -> None:
        with self.lock:
            self.fails[host] = self.fails.get(host, 0) + 1
            if self.fails[host] >= self.limit:
                self.open.add(host)

    def success(self, host: str) -> None:
        with self.lock:
            self.fails[host] = 0


def _needs_registry(c: Component) -> bool:
    return any(ledger._empty(getattr(c, f)) for f in ("licenses", "supplier", "description", "external_refs", "published_at", "hashes")) or "lockfile" in c.integrity


def fetch_registry(components: list[Component], http: HttpClient, cache: Optional[Cache], budget_s: float = 120.0, workers: int = 8,
                   on_progress: Optional[Callable[[str], None]] = None) -> dict[str, Any]:
    """Phase 3: query registries for components that still miss data or whose lockfile digest should be verified."""
    todo = [c for c in components if not c.is_self and c.type != "file" and c.version and supported(c.ecosystem) and _needs_registry(c)]
    stats: dict[str, Any] = {"eligible": len(todo), "from_cache": 0, "fetched": 0, "not_found": 0, "unavailable": 0, "skipped_budget": 0, "hosts_tripped": [],
                             "unsupported_ecosystems": sorted({c.ecosystem for c in components if c.ecosystem and not supported(c.ecosystem) and not c.is_self})}
    if not todo:
        return stats
    br, t0 = _Breaker(), time.time()
    uniq: dict[tuple, list[Component]] = {}
    for c in todo:
        uniq.setdefault((c.ecosystem, c.name, c.version), []).append(c)

    def work(k: tuple) -> tuple[tuple, dict, str]:
        eco, name, ver = k
        ck = f"{eco}:{name}@{ver}|{'+'.join(l for l, _ in FETCHERS[eco])}"  # key includes the client set: adding a client never serves stale, thinner records
        cached = cache.get("meta_fusion", ck, ttl=TTL) if cache else None
        if cached is not None:
            return k, cached, "cache"
        if time.time() - t0 > budget_s:
            return k, {}, "budget"
        merged: dict[str, Any] = {"sources": {}}
        saw_any = False
        for label, fn in FETCHERS[eco]:
            if not br.ok(label):
                continue
            try:
                rec = fn(http, eco, name, ver)
                br.success(label)
            except NotFound:
                continue
            except SourceUnavailable:
                br.failure(label)
                continue
            except Exception:
                continue
            if not rec:
                continue
            saw_any = True
            merged["sources"][label] = rec.get("url")
            for f, v in rec.items():
                if f in ("url",):
                    continue
                if f in ("licenses", "links", "digests") and f in merged:
                    seen = {str(x) for x in merged[f]}
                    merged[f] = merged[f] + [x for x in v if str(x) not in seen]
                elif f not in merged:
                    merged[f] = v
        if not saw_any:
            all_down = all(not br.ok(l) for l, _ in FETCHERS[eco])
            if cache and not all_down:
                cache.set("meta_fusion", ck, {"_negative": True, "ts": time.time()})
            return k, {}, "unavailable" if all_down else "not_found"
        if cache:
            cache.set("meta_fusion", ck, merged)
        return k, merged, "fetched"

    done = 0
    with ThreadPoolExecutor(max_workers=workers) as ex:
        futs = [ex.submit(work, k) for k in uniq]
        for f in as_completed(futs):
            k, rec, status = f.result()
            if rec.get("_negative"):
                status, rec = "not_found", {}
            stats["from_cache" if status == "cache" else "fetched" if status == "fetched" else "not_found" if status == "not_found"
                  else "skipped_budget" if status == "budget" else "unavailable"] += 1
            for c in uniq[k]:
                if rec:
                    _apply_record(c, rec)
                    c.integrity["lookup"] = "found"
                elif status == "not_found":
                    c.integrity["lookup"] = "not_found"
            done += 1
            if on_progress and done % 50 == 0:
                on_progress(f"{done}/{len(uniq)} package versions resolved against registries")
    stats["hosts_tripped"] = sorted(br.open)
    stats["seconds"] = round(time.time() - t0, 1)
    return stats


def _apply_record(c: Component, rec: dict) -> None:
    srcs = rec.get("sources") or {}
    src_label = "registry:" + "+".join(srcs) if srcs else "registry"
    ev = "; ".join(f"{k}: {v}" for k, v in srcs.items() if v)[:300]
    if rec.get("licenses"):
        ledger.set_field(c, "licenses", rec["licenses"][:3], src_label, ev)
    if rec.get("supplier"):
        ledger.set_field(c, "supplier", rec["supplier"], src_label, ev)
    if rec.get("description"):
        ledger.set_field(c, "description", rec["description"], src_label, ev)
    if rec.get("published_at"):
        ledger.set_field(c, "published_at", rec["published_at"], src_label, ev)
    if "deprecated" in rec:
        ledger.set_field(c, "deprecated", bool(rec["deprecated"]), src_label, ev) if rec["deprecated"] else None
    if "install_script" in rec and rec["install_script"]:
        ledger.set_field(c, "install_script", True, src_label, ev)
    if rec.get("links"):
        ledger.set_field(c, "external_refs", [{**l, "source": src_label} for l in rec["links"]], src_label, ev)
    if rec.get("provenance_attestations"):
        c.integrity["attestations"] = rec["provenance_attestations"]
        c.integrity["attested"] = True
    if rec.get("yanked"):
        c.integrity["yanked"] = True
    # integrity triangulation
    digs = [d for d in rec.get("digests", []) if d.get("kind") == "file"]
    lock = c.integrity.get("lockfile")
    if lock:
        if lock.get("kind") == "tree":
            trees = [d for d in rec.get("digests", []) if d.get("kind") == "tree"]
            if not trees:
                c.integrity.update(status="unverifiable", reason="Go module tree hash (h1:) could not be compared: checksum database returned nothing")
            elif any(d["hex"] == lock["hex"] for d in trees):
                c.integrity.update(status="verified", algorithm="go-h1", registry=trees[0]["hex"], reason="go.sum h1 equals the Go checksum database (sum.golang.org)")
            else:
                c.integrity.update(status="mismatch", algorithm="go-h1", registry=trees[0]["hex"], reason="go.sum h1 differs from the Go checksum database")
        else:
            comparable = [d for d in digs if d["alg"] == lock["alg"]]
            if not digs or not comparable:
                c.integrity.update(status="unverifiable", reason="the registry publishes no digest of the same algorithm")
            elif any(d["hex"] == lock["hex"] for d in comparable):
                c.integrity.update(status="verified", algorithm=lock["alg"], registry=comparable[0]["hex"], reason="lockfile digest equals the registry digest")
            else:
                c.integrity.update(status="mismatch", algorithm=lock["alg"], registry=comparable[0]["hex"],
                                   reason="the lockfile pins a digest that differs from the registry's current digest for this exact version")
    elif digs:
        ch = [to_cyclonedx(d) for d in digs[:2]]
        ch = [h for h in ch if h]
        if ch:
            ledger.set_field(c, "hashes", ch, src_label, ev, "medium")
        c.integrity.update(status="absent", reason="the lockfile records no digest; registry digest added with medium confidence")


def finalize(components: list[Component], lock_only_snapshot: dict[str, int]) -> dict[str, Any]:
    """Phase 5: completeness, coverage before/after, integrity summary, missing reasons."""
    pk = [c for c in components if not c.is_self and c.type != "file"]
    n = len(pk) or 1
    cov = {f: sum(1 for c in pk if not ledger._empty(getattr(c, f))) for f in FIELDS_REPORTED}
    by_source: dict[str, int] = {}
    for c in pk:
        for f in FIELDS_REPORTED:
            p = c.provenance.get(f)
            if p and not ledger._empty(getattr(c, f)):
                by_source[ledger.source_class(p["source"])] = by_source.get(ledger.source_class(p["source"]), 0) + 1
    integ: dict[str, int] = {}
    for c in pk:
        st = c.integrity.get("status") or ("absent" if "lockfile" not in c.integrity else "unverifiable")
        c.integrity.setdefault("status", st)
        integ[st] = integ.get(st, 0) + 1
    for c in pk:
        reasons = {}
        for f in FIELDS_REPORTED:
            if ledger._empty(getattr(c, f)):
                if not supported(c.ecosystem):
                    reasons[f] = "no registry client for this ecosystem and the lockfile does not record it"
                else:
                    reasons[f] = "not recorded by the lockfile/scanner and not published by the registry (or registry unreachable)"
        c.provenance.setdefault("_missing", {})["reasons"] = reasons
    comp_scores = [ledger.completeness(c) for c in pk]
    for c, sc in zip(pk, comp_scores):
        c.completeness = sc
    conflicts = [{"component": f"{c.name}@{c.version}", "field": f, "chosen": c.provenance[f]["source"], "conflicts": c.provenance[f]["conflicts"]}
                 for c in pk for f in FIELDS_REPORTED if c.provenance.get(f, {}).get("conflicts")]
    mism = [{"component": f"{c.name}@{c.version}", "ecosystem": c.ecosystem, "service": c.service_dir, "lockfile": c.integrity.get("lockfile", {}).get("file"),
             "algorithm": c.integrity.get("algorithm"), "lockfile_digest": c.integrity["lockfile"]["hex"], "registry_digest": c.integrity.get("registry")}
            for c in pk if c.integrity.get("status") == "mismatch"]
    return {"components": len(pk), "coverage": {f: {"before": lock_only_snapshot.get(f, 0), "after": cov[f], "percent": round(100 * cov[f] / n, 1)} for f in FIELDS_REPORTED},
            "fields_by_source": by_source, "integrity": integ, "integrity_mismatches": mism, "conflicts": conflicts[:100], "conflict_count": len(conflicts),
            "average_completeness": round(sum(comp_scores) / n, 3) if comp_scores else 0.0,
            "install_script_packages": sorted(f"{c.name}@{c.version}" for c in pk if c.install_script)[:50],
            "deprecated_packages": sorted(f"{c.name}@{c.version}" for c in pk if c.deprecated)[:50]}


def fuse(components: list[Component], lock_deps: list[LockDependency], http: Optional[HttpClient], cache: Optional[Cache], registry: bool = True,
         budget_s: float = 120.0, on_progress: Optional[Callable[[str], None]] = None) -> dict[str, Any]:
    """Run all phases in place on ``components`` and return the fusion report."""
    pk = [c for c in components if not c.is_self and c.type != "file"]
    for c in pk:
        ledger.init_scanner_provenance(c)
    snap_scanner = {f: sum(1 for c in pk if not ledger._empty(getattr(c, f))) for f in FIELDS_REPORTED}
    lk = apply_lockfile(components, lock_deps)
    snap_lock = {f: sum(1 for c in pk if not ledger._empty(getattr(c, f))) for f in FIELDS_REPORTED}
    reg: dict[str, Any] = {"skipped": True}
    if registry and http is not None:
        reg = fetch_registry(components, http, cache, budget_s=budget_s, on_progress=on_progress)
    rep = finalize(components, snap_scanner)
    rep["lockfile_phase"] = {**lk, "coverage_after_lockfile": snap_lock}
    rep["registry_phase"] = reg
    return rep
