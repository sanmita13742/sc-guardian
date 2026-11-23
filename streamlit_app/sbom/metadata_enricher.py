"""Optional metadata enrichment from trusted registries (npm, PyPI). Every enriched field records its source.

The original Syft component data is never overwritten: enrichment only fills fields that are empty and stores
``{value, source, retrieved_at}`` under ``Component.enriched``.
"""
from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import quote

from core.http import HttpClient, NotFound, SourceUnavailable
from core.models import Component
from storage.cache import Cache

TTL = 7 * 24 * 3600


def _npm(http: HttpClient, name: str, version: str):
    url = f"https://registry.npmjs.org/{quote(name, safe='@')}/{quote(version, safe='')}"
    d = http.get_json(url)
    lic = d.get("license")
    if isinstance(lic, dict):
        lic = lic.get("type")
    maint = d.get("_npmUser", {}).get("name") or (d.get("maintainers") or [{}])[0].get("name")
    return url, {"license": lic if isinstance(lic, str) else None, "supplier": maint}


def _pypi(http: HttpClient, name: str, version: str):
    url = f"https://pypi.org/pypi/{quote(name, safe='')}/{quote(version, safe='')}/json"
    info = http.get_json(url).get("info", {})
    lic = info.get("license_expression") or (info.get("license") if info.get("license") and len(info["license"]) < 80 else None)
    return url, {"license": lic or None, "supplier": info.get("author") or info.get("maintainer") or None}


FETCHERS = {"npm": _npm, "PyPI": _pypi}


def enrich_components(components: list[Component], http: HttpClient, cache: Cache | None = None, limit: int = 150) -> dict:
    """Fill missing license/supplier from registries. Returns stats; failures are counted, never raised."""
    todo = [c for c in components if c.ecosystem in FETCHERS and c.version and (not c.licenses or not c.supplier)][:limit]
    stats = {"attempted": len(todo), "enriched_fields": 0, "not_found": 0, "unavailable": 0, "skipped_unsupported": 0}

    def work(c: Component):
        key = f"{c.ecosystem}:{c.name}@{c.version}"
        hit = cache.get("registry_meta", key, ttl=TTL) if cache else None
        if hit is None:
            try:
                url, fields = FETCHERS[c.ecosystem](http, c.name, c.version)
            except NotFound:
                return c, None, "not_found"
            except SourceUnavailable:
                return c, None, "unavailable"
            except Exception:
                return c, None, "unavailable"
            hit = {"url": url, "fields": fields}
            if cache:
                cache.set("registry_meta", key, hit)
        return c, hit, "ok"

    with ThreadPoolExecutor(max_workers=6) as ex:
        for c, hit, status in ex.map(work, todo):
            if status != "ok":
                stats["not_found" if status == "not_found" else "unavailable"] += 1
                continue
            now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
            for fld, val in hit["fields"].items():
                if not val:
                    continue
                if fld == "license" and not c.licenses:
                    c.licenses = [val]
                elif fld == "supplier" and not c.supplier:
                    c.supplier = val
                else:
                    continue
                c.enriched[fld] = {"value": val, "source": hit["url"], "retrieved_at": now}
                stats["enriched_fields"] += 1
    stats["skipped_unsupported"] = sum(1 for c in components if c.ecosystem and c.ecosystem not in FETCHERS and (not c.licenses or not c.supplier))
    return stats
