"""HTTP client with timeouts, retry/backoff and explicit failure types (errors are never silently swallowed)."""
from __future__ import annotations

import time
from typing import Any, Optional

import requests

UA = "sc-guardian-scanner/1.0"


class SourceUnavailable(RuntimeError):
    """The remote source could not be reached or kept failing after retries."""


class NotFound(RuntimeError):
    pass


class HttpClient:
    def __init__(self, timeout: int = 25, retries: int = 3, backoff: float = 1.0, session: requests.Session | None = None):
        self.timeout, self.retries, self.backoff = timeout, retries, backoff
        self.session = session or requests.Session()
        self.session.headers.update({"User-Agent": UA})

    def request(self, method: str, url: str, headers: dict | None = None, **kw) -> requests.Response:
        last: Optional[Exception] = None
        for attempt in range(self.retries + 1):
            try:
                r = self.session.request(method, url, headers=headers, timeout=self.timeout, **kw)
            except (requests.ConnectionError, requests.Timeout) as e:
                last = e
            else:
                if r.status_code == 404:
                    raise NotFound(url)
                if r.status_code == 429 or r.status_code >= 500:
                    last = SourceUnavailable(f"HTTP {r.status_code} from {url}")
                    ra = r.headers.get("Retry-After")
                    if ra and ra.isdigit() and attempt < self.retries:
                        time.sleep(min(int(ra), 30))
                        continue
                elif r.status_code >= 400:
                    raise SourceUnavailable(f"HTTP {r.status_code} from {url}: {r.text[:200]}")
                else:
                    return r
            if attempt < self.retries:
                time.sleep(self.backoff * (2 ** attempt))
        raise SourceUnavailable(f"{url} unreachable after {self.retries + 1} attempts: {last}")

    def get_json(self, url: str, **kw) -> Any:
        return self.request("GET", url, **kw).json()

    def post_json(self, url: str, payload: Any, **kw) -> Any:
        return self.request("POST", url, json=payload, **kw).json()
