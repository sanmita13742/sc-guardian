"""Minimal environments for subprocesses and a process-wide rate limiter.

Git, Syft and Trivy are pointed at untrusted repositories. They never need the scanner's secrets (``ANTHROPIC_API_KEY``,
``NVD_API_KEY`` ...), so they get an allow-listed environment instead of ``os.environ``.
"""
from __future__ import annotations

import os
import threading
import time

_ALLOW = {
    "PATH", "PATHEXT", "SYSTEMROOT", "WINDIR", "COMSPEC", "HOME", "USERPROFILE", "HOMEDRIVE", "HOMEPATH", "APPDATA", "LOCALAPPDATA",
    "TEMP", "TMP", "TMPDIR", "LANG", "LC_ALL", "SSL_CERT_FILE", "SSL_CERT_DIR", "REQUESTS_CA_BUNDLE", "GIT_SSL_CAINFO",
    "HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY", "http_proxy", "https_proxy", "no_proxy", "PROGRAMDATA", "PROGRAMFILES", "PROGRAMFILES(X86)",
}


def scrubbed_env(extra: dict[str, str] | None = None) -> dict[str, str]:
    """Allow-listed copy of the environment (case-insensitive on Windows) plus ``extra``."""
    allow = {k.upper() for k in _ALLOW}
    env = {k: v for k, v in os.environ.items() if k.upper() in allow}
    env.update(extra or {})
    return env


class RateLimiter:
    """Process-wide minimum interval per key, shared by every scan/thread (e.g. NVD's public rate limit)."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._next: dict[str, float] = {}

    def wait(self, key: str, min_interval: float) -> None:
        with self._lock:
            now = time.monotonic()
            at = max(now, self._next.get(key, 0.0))
            self._next[key] = at + min_interval
        delay = at - now
        if delay > 0:
            time.sleep(delay)


LIMITER = RateLimiter()
