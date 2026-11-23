"""Strict validation of repository URLs (public GitHub over HTTPS only)."""
from __future__ import annotations

import re
from dataclasses import dataclass
from urllib.parse import urlparse

_SEGMENT = re.compile(r"^[A-Za-z0-9_.-]{1,100}$")
_REF = re.compile(r"^[A-Za-z0-9._/@+-]{1,200}$")


class InvalidRepositoryURL(ValueError):
    pass


@dataclass(frozen=True)
class GitHubRepo:
    owner: str
    name: str

    @property
    def clone_url(self) -> str:
        return f"https://github.com/{self.owner}/{self.name}.git"

    @property
    def web_url(self) -> str:
        return f"https://github.com/{self.owner}/{self.name}"


def validate_github_url(url: str) -> GitHubRepo:
    """Return a normalized GitHubRepo or raise InvalidRepositoryURL.

    Rejects local paths, other schemes/hosts, credentials, ports, queries, control characters and
    anything that is not exactly ``https://github.com/<owner>/<repo>[.git][/]``.
    """
    if not isinstance(url, str):
        raise InvalidRepositoryURL("URL must be a string")
    url = url.strip()
    if not url or len(url) > 300:
        raise InvalidRepositoryURL("URL is empty or too long")
    if any(ord(c) < 33 or ord(c) == 127 for c in url) or "\\" in url:
        raise InvalidRepositoryURL("URL contains whitespace, control characters or backslashes")
    p = urlparse(url)
    if p.scheme != "https":
        raise InvalidRepositoryURL("Only https:// GitHub URLs are supported")
    if p.username or p.password or p.port:
        raise InvalidRepositoryURL("Credentials and ports are not allowed in the URL")
    if (p.hostname or "").lower() not in ("github.com", "www.github.com"):
        raise InvalidRepositoryURL("Only github.com repositories are supported")
    if p.query or p.fragment or p.params:
        raise InvalidRepositoryURL("Query strings and fragments are not allowed")
    parts = [s for s in p.path.split("/") if s != ""]
    if len(parts) != 2:
        raise InvalidRepositoryURL("URL must look like https://github.com/<owner>/<repository>")
    owner, name = parts
    if name.endswith(".git"):
        name = name[:-4]
    for seg in (owner, name):
        if not _SEGMENT.match(seg) or seg in (".", "..") or seg.startswith("-"):
            raise InvalidRepositoryURL("Invalid owner or repository name")
    return GitHubRepo(owner=owner, name=name)


def validate_ref(ref: str | None) -> str | None:
    """Validate a branch/tag name; reject anything that could be parsed as an option or path trick."""
    if ref is None or ref.strip() == "":
        return None
    ref = ref.strip()
    if not _REF.match(ref) or ref.startswith("-") or ".." in ref or ref.endswith("/") or "//" in ref:
        raise InvalidRepositoryURL("Invalid branch or tag name")
    return ref
