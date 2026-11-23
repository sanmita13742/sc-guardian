"""Strict validation of repository URLs (public GitHub over HTTPS only)."""
from __future__ import annotations

import re
from dataclasses import dataclass
from urllib.parse import urlparse

_SEGMENT = re.compile(r"^[A-Za-z0-9_.-]{1,100}$")
_REF = re.compile(r"^[A-Za-z0-9._/@+-]{1,200}$")


class InvalidRepositoryURL(ValueError):
    pass


# GitHub UI sub-pages that may follow ``/<owner>/<repo>`` in a pasted address; they do not change which repository is meant.
_UI_SEGMENTS = {"blob", "commit", "commits", "releases", "tags", "branches", "issues", "pulls", "pull", "actions", "wiki", "security",
                "network", "graphs", "stargazers", "forks", "watchers", "tree", "archive", "compare", "projects", "discussions", "pulse"}


@dataclass(frozen=True)
class GitHubRepo:
    owner: str
    name: str
    ref: str | None = None  # branch/tag taken from a pasted ``/tree/<ref>`` address

    @property
    def clone_url(self) -> str:
        return f"https://github.com/{self.owner}/{self.name}.git"

    @property
    def web_url(self) -> str:
        return f"https://github.com/{self.owner}/{self.name}"


def _normalize(url: str) -> str:
    """Accept the usual pasted forms: scheme-less, http://, git@github.com:owner/repo.git, with query/fragment."""
    u = url.strip()
    if u.lower().startswith("git@github.com:"):
        u = "https://github.com/" + u[len("git@github.com:"):]
    elif u.lower().startswith(("github.com/", "www.github.com/")):
        u = "https://" + u
    elif u.lower().startswith("http://"):
        u = "https://" + u[len("http://"):]
    return u


def validate_github_url(url: str) -> GitHubRepo:
    """Return a normalized GitHubRepo or raise InvalidRepositoryURL.

    Accepts ``https://github.com/<owner>/<repo>[.git][/]`` plus the common pasted variants (see ``_normalize``) and GitHub
    UI sub-pages such as ``/tree/<branch>``. Rejects local paths, other hosts/schemes, credentials, ports, control characters.
    The clone URL is always rebuilt from owner/repo, never taken from the input.
    """
    if not isinstance(url, str):
        raise InvalidRepositoryURL("URL must be a string")
    url = _normalize(url)
    if not url or len(url) > 300:
        raise InvalidRepositoryURL("URL is empty or too long")
    if any(ord(c) < 33 or ord(c) == 127 for c in url) or "\\" in url:
        raise InvalidRepositoryURL("URL contains whitespace, control characters or backslashes")
    p = urlparse(url)
    if p.scheme != "https":
        raise InvalidRepositoryURL("Only GitHub repository URLs are supported (https://github.com/<owner>/<repository>)")
    if p.username or p.password or p.port:
        raise InvalidRepositoryURL("Credentials and ports are not allowed in the URL")
    if (p.hostname or "").lower() not in ("github.com", "www.github.com"):
        raise InvalidRepositoryURL("Only github.com repositories are supported")
    parts = [s for s in p.path.split("/") if s != ""]  # query string and fragment are ignored
    if len(parts) < 2:
        raise InvalidRepositoryURL("URL must look like https://github.com/<owner>/<repository>")
    owner, name = parts[0], parts[1]
    if name.endswith(".git"):
        name = name[:-4]
    for seg in (owner, name):
        if not _SEGMENT.match(seg) or seg in (".", "..") or seg.startswith("-"):
            raise InvalidRepositoryURL("Invalid owner or repository name")
    ref = None
    if len(parts) > 2:
        if parts[2] not in _UI_SEGMENTS:
            raise InvalidRepositoryURL("URL must point at the repository itself, e.g. https://github.com/<owner>/<repository>")
        if parts[2] == "tree" and len(parts) > 3:
            ref = validate_ref("/".join(parts[3:]))
    return GitHubRepo(owner=owner, name=name, ref=ref)


def validate_ref(ref: str | None) -> str | None:
    """Validate a branch/tag name; reject anything that could be parsed as an option or path trick."""
    if ref is None or ref.strip() == "":
        return None
    ref = ref.strip()
    if not _REF.match(ref) or ref.startswith("-") or ".." in ref or ref.endswith("/") or "//" in ref:
        raise InvalidRepositoryURL("Invalid branch or tag name")
    return ref
