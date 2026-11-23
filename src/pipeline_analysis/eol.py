"""Known end-of-life base-image lines. A small, explicit table (vendor lifecycle pages), NOT a live feed: it is dated and the finding says so.

``AS_OF`` is the date the table was last reviewed. A tag is flagged only when its version is at or below the listed last-EOL value.
"""
from __future__ import annotations

import re
from typing import Optional

AS_OF = "2026-11"

# image (official name) -> (numeric-version regex on the tag, last EOL major/minor tuple, human note)
_LINES = {
    "node": (r"^(\d+)", (20,), "Node.js 20 and older are end-of-life (even-numbered LTS lines end 30 months after release)"),
    "python": (r"^(\d+)\.(\d+)", (3, 10), "Python 3.10 and older are end-of-life"),
    "ubuntu": (r"^(\d+)\.(\d+)", (20, 4), "Ubuntu 20.04 and older have left standard support"),
    "debian": (None, None, "Debian 11 (bullseye) and older"),
    "alpine": (r"^(\d+)\.(\d+)", (3, 19), "Alpine 3.19 and older are unsupported"),
    "centos": (r"^(\d+)", (8,), "CentOS 8 and older are end-of-life (CentOS Stream is the successor)"),
    "openjdk": (r"^(\d+)", (16,), "non-LTS/old OpenJDK images are deprecated (use eclipse-temurin)"),
    "php": (r"^(\d+)\.(\d+)", (8, 1), "PHP 8.1 and older are end-of-life"),
    "ruby": (r"^(\d+)\.(\d+)", (3, 1), "Ruby 3.1 and older are end-of-life"),
    "golang": (r"^(\d+)\.(\d+)", (1, 23), "Go releases older than the two latest are unsupported"),
    "mysql": (r"^(\d+)\.(\d+)", (5, 7), "MySQL 5.7 and older are end-of-life"),
    "postgres": (r"^(\d+)", (13,), "PostgreSQL 13 and older are end-of-life"),
    "mongo": (r"^(\d+)\.(\d+)", (5, 0), "MongoDB 5.0 and older are end-of-life"),
    "redis": (r"^(\d+)\.(\d+)", (6, 2), "Redis 6.2 and older are end-of-life"),
    "nginx": (r"^(\d+)\.(\d+)", (1, 24), "old nginx lines are unsupported"),
}
_DEBIAN_EOL = {"buster", "bullseye", "stretch", "jessie", "wheezy"}


def eol_note(image: str, tag: Optional[str]) -> Optional[str]:
    """Return a human note if ``image:tag`` is a known end-of-life line, else None. Unknown images/tags are never flagged."""
    base = image.lower()
    for pre in ("docker.io/", "index.docker.io/", "registry-1.docker.io/"):
        if base.startswith(pre):
            base = base[len(pre):]
    if base.startswith("library/"):
        base = base[len("library/"):]
    if "/" in base:  # namespaced / third-party registry image: the official-image lifecycle table does not apply
        return None
    name = base
    if not tag or tag in ("latest",):
        return None
    t = tag.lower()
    if name == "debian":
        if any(c in t for c in _DEBIAN_EOL):
            return _LINES["debian"][2]
        m = re.match(r"^(\d+)", t)
        return _LINES["debian"][2] if m and int(m.group(1)) <= 11 else None
    spec = _LINES.get(name)
    if not spec or not spec[0]:
        return None
    m = re.match(spec[0], t)
    if not m:
        return None
    try:
        got = tuple(int(x) for x in m.groups())
    except ValueError:
        return None
    return f"{spec[2]} (lifecycle table reviewed {AS_OF})" if got <= spec[1] else None
