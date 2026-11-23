"""Digest normalisation: SRI / hex / go h1 / NuGet base64 -> [{alg, hex|b64, kind}] and CycloneDX hash entries."""
from __future__ import annotations

import base64
import re
from typing import Optional

_ALG = {"sha1": "SHA-1", "sha256": "SHA-256", "sha384": "SHA-384", "sha512": "SHA-512", "md5": "MD5"}
_HEXLEN = {32: "md5", 40: "sha1", 64: "sha256", 96: "sha384", 128: "sha512"}
_HEX = re.compile(r"^[0-9a-fA-F]+$")


def parse_digest(s: Optional[str], hint: Optional[str] = None) -> Optional[dict]:
    """Return {alg, hex, kind} where kind is 'file' (digest of the distributed artifact) or 'tree' (Go module hash: not comparable to registry digests)."""
    if not s or not isinstance(s, str):
        return None
    s = s.strip()
    m = re.match(r"^(sha1|sha256|sha384|sha512|md5)[-:=](.+)$", s, re.I)
    if m:
        alg, val = m.group(1).lower(), m.group(2).strip()
        if _HEX.match(val) and _HEXLEN.get(len(val)) == alg:
            return {"alg": alg, "hex": val.lower(), "kind": "file"}
        try:
            raw = base64.b64decode(val + "=" * (-len(val) % 4), validate=False)
            return {"alg": alg, "hex": raw.hex(), "kind": "file"}
        except Exception:
            return None
    if s.startswith("h1:"):
        try:
            return {"alg": "sha256", "hex": base64.b64decode(s[3:] + "=" * (-len(s[3:]) % 4)).hex(), "kind": "tree"}
        except Exception:
            return None
    if _HEX.match(s) and len(s) in _HEXLEN:
        return {"alg": _HEXLEN[len(s)], "hex": s.lower(), "kind": "file"}
    if hint and hint.lower() in _ALG:  # bare base64 (NuGet contentHash is sha512)
        try:
            return {"alg": hint.lower(), "hex": base64.b64decode(s + "=" * (-len(s) % 4)).hex(), "kind": "file"}
        except Exception:
            return None
    return None


def to_cyclonedx(d: dict) -> Optional[dict]:
    if not d or d.get("kind") == "tree":
        return None
    alg = _ALG.get(d["alg"])
    return {"alg": alg, "content": d["hex"]} if alg else None
