"""Static Dockerfile / docker-compose analysis. Nothing is built or run; the files are only parsed."""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Optional

import yaml

from pipeline_analysis.eol import eol_note
from pipeline_analysis.models import SECRET_LITERAL, PipelineFinding, redact_line

SECRET_NAME = re.compile(r"(PASS(WORD)?|SECRET|TOKEN|API[_-]?KEY|PRIVATE[_-]?KEY|CREDENTIAL|ACCESS[_-]?KEY)", re.I)
PIPE_TO_SHELL = re.compile(r"(curl|wget)\b[^|;&\n]*\|\s*(sudo\s+)?(ba|z|da)?sh\b", re.I)
INSECURE = re.compile(r"(--no-check-certificate|--insecure|\bcurl\b[^\n]*\s-k\b|NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*0|GIT_SSL_NO_VERIFY\s*=\s*(1|true)|strict-ssl\s+false)", re.I)
SENSITIVE_COPY = re.compile(r"(^|/)(\.env(\..+)?|id_rsa|id_ed25519|.*\.pem|.*\.p12|\.npmrc|\.pypirc|credentials|\.aws|\.ssh)(/|$)", re.I)
TRUSTED_REGISTRIES = ("mcr.microsoft.com", "gcr.io", "registry.k8s.io", "quay.io", "public.ecr.aws", "ghcr.io", "cgr.dev", "docker.io", "index.docker.io", "registry-1.docker.io")
SENSITIVE_HINT = ("secret", "password", "token", "key")


@dataclass
class Instr:
    line: int
    op: str
    args: str
    stage: int


def parse_dockerfile(text: str) -> list[Instr]:
    """Instructions with line numbers (continuations joined, comments dropped, stage index assigned on FROM)."""
    out: list[Instr] = []
    stage, buf, start = -1, "", 0
    for i, raw in enumerate(text.splitlines(), 1):
        line = raw.rstrip()
        if not buf and (not line.strip() or line.lstrip().startswith("#")):
            continue
        if line.lstrip().startswith("#") and buf:
            continue
        if not buf:
            start = i
        if line.endswith("\\"):
            buf += line[:-1] + " "
            continue
        buf += line
        m = re.match(r"^\s*([A-Za-z]+)\s*(.*)$", buf)
        buf_text, buf = buf, ""
        if not m:
            continue
        op, args = m.group(1).upper(), m.group(2).strip()
        if op == "FROM":
            stage += 1
        out.append(Instr(start, op, args, max(stage, 0)))
    return out


def split_image(ref: str) -> tuple[str, Optional[str], Optional[str]]:
    """image reference -> (name, tag, digest)."""
    digest = None
    if "@" in ref:
        ref, digest = ref.split("@", 1)
    tag = None
    last = ref.rsplit("/", 1)[-1]
    if ":" in last:
        ref, tag = ref.rsplit(":", 1)
    return ref, tag, digest


def classify_image(name: str) -> str:
    """official | verified-registry | community | unknown-registry (heuristic by registry host / namespace)."""
    parts = name.split("/")
    if "." in parts[0] or ":" in parts[0] or parts[0] == "localhost":
        host = parts[0]
        if host in ("docker.io", "index.docker.io", "registry-1.docker.io"):
            parts = parts[1:]
        elif host in TRUSTED_REGISTRIES:
            return "verified-registry"
        else:
            return "unknown-registry"
    if len(parts) == 1 or (len(parts) == 2 and parts[0] == "library"):
        return "official"
    return "community"


def _f(rule, title, sev, file, line, snippet, subject, why, fix, strength="high", refs=None, **extra) -> PipelineFinding:
    return PipelineFinding(rule_id=rule, category="container", ecosystem="Docker", title=title, severity=sev, file=file, line=line, snippet=redact_line(snippet.strip())[:200],
                           subject=subject, why=why, remediation=fix, evidence_strength=strength, references=refs or [], extra=extra)


def analyze_dockerfile(text: str, path: str) -> tuple[list[PipelineFinding], list[dict]]:
    """Return (findings, images). ``images`` lists every FROM with parsed name/tag/digest for the SBOM."""
    ins = parse_dockerfile(text)
    findings: list[PipelineFinding] = []
    images: list[dict] = []
    stage_names: set[str] = set()
    last_stage = max((i.stage for i in ins), default=0)
    user_by_stage: dict[int, str] = {}
    for i in ins:
        if i.op == "FROM":
            a = re.sub(r"--platform=\S+\s*", "", i.args)
            m = re.match(r"^(\S+)(?:\s+[Aa][Ss]\s+(\S+))?", a)
            if not m:
                continue
            ref, alias = m.group(1), m.group(2)
            if alias:
                stage_names.add(alias.lower())
            if ref.lower() in stage_names or ref.lower() == "scratch" or "$" in ref:
                continue
            name, tag, digest = split_image(ref)
            kind = classify_image(name)
            images.append({"ref": ref, "name": name, "tag": tag, "digest": digest, "kind": kind, "file": path, "line": i.line, "stage": i.stage, "final": False})
            if not digest and (tag in (None, "latest")):
                findings.append(_f("DF001", "Base image is not pinned to a version (uses 'latest' or no tag)", "HIGH", path, i.line, f"FROM {ref}", ref,
                                   "A floating tag changes silently; a rebuild can pull different (possibly compromised or incompatible) content.",
                                   "Pin a specific version tag and, for reproducibility, its sha256 digest.", refs=["https://docs.docker.com/build/building/best-practices/#pin-base-image-versions"]))
            elif not digest:
                findings.append(_f("DF002", "Base image tag is not pinned by digest", "LOW", path, i.line, f"FROM {ref}", ref,
                                   "Tags are mutable: the same tag can later point to different content (tag re-push or registry compromise).",
                                   f"Pin by digest: FROM {name}:{tag}@sha256:<digest>."))
            if kind == "unknown-registry":
                findings.append(_f("DF014", "Base image comes from an unrecognised registry", "MEDIUM", path, i.line, f"FROM {ref}", ref,
                                   "Images from registries outside the well-known set have no established provenance or review process.",
                                   "Use an official/verified image or mirror the image into a registry you control and verify its signature.", strength="medium"))
            elif kind == "community":
                findings.append(_f("DF015", "Base image is a community (non-official) image", "LOW", path, i.line, f"FROM {ref}", ref,
                                   "Community images on Docker Hub are maintained by individuals; contents and update cadence are not vetted by Docker.",
                                   "Prefer an official or verified-publisher image, or build from an official base.", strength="medium"))
            note = eol_note(name, tag)
            if note:
                findings.append(_f("DF012", "Base image is an end-of-life version", "MEDIUM", path, i.line, f"FROM {ref}", ref, note + ". It no longer receives security fixes.",
                                   "Move to a currently supported release line.", strength="medium"))
        elif i.op == "USER":
            user_by_stage[i.stage] = i.args.split(":")[0].strip().lower()
        elif i.op == "ADD":
            if re.match(r"^(--\S+\s+)*https?://", i.args):
                findings.append(_f("DF004", "ADD downloads a remote file at build time", "HIGH", path, i.line, f"ADD {i.args}", i.args.split()[-2] if len(i.args.split()) > 1 else i.args,
                                   "ADD <url> fetches unverified content with no checksum; the file can change between builds.",
                                   "Use curl/wget with a pinned URL and verify a SHA-256 checksum, or COPY a vendored file."))
        elif i.op in ("ENV", "ARG"):
            for m in re.finditer(r"([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(\"[^\"]*\"|'[^']*'|\S+)", i.args):
                nm, val = m.group(1), m.group(2).strip("\"'")
                if (SECRET_NAME.search(nm) and val and not val.startswith("$") and val.lower() not in ("changeme", "")) or SECRET_LITERAL.search(val):
                    findings.append(_f("DF006", "Credential-like value is baked into the image", "HIGH", path, i.line, f"{i.op} {nm}=[REDACTED]", nm,
                                       "Values in ENV/ARG are stored in image layers and visible to anyone who can pull the image.",
                                       "Inject secrets at runtime (orchestrator secrets) or use BuildKit `--mount=type=secret`; rotate any value already committed."))
        elif i.op in ("COPY", "ADD"):
            pass
        if i.op == "RUN":
            if PIPE_TO_SHELL.search(i.args):
                findings.append(_f("DF005", "Remote script is piped straight into a shell", "HIGH", path, i.line, f"RUN {i.args}", i.args[:80],
                                   "Executes whatever the server returns at build time with no integrity check (classic supply-chain injection point).",
                                   "Download to a file, verify a pinned checksum/signature, then execute."))
            if INSECURE.search(i.args):
                findings.append(_f("DF007", "TLS verification is disabled", "MEDIUM", path, i.line, f"RUN {i.args}", i.args[:80],
                                   "Disabling certificate checks allows man-in-the-middle tampering of downloaded artifacts.", "Remove the insecure flag; fix the certificate chain instead."))
            if re.search(r"chmod\s+(-R\s+)?0?777", i.args):
                findings.append(_f("DF010", "World-writable permissions (chmod 777)", "MEDIUM", path, i.line, f"RUN {i.args}", "chmod 777", "Any process in the container can modify these files.", "Grant the minimum required permissions."))
            if re.search(r"\bnpm\s+install\b(?!\s+-g)", i.args) and "npm ci" not in i.args:
                findings.append(_f("DF008", "`npm install` used in container build instead of `npm ci`", "LOW", path, i.line, f"RUN {i.args}", "npm install",
                                   "`npm install` in container builds may write to or re-evaluate package-lock.json if manifests differ; `npm ci` enforces strict, reproducible, read-only installation from the lockfile.",
                                   "Use `npm ci` (exact lockfile install) for deterministic container builds.", strength="medium"))
            if re.search(r"\bpip3?\s+install\b", i.args) and "--require-hashes" not in i.args and re.search(r"pip3?\s+install\s+(?!-r|--upgrade pip|-U pip)[A-Za-z]", i.args):
                findings.append(_f("DF009", "Python packages installed without pinned versions or hashes", "LOW", path, i.line, f"RUN {i.args}", "pip install",
                                   "Unpinned installs resolve to whatever is newest at build time.", "Pin versions (and `--require-hashes`) via a requirements/constraints file.", strength="medium"))
        if i.op in ("COPY", "ADD"):
            for tok in i.args.split():
                if not tok.startswith("-") and SENSITIVE_COPY.search(tok.strip("\"'")):
                    findings.append(_f("DF011", "Sensitive-looking file is copied into the image", "HIGH", path, i.line, f"{i.op} {i.args}", tok,
                                       "Keys, .env, .npmrc and credential files copied into a layer are recoverable by anyone with the image.",
                                       "Exclude via .dockerignore and use build secrets instead.", strength="medium"))
                    break
    # final stage should not run as root
    if images:
        images[-1]["final"] = True
    final_user = user_by_stage.get(last_stage)
    if ins and (final_user is None or final_user in ("root", "0")):
        findings.append(_f("DF003", "Container runs as root", "MEDIUM", path, 0, "(no non-root USER in the final stage)" if final_user is None else "USER root", "USER",
                           "A compromised process inherits root inside the container, which eases breakout and tampering.", "Add a dedicated unprivileged `USER` before the entrypoint.",
                           refs=["https://docs.docker.com/build/building/best-practices/#user"]))
    for i in ins:  # secret literals anywhere in the file
        if SECRET_LITERAL.search(i.args) and not any(f.rule_id == "DF006" and f.line == i.line for f in findings):
            findings.append(_f("SEC001", "A credential appears to be committed in this file", "CRITICAL", path, i.line, f"{i.op} {i.args}", "credential",
                               "A live-looking token/key is stored in the repository.", "Revoke and rotate it now; move it to a secret store."))
    return findings, images


def analyze_compose(text: str, path: str) -> tuple[list[PipelineFinding], list[dict]]:
    findings: list[PipelineFinding] = []
    images: list[dict] = []
    try:
        data = yaml.safe_load(text) or {}
    except Exception:
        return findings, images
    services = (data.get("services") if isinstance(data, dict) else None) or {}
    lines = text.splitlines()

    def line_of(needle: str) -> int:
        for n, l in enumerate(lines, 1):
            if needle in l:
                return n
        return 0

    for name, svc in services.items():
        if not isinstance(svc, dict):
            continue
        img = svc.get("image")
        if isinstance(img, str) and "$" not in img:
            nm, tag, digest = split_image(img)
            images.append({"ref": img, "name": nm, "tag": tag, "digest": digest, "kind": classify_image(nm), "file": path, "line": line_of(img), "stage": 0, "final": True, "service": name})
            if not digest and tag in (None, "latest"):
                findings.append(_f("DC001", f"Service '{name}' uses an unpinned image", "MEDIUM", path, line_of(img), f"image: {img}", img,
                                   "A floating tag changes silently between deployments.", "Pin a version tag and digest."))
            note = eol_note(nm, tag)
            if note:
                findings.append(_f("DF012", f"Service '{name}' uses an end-of-life image", "MEDIUM", path, line_of(img), f"image: {img}", img, note + ".", "Move to a supported release line.", strength="medium"))
        if svc.get("privileged") is True:
            findings.append(_f("DC002", f"Service '{name}' runs privileged", "HIGH", path, line_of("privileged"), "privileged: true", name,
                               "A privileged container has nearly the full capabilities of the host.", "Drop `privileged`; add only the specific capabilities needed."))
        if str(svc.get("network_mode", "")).lower() == "host":
            findings.append(_f("DC003", f"Service '{name}' uses the host network", "MEDIUM", path, line_of("network_mode"), "network_mode: host", name,
                               "Removes network isolation between the container and the host.", "Use a user-defined bridge network and publish only needed ports."))
        vols = [str(v) for v in svc.get("volumes") or []]
        if any("docker.sock" in v for v in vols):
            findings.append(_f("DC004", f"Service '{name}' mounts the Docker socket", "HIGH", path, line_of("docker.sock"), "volumes: /var/run/docker.sock", name,
                               "Access to the Docker socket is equivalent to root on the host.", "Avoid it; use a socket proxy with a restricted API if unavoidable."))
        caps = [str(c).upper() for c in svc.get("cap_add") or []]
        if "ALL" in caps or "SYS_ADMIN" in caps:
            findings.append(_f("DC005", f"Service '{name}' adds dangerous capabilities", "HIGH", path, line_of("cap_add"), f"cap_add: {', '.join(caps)}", name,
                               "SYS_ADMIN/ALL capabilities allow many container-escape techniques.", "Add only the minimal capability set."))
        env = svc.get("environment")
        pairs = list(env.items()) if isinstance(env, dict) else [str(e).split("=", 1) for e in (env or []) if "=" in str(e)]
        for p in pairs:
            if len(p) == 2 and p[1] not in (None, "") and SECRET_NAME.search(str(p[0])) and not str(p[1]).startswith("$"):
                findings.append(_f("DC006", f"Service '{name}' has a hard-coded credential-like environment value", "MEDIUM", path, line_of(str(p[0])), f"{p[0]}=[REDACTED]", str(p[0]),
                                   "Credentials in compose files end up in version control.", "Use `env_file` excluded from Git or Docker secrets.", strength="medium"))
    return findings, images
