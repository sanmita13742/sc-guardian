"""CI/CD pipeline analysis: GitHub Actions (structured) and GitLab CI / Jenkins / CircleCI / Azure Pipelines (script-level).

Rules target how supply-chain attacks actually reach pipelines: mutable action references, privileged triggers that check out untrusted code,
script injection through event data, over-broad token permissions, self-hosted runners on public PRs, remote scripts piped into shells, and
committed credentials. Files are parsed, never executed.
"""
from __future__ import annotations

import re
from typing import Any, Optional

import yaml

from pipeline_analysis.dockerfile import INSECURE, PIPE_TO_SHELL
from pipeline_analysis.models import SECRET_LITERAL, PipelineFinding, redact_line

SHA40 = re.compile(r"^[0-9a-f]{40}$")
FIRST_PARTY = ("actions/", "github/", "docker/", "aws-actions/", "azure/", "google-github-actions/", "hashicorp/")
# first-party actions whose older majors run on end-of-life Node runtimes or were shut down by GitHub (table reviewed 2026-11)
DEPRECATED_BELOW = {"actions/checkout": 4, "actions/setup-node": 4, "actions/cache": 4, "actions/upload-artifact": 4, "actions/download-artifact": 4, "actions/setup-python": 5,
                    "actions/setup-java": 4, "actions/setup-go": 5, "actions/github-script": 7}
UNTRUSTED_TRIGGERS = {"pull_request_target", "workflow_run", "issue_comment", "issues", "pull_request_review", "pull_request_review_comment", "discussion", "discussion_comment"}
INJECTABLE = re.compile(r"\$\{\{\s*(github\.event\.(issue|pull_request|comment|review|review_comment|discussion|head_commit|commits|pages|inputs|client_payload)[\w.\[\]*\-]*"
                        r"|github\.head_ref|github\.event\.workflow_run\.(head_branch|head_commit|display_title)[\w.]*|inputs\.[\w\-]+)\s*\}\}", re.I)
INJECTABLE_FIELDS = re.compile(r"(title|body|name|label|message|ref|email|head_ref|head_branch|display_title|login|description|comment|inputs|client_payload)", re.I)


def _f(rule, title, sev, eco, file, line, snippet, subject, why, fix, strength="high", refs=None, **extra) -> PipelineFinding:
    return PipelineFinding(rule_id=rule, category="ci", ecosystem=eco, title=title, severity=sev, file=file, line=line, snippet=redact_line(snippet.strip())[:200], subject=subject,
                           why=why, remediation=fix, evidence_strength=strength, references=refs or [], extra=extra)


def _line_index(text: str) -> list[str]:
    return text.splitlines()


def _find(lines: list[str], needle: str, start: int = 0) -> int:
    for n in range(start, len(lines)):
        if needle in lines[n]:
            return n + 1
    return 0


def parse_action_ref(uses: str) -> Optional[dict]:
    if not isinstance(uses, str) or uses.startswith(("./", "docker://")):
        return {"kind": "docker" if str(uses).startswith("docker://") else "local", "uses": uses, "name": uses, "ref": None, "pinned": str(uses).startswith("docker://") and "@sha256:" in uses}
    m = re.match(r"^([\w.\-]+/[\w.\-]+)((?:/[\w.\-/]+)?)@(\S+)$", uses)
    if not m:
        return None
    repo, sub, ref = m.group(1), m.group(2), m.group(3)
    return {"kind": "action", "uses": uses, "name": repo, "path": sub, "ref": ref, "pinned": bool(SHA40.match(ref)), "first_party": repo.lower().startswith(FIRST_PARTY)}


def analyze_github_workflow(text: str, path: str) -> tuple[list[PipelineFinding], list[dict]]:
    findings: list[PipelineFinding] = []
    actions: list[dict] = []
    try:
        data = yaml.safe_load(text)
    except Exception:
        return findings, actions
    if not isinstance(data, dict):
        return findings, actions
    lines = _line_index(text)
    on = data.get("on", data.get(True))  # PyYAML turns the key `on` into boolean True
    triggers = set(on) if isinstance(on, (dict, list)) else ({on} if isinstance(on, str) else set())
    triggers = {str(t) for t in triggers}
    untrusted = bool(triggers & UNTRUSTED_TRIGGERS)
    pr_trigger = bool(triggers & {"pull_request", "pull_request_target"})
    perms = data.get("permissions")
    jobs = data.get("jobs") if isinstance(data.get("jobs"), dict) else {}

    if perms is None and not any(isinstance(j, dict) and j.get("permissions") is not None for j in jobs.values()):
        findings.append(_f("GHA004", "No explicit token permissions (defaults may be read-write)", "LOW", "GitHub Actions", path, 1, "(no `permissions:` key)", "permissions",
                           "Without an explicit `permissions:` block the GITHUB_TOKEN gets the repository/org default, which can include write access.",
                           "Add a top-level `permissions: contents: read` and grant extra scopes per job.", strength="medium",
                           refs=["https://docs.github.com/actions/security-guides/automatic-token-authentication"]))
    if perms in ("write-all",) or (isinstance(perms, dict) and any(v == "write" for v in perms.values()) and untrusted):
        findings.append(_f("GHA004", "Over-broad GITHUB_TOKEN permissions", "HIGH", "GitHub Actions", path, _find(lines, "permissions"), "permissions: " + (perms if isinstance(perms, str) else "write scopes"),
                           "permissions", "A write-capable token in a workflow reachable by untrusted input lets an attacker modify the repository.", "Use least privilege (`contents: read`)."))

    for jname, job in jobs.items():
        if not isinstance(job, dict):
            continue
        runs_on = job.get("runs-on")
        ro = " ".join(map(str, runs_on)) if isinstance(runs_on, list) else str(runs_on or "")
        if "self-hosted" in ro and pr_trigger:
            findings.append(_f("GHA006", f"Job '{jname}' runs untrusted pull-request code on a self-hosted runner", "HIGH", "GitHub Actions", path, _find(lines, "self-hosted"), f"runs-on: {ro}", jname,
                               "Self-hosted runners persist state and often have network access to internal systems; a malicious PR can pivot from them.",
                               "Use ephemeral GitHub-hosted runners for pull_request workflows, or require approval for outside contributors."))
        if job.get("secrets") == "inherit":
            findings.append(_f("GHA005", f"Job '{jname}' passes all secrets to a reusable workflow", "MEDIUM", "GitHub Actions", path, _find(lines, "secrets: inherit"), "secrets: inherit", jname,
                               "Every repository secret is exposed to the called workflow.", "Pass only the specific secrets required.", strength="medium"))
        if isinstance(job.get("uses"), str):  # reusable workflow
            ref = parse_action_ref(job["uses"])
            if ref and ref.get("kind") == "action":
                actions.append({**ref, "file": path, "line": _find(lines, job["uses"]), "job": jname, "reusable_workflow": True})
        steps = job.get("steps") or []
        checkout_head = False
        for st_ in steps:
            if not isinstance(st_, dict):
                continue
            uses, run, withd = st_.get("uses"), st_.get("run"), st_.get("with") or {}
            if isinstance(uses, str):
                ref = parse_action_ref(uses)
                ln = _find(lines, uses)
                if ref:
                    actions.append({**ref, "file": path, "line": ln, "job": jname})
                if ref and ref.get("kind") == "action" and not ref["pinned"]:
                    branchy = ref["ref"] in ("main", "master", "latest", "develop", "dev", "trunk")
                    sev = "HIGH" if branchy else ("LOW" if ref.get("first_party") else "MEDIUM")
                    findings.append(_f("GHA001", f"Action '{ref['name']}' is not pinned to a commit SHA", sev, "GitHub Actions", path, ln, f"uses: {uses}", uses,
                                       ("The reference is a moving branch: " if branchy else "Tags can be moved or re-pointed: ") + "a compromised upstream changes what your pipeline runs "
                                       "(this is how the tj-actions/changed-files supply-chain compromise spread).",
                                       f"Pin to the full 40-character commit SHA (keep the tag in a comment): `uses: {ref['name']}@<sha> # {ref['ref']}`.",
                                       refs=["https://docs.github.com/actions/security-guides/security-hardening-for-github-actions#using-third-party-actions"], third_party=not ref.get("first_party")))
                if ref and ref.get("kind") == "action" and ref["name"].lower() in DEPRECATED_BELOW:
                    mm = re.match(r"^v?(\d+)", ref["ref"] or "")
                    if mm and int(mm.group(1)) < DEPRECATED_BELOW[ref["name"].lower()]:
                        findings.append(_f("GHA012", f"Action '{ref['name']}@{ref['ref']}' is an outdated major version", "MEDIUM", "GitHub Actions", path, ln, f"uses: {uses}", uses + "#outdated",
                                           "This major runs on an end-of-life Node.js runtime or was deprecated/shut down by GitHub; it no longer receives fixes and may stop working.",
                                           f"Upgrade to {ref['name']}@v{DEPRECATED_BELOW[ref['name'].lower()]} or newer (pinned to a commit SHA).", strength="medium"))
                if isinstance(uses, str) and "checkout" in uses:
                    r = str(withd.get("ref", ""))
                    if "pull_request.head" in r or "head_ref" in r or "workflow_run.head" in r:
                        checkout_head = True
                        if triggers & {"pull_request_target", "workflow_run"}:
                            findings.append(_f("GHA002", f"Job '{jname}' checks out untrusted pull-request code in a privileged workflow", "CRITICAL", "GitHub Actions", path, _find(lines, "ref:", max(ln - 1, 0)),
                                               f"{', '.join(sorted(triggers & {'pull_request_target', 'workflow_run'}))} + checkout of the PR head", jname,
                                               "pull_request_target/workflow_run run with repository secrets and a write token; building untrusted PR code there lets any contributor steal them (\"pwn request\").",
                                               "Never check out or run PR head code in these workflows; split into an unprivileged `pull_request` build and a separate privileged workflow that only consumes vetted artifacts.",
                                               refs=["https://securitylab.github.com/resources/github-actions-preventing-pwn-requests/"]))
            if isinstance(run, str):
                ln = _find(lines, run.strip().splitlines()[0][:60]) if run.strip() else 0
                for m in INJECTABLE.finditer(run):
                    if INJECTABLE_FIELDS.search(m.group(0)):
                        findings.append(_f("GHA003", f"Script injection: untrusted event data is expanded inside a `run` step", "HIGH", "GitHub Actions", path, ln, m.group(0), m.group(0),
                                           "The expression is substituted into the shell script *before* it runs, so a crafted issue/PR title or branch name becomes shell code.",
                                           "Pass the value through an intermediate environment variable (`env: TITLE: ${{ ... }}`) and reference it as \"$TITLE\".",
                                           refs=["https://securitylab.github.com/resources/github-actions-untrusted-input/"]))
                        break
                if PIPE_TO_SHELL.search(run):
                    findings.append(_f("GHA007", "Remote script is piped into a shell in a workflow step", "HIGH", "GitHub Actions", path, ln, run.strip().splitlines()[0], "curl|sh",
                                       "Runs whatever the server returns with the job's permissions and secrets.", "Download, verify a pinned checksum/signature, then run."))
                if INSECURE.search(run):
                    findings.append(_f("GHA008", "TLS verification disabled in a workflow step", "MEDIUM", "GitHub Actions", path, ln, run.strip().splitlines()[0], "insecure", "Allows tampering of downloaded tools.", "Remove the insecure flag."))
                if re.search(r"::(set-env|add-path)\b", run):
                    findings.append(_f("GHA009", "Deprecated, injectable `set-env`/`add-path` workflow command", "HIGH", "GitHub Actions", path, ln, run.strip().splitlines()[0], "set-env",
                                       "These commands were disabled because untrusted output can set arbitrary environment variables.", "Write to $GITHUB_ENV / $GITHUB_PATH instead."))
                if re.search(r"echo\s+[\"']?\$\{\{\s*secrets\.", run):
                    findings.append(_f("GHA010", "A secret is echoed in a run step", "MEDIUM", "GitHub Actions", path, ln, "echo ${{ secrets.* }}", "secret echo", "Secrets printed to logs can leak through log retention/forks.", "Never print secrets.", strength="medium"))
    for n, l in enumerate(lines, 1):
        if SECRET_LITERAL.search(l):
            findings.append(_f("SEC001", "A credential appears to be committed in this workflow", "CRITICAL", "GitHub Actions", path, n, l, "credential", "A live-looking token/key is stored in the repository.", "Revoke and rotate it; use encrypted secrets."))
            break
    return findings, actions


def analyze_generic_ci(text: str, path: str) -> tuple[list[PipelineFinding], list[dict]]:
    eco = "CI (generic)"
    name = path.rsplit("/", 1)[-1].lower()
    findings: list[PipelineFinding] = []
    images: list[dict] = []
    for n, raw in enumerate(text.splitlines(), 1):
        l = raw.strip()
        if not l or l.startswith("#") or l.startswith("//"):
            continue
        if PIPE_TO_SHELL.search(l):
            findings.append(_f("CI001", "Remote script is piped into a shell", "HIGH", eco, path, n, l, "curl|sh", "Runs unverified remote content with the pipeline's permissions.", "Download, verify a checksum/signature, then run."))
        if INSECURE.search(l):
            findings.append(_f("CI002", "TLS verification is disabled", "MEDIUM", eco, path, n, l, "insecure", "Allows tampering of downloaded artifacts.", "Remove the insecure flag."))
        m = re.match(r"^(?:-\s*)?image:\s*['\"]?([^\s'\"#]+)", l)
        if m and "$" not in m.group(1):
            from pipeline_analysis.dockerfile import classify_image, split_image
            nm, tag, dig = split_image(m.group(1))
            images.append({"ref": m.group(1), "name": nm, "tag": tag, "digest": dig, "kind": classify_image(nm), "file": path, "line": n, "stage": 0, "final": False})
            if not dig and tag in (None, "latest"):
                findings.append(_f("CI003", "CI job image is not pinned", "MEDIUM", eco, path, n, l, m.group(1), "A floating job image changes what builds run on without a code change.", "Pin a version tag and digest."))
        if re.search(r"remote:\s*['\"]?http://|include:\s*['\"]?http://", l, re.I) or re.search(r"\bhttp://[^\s'\"]+\.(sh|bash|py|ps1)\b", l):
            findings.append(_f("CI004", "Pipeline fetches code over plain HTTP", "HIGH", eco, path, n, l, "http", "Unencrypted downloads can be modified in transit.", "Use HTTPS with a pinned checksum."))
        if SECRET_LITERAL.search(l):
            findings.append(_f("SEC001", "A credential appears to be committed in this pipeline file", "CRITICAL", eco, path, n, l, "credential", "A live-looking token/key is stored in the repository.", "Revoke and rotate it; use the CI secret store."))
    if name == ".gitlab-ci.yml":
        for n, raw in enumerate(text.splitlines(), 1):
            if re.search(r"privileged:\s*true", raw):
                findings.append(_f("CI005", "GitLab runner service runs privileged (Docker-in-Docker)", "MEDIUM", eco, path, n, raw, "privileged", "Privileged DinD gives the job host-level capabilities.", "Prefer rootless builders (Kaniko/Buildah).", strength="medium"))
    return findings, images
