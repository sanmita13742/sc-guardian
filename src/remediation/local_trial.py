"""Clone -> apply -> test -> validate -> (then) accept or ignore, for projects scanned from a local folder.

``run_trial`` never touches the real folder. It copies the project into a scratch clone, applies the proposed fix there
(manifest patch + lockfile refresh), rescans the clone, optionally runs the project's own build/tests in the Docker sandbox, and
keeps only the files that changed ("validated files") together with the hashes of the originals. ``accept_validated`` then copies
exactly those tested files into the real folder (after checking the originals are unchanged); ``undo`` is in ``apply_local``.
"""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import stat
import subprocess
import tempfile
import time
import uuid
from pathlib import Path
from typing import Any, Callable, Optional

from config.constants import IGNORED_DIRS
from config.settings import Settings, get_settings
from remediation.apply_local import _safe, _state_file, _store, apply_in_place, applied_record

BLOCKING = ("CRITICAL", "HIGH")
SKIP = set(IGNORED_DIRS) | {".guardian"}


def _rm(path: Path, tries: int = 4) -> bool:
    """Remove a directory tree on Windows too. Copies of OneDrive-synced folders carry the read-only attribute on directories, which
    makes rmdir fail with 'Access denied'; clear it first, retry while sync/antivirus hold files, and finally fall back to ``rmdir /s /q``."""
    path = Path(path)
    for n in range(tries):
        if not path.exists():
            return True
        for cur, dirs, files in os.walk(path):
            for name in dirs + files:
                try:
                    os.chmod(os.path.join(cur, name), stat.S_IWRITE | stat.S_IREAD)
                except OSError:
                    pass
        try:
            os.chmod(path, stat.S_IWRITE | stat.S_IREAD)
        except OSError:
            pass
        shutil.rmtree(path, ignore_errors=True)
        if not path.exists():
            return True
        if os.name == "nt":
            try:
                subprocess.run(["cmd", "/c", "rmdir", "/s", "/q", str(path)], capture_output=True, timeout=60, shell=False)
            except (OSError, subprocess.TimeoutExpired):
                pass
            if not path.exists():
                return True
        time.sleep(0.4 * (n + 1))
    return not path.exists()


def _sha(p: Path) -> Optional[str]:
    try:
        return hashlib.sha256(p.read_bytes()).hexdigest()
    except OSError:
        return None


def _trial_dir(root: Path, rem: dict) -> Path:
    return _store(root) / "trials" / "".join(c if c.isalnum() or c in "-_." else "_" for c in rem["id"])


def _fingerprint(root: Path, rem: dict, with_tests: bool) -> str:
    diff = (rem.get("patch") or {}).get("diff", "")
    manifest = (rem.get("patch") or {}).get("path", "")
    return hashlib.sha256(f"{diff}|{_sha(root / manifest) if manifest else ''}|{with_tests}".encode()).hexdigest()[:20]


def _copy_project(root: Path, dest: Path, max_bytes: int) -> int:
    total = 0

    def ignore(d: str, names: list[str]) -> set[str]:
        nonlocal total
        skip = {n for n in names if n in SKIP or (Path(d) / n).is_symlink()}
        for n in names:
            if n in skip:
                continue
            p = Path(d) / n
            if p.is_file():
                total += p.stat().st_size
        if total > max_bytes:
            raise ValueError(f"project is larger than {max_bytes // (1024 * 1024)} MB (excluding node_modules, .git, build output); validate a smaller folder")
        return skip

    shutil.copytree(root, dest, ignore=ignore, symlinks=False)
    return total


def _finding_keys(vulns: list[dict]) -> dict[tuple, dict]:
    return {(v.get("package_name"), v.get("installed_version"), v.get("primary_id")): v for v in vulns or []}


def _compare(rem: dict, before: list[dict], after: list[dict]) -> dict[str, Any]:
    b, a = _finding_keys(before), _finding_keys(after)
    # the fixed package's version changes, so also match on (package, advisory id)
    a_ids = {(k[0], k[2]) for k in a}
    b_ids = {(k[0], k[2]) for k in b}
    fixed = [v for k, v in b.items() if (k[0], k[2]) not in a_ids]
    new = [v for k, v in a.items() if (k[0], k[2]) not in b_ids]
    remaining = [v for k, v in a.items() if (k[0], k[2]) in b_ids]
    brief = lambda v: {"package": v.get("package_name"), "version": v.get("installed_version"), "id": v.get("primary_id"), "severity": v.get("severity")}  # noqa: E731
    return {"before": len(b), "after": len(a), "fixed": [brief(v) for v in fixed], "remaining": [brief(v) for v in remaining], "new": [brief(v) for v in new]}


def _keep_validated(out: dict, res: dict, clone: Path, tdir: Path, root: Path) -> None:
    """Keep only the tested files, with the hashes of the originals, so Accept applies exactly what was validated."""
    vdir = tdir / "validated"
    files: dict[str, dict] = {}
    for rel in res["backups"]:
        src = clone / rel
        dst = vdir / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        if src.exists():
            shutil.copy2(src, dst)
            files[rel] = {"base_sha": _sha(root / rel), "new_sha": _sha(src)}
    out["files"] = files


def run_trial(root: Path | str, rem: dict, original: dict, settings: Settings | None = None, with_tests: bool = False,
              progress: Optional[Callable[[str], None]] = None) -> dict[str, Any]:
    """Validate ``rem`` on a scratch clone of ``root``. ``original`` is the stored scan result the proposal came from."""
    say = progress or (lambda m: None)
    s = settings or get_settings()
    root = Path(root).resolve()
    tdir = _trial_dir(root, rem)
    tdir.mkdir(parents=True, exist_ok=True)
    for old in tdir.glob("clone*"):  # leftovers of earlier runs; never reused
        _rm(old)
    _rm(tdir / "validated")
    clone = tdir / f"clone-{uuid.uuid4().hex[:8]}"  # unique per run: a stale or concurrent run cannot collide with it
    out: dict[str, Any] = {"status": "failed", "id": rem["id"], "fingerprint": _fingerprint(root, rem, with_tests), "ran_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                           "steps": [], "reasons": [], "warnings": []}
    scratch_db_dir = Path(tempfile.mkdtemp(prefix="guardian-trial-"))
    try:
        if not (rem.get("patch") or {}).get("diff"):
            out["reasons"].append("this proposal has no automatic file change")
            return out
        say("1/4 Cloning the project into a scratch workspace ...")
        size = _copy_project(root, clone, min(s.max_repo_bytes, 200 * 1024 * 1024))
        out["steps"].append({"step": "clone", "ok": True, "detail": f"copied {size // 1024} KB (node_modules, .git and build output excluded)"})

        say("2/4 Applying the fix in the clone and refreshing the lockfile ...")
        res = apply_in_place(clone, rem)
        if res["status"] != "success":
            out["steps"].append({"step": "apply", "ok": False, "detail": res["error"]})
            out["reasons"].append(res["error"])
            return out
        lock = res["lock"]
        out["steps"].append({"step": "apply", "ok": True, "detail": "changed " + ", ".join(res["files"]) + f"; lockfile: {lock['note']}"})
        out["lock"] = lock
        if lock["status"] in ("failed", "tool_missing"):
            out["reasons"].append("the lockfile could not be refreshed, so a rescan would still see the old version: " + lock["note"])

        if rem.get("ecosystem") == "Container":
            return _container_trial(out, res, clone, root, rem, original, s, with_tests, say, tdir)

        say("3/4 Rescanning the clone ...")
        from core.scan_orchestrator import ScanOptions, scan_local_directory
        from storage.database import Database
        used = (original.get("sbom_tool") or {}).get("used")
        opts = ScanOptions(use_nvd=False, use_kev=False, registry_checks=False, metadata_registry=False, investigate=False, remediate=False, use_llm=False,
                           reuse_cached=False, sbom_scanner=used if used in ("syft", "trivy", "builtin") else "auto")
        rescan = scan_local_directory(clone, opts, s, Database(scratch_db_dir / "trial.db"), name="validation-clone")
        if rescan.get("status") == "failed":
            out["steps"].append({"step": "rescan", "ok": False, "detail": rescan.get("error", "rescan failed")})
            out["reasons"].append("the rescan of the patched clone failed")
            return out
        cmp_ = _compare(rem, original.get("vulnerabilities") or [], rescan.get("vulnerabilities") or [])
        out["comparison"] = cmp_
        out["steps"].append({"step": "rescan", "ok": True, "detail": f"{cmp_['before']} -> {cmp_['after']} findings: {len(cmp_['fixed'])} fixed, {len(cmp_['new'])} new"})
        if not cmp_["fixed"]:
            out["reasons"].append("the fix does not remove any finding in the rescan")
        worse = [n for n in cmp_["new"] if str(n.get("severity") or "").upper() in BLOCKING]
        if worse:
            out["reasons"].append(f"the fix introduces {len(worse)} new High/Critical finding(s): " + ", ".join(f"{n['id']} ({n['package']})" for n in worse[:3]))

        say("Checking declared compatibility (registry metadata) ...")
        from remediation.compat import static_compat
        compat = static_compat(rem, root)
        out["compat"] = compat
        bad = [c for c in compat["checks"] if c["status"] == "fail"]
        out["steps"].append({"step": "compatibility", "ok": not bad, "detail": f"{compat['status']}: " + (", ".join(f"{c['name']}" for c in bad) if bad else f"{len(compat['checks'])} check(s)")})
        for c in bad:
            out["reasons"].append(f"incompatible: {c['name']} - {c['detail']}")
        out["warnings"] += [f"{c['name']}: {c['detail']}" for c in compat["checks"] if c["status"] == "warn"]

        tests: dict[str, Any] = {"status": "not_run", "reason": "build/tests were not requested"}
        if with_tests:
            say("4/4 Running the project's build and tests in the Docker sandbox ...")
            tests = _run_tests(s, clone, root, rem, say)
            if tests["status"] == "failed" and (tests.get("baseline") or {}).get("status") != "failed":
                out["reasons"].append("the project's tests pass without the fix but fail with it")
        out["tests"] = tests
        if tests["status"] == "failed" and (tests.get("baseline") or {}).get("status") == "failed":
            out["warnings"].append("the project's tests fail both with and without the fix, so they cannot confirm compatibility")
        elif tests["status"] in ("not_run", "skipped", "error"):
            out["warnings"].append("compatibility was not confirmed by the project's tests: " + str(tests.get("reason") or "not run"))
        out["steps"].append({"step": "tests", "ok": tests["status"] in ("passed", "not_run", "skipped") or (tests["status"] == "failed" and (tests.get("baseline") or {}).get("status") == "failed"),
                             "detail": f"{tests['status']}: {tests.get('reason') or tests.get('attribution') or ''}".strip(": ")})

        _keep_validated(out, res, clone, tdir, root)
        out["status"] = "passed" if not out["reasons"] else "failed"
        return out
    except Exception as e:  # noqa: BLE001
        out["reasons"].append(f"validation could not complete: {type(e).__name__}: {str(e)[:200]}")
        return out
    finally:
        _rm(clone)
        _rm(_store(clone))
        _rm(scratch_db_dir)
        try:
            (tdir / "result.json").write_text(json.dumps(out, indent=2, default=str), encoding="utf-8")
        except OSError:
            pass


def _container_trial(out: dict, res: dict, clone: Path, root: Path, rem: dict, original: dict, s: Settings, allowed: bool,
                     say: Callable[[str], None], tdir: Path) -> dict[str, Any]:
    """Container proposal: build the patched Dockerfile in the clone, scan the built image with Trivy, compare OS-package findings."""
    from containers.trivy_image_scanner import parse_trivy_image_json
    from core.safe_env import scrubbed_env
    from sandbox.runner import docker_status
    from sbom.tool_locator import find_tool
    rel = (rem.get("patch") or {}).get("path", "")
    ds, trivy = docker_status(), find_tool("trivy")
    why = ("verification was not requested" if not allowed else ds["reason"] if not ds["available"] else "Trivy is not installed" if not trivy else "")
    if why:
        out["steps"].append({"step": "image build and rescan", "ok": True, "detail": f"skipped: {why}"})
        out["warnings"].append(f"the fix was not verified (building the image and rescanning it needs Docker and Trivy): {why}")
        _keep_validated(out, res, clone, tdir, root)
        out["status"] = "passed" if not out["reasons"] else "failed"
        return out
    dockerfile = clone / rel
    ctx_dir = dockerfile.parent  # build context: the Dockerfile's own folder (the project root for a root-level Dockerfile)
    tag = f"guardian-trial-{uuid.uuid4().hex[:10]}"
    env = scrubbed_env()
    try:
        say("Building the patched image from the clone (runs the project's Dockerfile) ...")
        b = subprocess.run([ds["exe"], "build", "-t", tag, "-f", str(dockerfile), str(ctx_dir)], capture_output=True, text=True, encoding="utf-8", errors="replace",
                           timeout=1500, shell=False, env=env)
        if b.returncode != 0:
            tail = "\n".join((b.stdout + "\n" + b.stderr).strip().splitlines()[-12:])
            out["steps"].append({"step": "image build", "ok": False, "detail": tail[-400:]})
            out["reasons"].append("the patched image does not build: " + tail.splitlines()[-1][:200] if tail else "the patched image does not build")
            return out
        out["steps"].append({"step": "image build", "ok": True, "detail": f"built {tag}"})
        say("Scanning the built image with Trivy ...")
        t = subprocess.run([trivy, "image", "--quiet", "--format", "json", "--scanners", "vuln", "--timeout", "15m", tag], capture_output=True, text=True,
                           encoding="utf-8", errors="replace", timeout=1200, shell=False, env=env)
        after = [f.to_dict() for f in parse_trivy_image_json(t.stdout, tag, rel) if f.package_type == "os_pkg"]
        if t.returncode not in (0, 1) or (not t.stdout.strip()):
            out["steps"].append({"step": "image rescan", "ok": False, "detail": (t.stderr or "trivy produced no output")[-300:]})
            out["reasons"].append("the rebuilt image could not be scanned: " + (t.stderr or "no output")[-160:])
            return out
        before = [v for v in original.get("vulnerabilities") or [] if v.get("asset_type") == "container_image"
                  and (v.get("container_details") or {}).get("source_file") == rel and (v.get("container_details") or {}).get("package_type") == "os_pkg"]
        key = lambda v: (v.get("package_name"), v.get("primary_id") or v.get("vuln_id"))  # noqa: E731
        b_keys, a_keys = {key(v) for v in before}, {key(v) for v in after}
        brief = lambda v: {"package": v.get("package_name"), "version": v.get("installed_version"), "id": v.get("primary_id") or v.get("vuln_id"), "severity": v.get("severity")}  # noqa: E731
        fixed = [brief(v) for v in before if key(v) not in a_keys]
        new = [brief(v) for v in after if key(v) not in b_keys]
        out["comparison"] = {"before": len(before), "after": len(after), "fixed": fixed, "remaining": [brief(v) for v in after if key(v) in b_keys], "new": new}
        out["steps"].append({"step": "image rescan", "ok": True, "detail": f"{len(before)} -> {len(after)} OS-package findings: {len(fixed)} fixed, {len(new)} new"})
        if not fixed:
            out["reasons"].append("the rebuilt image still has every OS-package finding: the distribution repository has not published the fixes yet")
        worse = [n for n in new if str(n.get("severity") or "").upper() in BLOCKING]
        if worse:
            out["reasons"].append(f"the rebuilt image has {len(worse)} new High/Critical OS-package finding(s)")
        out["tests"] = {"status": "not_run", "reason": "image build and rescan replace the language test run for container changes"}
        _keep_validated(out, res, clone, tdir, root)
        out["status"] = "passed" if not out["reasons"] else "failed"
        return out
    finally:
        try:
            subprocess.run([ds["exe"], "rmi", "-f", tag], capture_output=True, timeout=120, shell=False, env=env)
        except (OSError, subprocess.TimeoutExpired):
            pass


def tests_possible(root: Path | str, rem: dict) -> tuple[bool, str]:
    """Can this project's own build/tests run in the Docker sandbox? (False, reason) when not."""
    from sandbox.runner import detect_recipe, docker_status
    ds = docker_status()
    if not ds["available"]:
        return False, ds["reason"]
    if rem.get("ecosystem") == "Container":
        from sbom.tool_locator import find_tool
        return (True, "") if find_tool("trivy") else (False, "Trivy is not installed (needed to rescan the rebuilt image)")
    eco = rem.get("ecosystem") or (rem.get("target") or {}).get("ecosystem")
    if not detect_recipe(Path(root), eco, rem.get("service") or "."):
        return False, f"no recognised build/test recipe for {eco} in this project"
    return True, ""


def _run_tests(s: Settings, clone: Path, root: Path, rem: dict, say: Callable[[str], None]) -> dict[str, Any]:
    from sandbox.runner import INSTALL_TIMEOUT, TEST_TIMEOUT, _run, detect_recipe, docker_status
    ds = docker_status()
    if not ds["available"]:
        return {"status": "skipped", "reason": ds["reason"]}
    eco = rem.get("ecosystem") or (rem.get("target") or {}).get("ecosystem")
    recipe = detect_recipe(clone, eco, rem.get("service") or ".")
    if not recipe:
        return {"status": "skipped", "reason": f"no recognised build/test recipe for {eco} in this project (commands are never guessed)"}
    say(f"Installing dependencies in {recipe['image']} ...")
    inst = _run(ds["exe"], clone, recipe, "install", INSTALL_TIMEOUT)
    if inst["exit_code"] != 0:
        return {"status": "error", "reason": "dependency installation failed in the sandbox", "recipe": recipe, "runs": [inst]}
    say("Running the tests with the network disabled ...")
    test = _run(ds["exe"], clone, recipe, "test", TEST_TIMEOUT)
    out: dict[str, Any] = {"status": "passed" if test["exit_code"] == 0 else "failed", "recipe": recipe, "runs": [inst, test]}
    if test["exit_code"] != 0:  # was it already failing before the fix?
        say("Tests failed: running the unpatched project to see whether that pre-existed ...")
        base = Path(tempfile.mkdtemp(prefix="guardian-base-"))
        try:
            _copy_project(root, base / "p", 200 * 1024 * 1024)
            binst = _run(ds["exe"], base / "p", recipe, "install", INSTALL_TIMEOUT)
            btest = _run(ds["exe"], base / "p", recipe, "test", TEST_TIMEOUT) if binst["exit_code"] == 0 else None
            out["baseline"] = {"status": "passed" if btest and btest["exit_code"] == 0 else "failed", "runs": [binst] + ([btest] if btest else [])}
            out["attribution"] = "the same failure occurs without the fix (pre-existing)" if out["baseline"]["status"] == "failed" else "the project passes without the fix: the fix likely broke a test"
        finally:
            _rm(base)
    return out


def accept_validated(root: Path | str, rem: dict) -> dict[str, Any]:
    """Copy the files that passed validation into the real folder (originals backed up first, unchanged-since-trial check)."""
    root = Path(root).resolve()
    trial = _load_any(root, rem)
    if not trial or trial.get("status") != "passed":
        return {"status": "error", "error": "This proposal has not passed validation. Validate it first."}
    if applied_record(root, rem):
        return {"status": "error", "error": "Already applied. Use Undo to revert it."}
    vdir = _trial_dir(root, rem) / "validated"
    files = trial.get("files") or {}
    for rel, h in files.items():
        if _sha(root / rel) != h["base_sha"]:
            return {"status": "error", "error": f"`{rel}` changed since it was validated. Re-run validation before accepting."}
        if not (vdir / rel).exists():
            return {"status": "error", "error": f"validated copy of `{rel}` is missing; re-run validation."}
    stamp = time.strftime("%Y%m%dT%H%M%S")
    bdir = _store(root) / "backups" / f"{rem['id']}-{stamp}"
    backups: dict[str, str] = {}
    written: list[str] = []
    try:
        for rel in files:
            dst = _safe(root, rel)
            if dst.exists():
                b = bdir / rel
                b.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(dst, b)
                backups[rel] = str(b)
        for rel in files:
            shutil.copy2(vdir / rel, _safe(root, rel))
            written.append(rel)
    except OSError as e:
        for rel in written:
            if rel in backups:
                shutil.copy2(backups[rel], root / rel)
        return {"status": "error", "error": f"Could not write the files: {e}"}
    rec = {"status": "success", "id": rem["id"], "title": rem.get("title", ""), "files": list(files), "lock": trial.get("lock") or {}, "backup_dir": str(bdir), "backups": backups,
           "applied_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "validated": True,
           "fixed": (trial.get("comparison") or {}).get("fixed") or []}
    sf = _state_file(root, rem)
    sf.parent.mkdir(parents=True, exist_ok=True)
    sf.write_text(json.dumps(rec, indent=2), encoding="utf-8")
    return rec


def _load_any(root: Path, rem: dict) -> Optional[dict]:
    """The stored result for the current files regardless of whether tests were part of it."""
    try:
        res = json.loads((_trial_dir(root, rem) / "result.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    ok = res.get("fingerprint") in (_fingerprint(root, rem, False), _fingerprint(root, rem, True))
    return res if ok else None


def trial_record(root: Path | str, rem: dict) -> Optional[dict]:
    """The stored validation result of a proposal, even after the files changed (used by the Fix Report)."""
    try:
        return json.loads((_trial_dir(Path(root).resolve(), rem) / "result.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def latest_trial(root: Path | str, rem: dict) -> Optional[dict]:
    return _load_any(Path(root).resolve(), rem)


def discard_trial(root: Path | str, rem: dict) -> None:
    _rm(_trial_dir(Path(root).resolve(), rem))
