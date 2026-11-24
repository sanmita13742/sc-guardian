"""Remediation proposals for operating-system packages found inside container images (Debian/Ubuntu, Alpine, RPM family).

The fix version comes from the distro's own security data as reported by Trivy per finding (``FixedVersion`` for exactly that
distro release, e.g. ``1.1.1n-0+deb11u5``), not from a language registry. The change is a ``RUN`` layer in the Dockerfile's final stage that
upgrades just the affected packages with the distro's package manager, using the right tool for the detected distro. Whether that
actually clears the findings depends on the distro repository having published the fix, so it is verified by building the image
and rescanning it (see ``local_trial``); nothing is claimed beforehand.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Any, Optional

from remediation.patchers import unified_diff

APT = {"debian", "ubuntu"}
APK = {"alpine"}
RPM = {"redhat", "centos", "rocky", "almalinux", "alma", "amazon", "oracle", "fedora", "photon", "cbl-mariner", "azurelinux"}
_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9+._:-]{0,100}$")
_FROM = re.compile(r"^\s*FROM\s+", re.I)
MAX_PKGS = 40


def distro_family(distro: Optional[str]) -> Optional[str]:
    d = (distro or "").lower()
    return "apt" if d in APT else "apk" if d in APK else "rpm" if d in RPM else None


def upgrade_instruction(family: str, pkgs: list[str]) -> str:
    names = " ".join(pkgs)
    if family == "apt":
        return f"RUN apt-get update && apt-get install -y --no-install-recommends --only-upgrade {names} && rm -rf /var/lib/apt/lists/*"
    if family == "apk":
        return f"RUN apk add --no-cache --upgrade {names}"
    return f"RUN (command -v dnf >/dev/null 2>&1 && dnf upgrade -y {names} && dnf clean all) || (yum update -y {names} && yum clean all)"


def patch_dockerfile(text: str, path: str, family: str, pkgs: list[str]) -> Optional[dict]:
    """Insert the upgrade layer right after the last FROM (final stage, still root). None when there is no FROM or the layer is already there."""
    nl = "\r\n" if "\r\n" in text else "\n"
    lines = text.split(nl)
    last = max((n for n, ln in enumerate(lines) if _FROM.match(ln)), default=None)
    if last is None:
        return None
    instr = upgrade_instruction(family, pkgs)
    if instr in lines:
        return None
    new = lines[:last + 1] + ["# sc-guardian: upgrade OS packages that have published security fixes", instr] + lines[last + 1:]
    new_text = nl.join(new)
    return {"path": path, "diff": unified_diff(path, text, new_text), "new_text": new_text}


def _higher(a: str, b: str) -> str:
    try:
        from vulnerability.version_matcher import compare
        return a if compare("Debian", a, b) >= 0 else b
    except Exception:  # noqa: BLE001 - unknown scheme: fall back to a stable textual choice (display only; apt upgrades to the repo's newest anyway)
        return max(a, b)


def plan_container_groups(ctx: Any, vulns: list[dict], risks: dict[str, dict], first_id: int, best_risk) -> list[dict]:
    """One proposal per (Dockerfile, image) that has container findings."""
    groups: dict[tuple[str, str], list[dict]] = {}
    for v in vulns:
        if v.get("asset_type") != "container_image":
            continue
        cd = v.get("container_details") or {}
        groups.setdefault((cd.get("source_file") or "", cd.get("image_name") or "image"), []).append(v)
    out: list[dict] = []
    for n, ((source_file, image), fs) in enumerate(sorted(groups.items(), key=lambda kv: -len(kv[1]))):
        os_fs = [f for f in fs if (f.get("container_details") or {}).get("package_type") == "os_pkg"]
        lang_fs = [f for f in fs if f not in os_fs]
        fixable = [f for f in os_fs if f.get("recommended_fix")]
        unfixed = [f for f in os_fs if not f.get("recommended_fix")]
        distro = next(((f.get("container_details") or {}).get("os_distribution") for f in os_fs if (f.get("container_details") or {}).get("os_distribution")), None)
        family = distro_family(distro)
        pkgs: dict[str, dict] = {}
        for f in fixable:
            p = pkgs.setdefault(f["package_name"], {"package": f["package_name"], "from": f["installed_version"], "to": f["recommended_fix"], "kind": "bump"})
            if p["to"] != f["recommended_fix"]:  # several advisories fix the same package at different versions: show the higher one
                p["to"] = _higher(p["to"], f["recommended_fix"])
        names = sorted(n_ for n_ in pkgs if _NAME.match(n_))[:MAX_PKGS]
        label, priority = best_risk(fs, risks)
        rem: dict[str, Any] = {
            "id": f"REM-{first_id + n:03d}", "source_package": image, "root": source_file or image, "ecosystem": "Container", "service": ".",
            "finding_ids": sorted(f["finding_id"] for f in fs), "priority": priority, "risk_label": label, "packages": names[:8], "alternatives": [], "sim": None,
        }
        base_note = ("Distro fix versions come from the distribution's security tracker via Trivy and are specific to this release"
                     + (f" ({distro})" if distro else "") + ".")
        table = "; ".join(f"{pkgs[p]['package']} {pkgs[p]['from']} -> {pkgs[p]['to']}" for p in names[:6]) + (" ..." if len(names) > 6 else "")
        patch = None
        text = ctx.text(source_file) if source_file and not source_file.lower().endswith((".yml", ".yaml")) else None
        distroless = any(k in (image or "").lower() for k in ("distroless", "scratch"))
        if names and family and text and not distroless:
            patch = patch_dockerfile(text, source_file, family, names)
            if patch:
                ctx.originals[source_file] = text  # lets the Validator run `git apply --check` against the real Dockerfile
        if patch:
            rem.update(
                action="upgrade", title=f"Upgrade {len(names)} OS package(s) in {source_file}",
                target={"package": image, "from": f"{len(names)} package(s) with fixes", "to": "distro fixed versions", "ecosystem": distro or "Container"},
                changes=list(pkgs[p] for p in names), patch=patch,
                rationale=(f"{len(fixable)} finding(s) in {len(names)} operating-system package(s) of {image} have fixes published by the distribution. {base_note} "
                           f"Packages: {table}. A `RUN` layer after the final `FROM` upgrades only these packages with the distro package manager "
                           f"({'apt-get --only-upgrade' if family == 'apt' else 'apk --upgrade' if family == 'apk' else 'dnf/yum update'}). "
                           + (f"{len(unfixed)} further finding(s) have no distro fix yet and stay open. " if unfixed else "")
                           + (f"{len(lang_fs)} application-library finding(s) in the image are fixed through the project's own manifests, not this change. " if lang_fs else "")
                           + "Whether the repository has the fixed version is confirmed by building the image and rescanning it during validation."),
                compatibility={"semver_change": "patch", "breaking_risk": "low", "note": "Security updates inside the same distro release; rebuild and run your tests to be sure."},
                rollback=[f"Revert the change: remove the added `RUN` layer from `{source_file}` (`git checkout -- {source_file}`).", "Rebuild the image.", "Re-run the Guardian scan to confirm the previous state."],
                lock_note=None, confidence="medium",
            )
            rem["alternatives"].append({"action": "manual", "note": "Alternatively rebase onto a newer base-image tag (or digest) of the same distro; this picks up every fix at once and is the long-term fix."})
        else:
            why = ("no fixed versions are published yet" if not names else
                   "the base image has no package manager (distroless/scratch)" if distroless else
                   "the image is not built from a Dockerfile in this project" if not text else "the distro's package manager is not recognised" if not family else "the Dockerfile has no FROM line")
            rem.update(
                action="mitigate", title=f"Rebuild or rebase {image} onto a patched base image",
                target={"package": image, "from": None, "to": None}, patch=None, changes=[],
                rationale=(f"{len(os_fs)} OS-package finding(s) in {image}; no automatic Dockerfile change was made because {why}. {base_note} "
                           + (f"Fixes exist for: {table}. " if names else "") + "Rebuild with `--pull` on a newer tag of the same base image, or move to a maintained/slim/distroless base."),
                confidence="low", rollback=["Nothing is changed by this recommendation."],
            )
        out.append(rem)
    return out
