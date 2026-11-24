# Container Image Vulnerability Scanning Guide

**Document Version:** 2.3.0  
**Status:** Implemented  
**Scope:** Dockerfile discovery, Compose analysis, CI build linking, opt-in Trivy image vulnerability scanning, and OS-package remediation with build-and-rescan validation  

---

## 1. Overview & Non-Disruption Principles

SC Guardian incorporates container image security analysis alongside source code dependency scanning.

### Core Architectural Principles
1. **Zero Disruption to Existing Pipeline:** Source SBOM generation (Syft) and source dependency vulnerability detection (OSV-Scanner) remain completely independent and unmodified.
2. **Strictly Opt-In:** Container image vulnerability scanning is disabled by default (`CONTAINER_SCAN_ENABLED=false`).
3. **Failure Isolation:** Container scanning runs in isolated subprocesses with strict timeouts. Missing local Docker daemons, network registry restrictions, or missing Trivy binaries degrade gracefully with warnings and never fail a repository analysis.
4. **Normalized Finding Provenance:** Findings from container images are tagged with `asset_type: "container_image"` (versus `asset_type: "source_dependency"`), preserving image digests, origin Dockerfiles, and package classifications.

---

## 2. Container Asset Discovery

The container subsystem (`src/containers/`) correlates three independent data sources:
1. **Direct Dockerfiles:** Parsed by `pipeline_analysis.dockerfile` (base images, multi-stage targets, exposed ports).
2. **Compose Files:** Services, base images, and local build contexts.
3. **CI Pipeline Docker Builds:** Build commands (`docker build`, `kaniko`, `Docker@2`) extracted by Multi-CI adapters.

These are unified into `DiscoveredContainerAsset` records:
- `asset_id`: Stable hash identifying the container asset.
- `source_file`: Path to Dockerfile or compose file.
- `image_tag`: Production tag (e.g. `myorg/api:1.2.0`).
- `base_image`: Upstream base image (e.g. `python:3.11-slim`).
- `associated_ci_jobs`: Pipelines that build this image (e.g. `.gitlab-ci.yml#build-job`).

---

## 3. Configuration & Opt-In Settings

Container image scanning is controlled via environment variables (or an optional `scanner.toml`):

| Setting | Env Variable | Default | Description |
|---|---|---|---|
| `container_scan_enabled` | `CONTAINER_SCAN_ENABLED` | `false` | Enable opt-in Trivy container image scanning. |
| `container_scan_os_packages` | `CONTAINER_SCAN_OS_PKGS` | `true` | Scan operating system packages (Debian, Alpine, RPM). |
| `container_scan_app_packages` | `CONTAINER_SCAN_APP_PKGS` | `true` | Scan embedded application runtime packages. |
| `container_scan_timeout_s` | `CONTAINER_SCAN_TIMEOUT_S` | `180` | Subprocess timeout per image scan. |
| `container_scan_max_images` | `CONTAINER_SCAN_MAX_IMAGES` | `5` | Maximum number of container images to scan per run. |

To enable container scanning during repository analysis:
```bash
# In .env or shell:
CONTAINER_SCAN_ENABLED=true
```

---

## 4. Trivy Container Image Scanner Runner

When enabled, `src/containers/trivy_image_scanner.py` invokes:
```bash
trivy image --format json --quiet --scanners vuln --vuln-type os,library <image_reference>
```

### 4.1 Output Normalization
Trivy JSON output is parsed into normalized `ContainerScanFinding` models:
- **OS-Level Packages:** Classified under `package_type: "os_pkg"` with `os_distribution` (e.g., `libssl1.1` on Debian 11).
- **Application Packages:** Classified under `package_type: "lang_pkg"` (e.g., embedded `requests` or `urllib3` libraries).
- **Layer Diff ID:** Tracks the exact image layer where the vulnerable package originated.
- **CVSS Score & Vector:** Extracted from NVD, RedHat, or GHSA records embedded in Trivy output.

---

## 5. Correlator & Dashboard Integration

### 5.1 Correlator Integration
Container vulnerabilities are converted into complete `VulnerabilityFinding` records (every field the later stages need is filled from the model's defaults) with `asset_type: "container_image"` and merged into `ScanState.vulns`. This also holds for projects that contain only a Dockerfile and no package manifests.
- **Deduplication:** Source vulnerabilities and container vulnerabilities are tracked with distinct compound keys `(cve_id, package_name, asset_type, source_file)`, preventing collision.
- **Risk Scoring:** Scored via `score_vulnerability()`, preserving CVSS severity and attributing container layer details.

### 5.2 Streamlit Dashboard
- **Pipeline & Containers Page (`src/ui/pages/pipeline_page.py`):**
  - **Multi-CI Platforms Tab:** Explore discovered CI files, jobs, stages, and Docker build directives.
  - **Container Assets Tab:** View discovered Dockerfiles, base images, associated CI jobs, and Trivy container vulnerability findings.
- **Vulnerabilities Page (`src/ui/pages/vulns_page.py`):**
  - **Asset Source Filter:** Filter by `All Assets`, `Source Dependencies (OSV)`, or `Container Images (Trivy)`.
  - **Package Class Filter:** Toggle between OS packages (Debian/Alpine/RPM) and application libraries.
  - **Finding Details:** Detailed container metadata card displaying image tag, layer diff ID, package class, and origin Dockerfile.

---

## 6. Remediation of OS packages

Language packages are fixed through their manifests (see the main README). Operating-system packages inside an image are fixed through the **Dockerfile**, and the fix version comes from the **distribution's own security data**, not from a language registry.

### 6.1 Where the fix version comes from
Trivy reports, per finding, the `FixedVersion` for exactly the distro release in the image (for example `2.38.1-5+deb12u1` on Debian 12). SC Guardian records it as the finding's fixed version. There is no separate database: the data is whatever Trivy's distro advisory sources (Debian Security Tracker, Ubuntu, Alpine secdb, Red Hat and others) provide for that release.

### 6.2 What the proposal changes (`src/remediation/container_plan.py`)
One proposal per (Dockerfile, image):
* The OS-package findings that have a published fix are grouped, and a `RUN` layer is inserted **right after the last `FROM`** (the final stage, still root) that upgrades only those packages, using the tool for the detected distro:

| Distro family | Layer |
|---|---|
| Debian, Ubuntu | `apt-get update && apt-get install -y --no-install-recommends --only-upgrade <pkgs> && rm -rf /var/lib/apt/lists/*` |
| Alpine | `apk add --no-cache --upgrade <pkgs>` |
| Red Hat family, Amazon, Oracle, Fedora, Photon, Azure Linux | `dnf upgrade -y <pkgs>` (falling back to `yum update -y <pkgs>`), then clean |

* Package names are validated against a strict pattern before they are written into the Dockerfile. At most 40 packages per layer.
* Findings without a published fix stay open and are listed in the rationale. Application-library findings in the image are fixed through the project's own manifests, not this change.
* **No automatic patch** (a recommendation to rebuild with `--pull` or rebase onto a newer base-image tag instead) when no fixes are published yet, the base is distroless or `scratch` (no package manager), the image is not built from a Dockerfile in the project (for example compose-only or prebuilt), or the distro is not recognised.
* Rebasing onto a newer tag of the same distro is always offered as an alternative: it picks up every fix at once and is the long-term fix.

### 6.3 Validation: build and rescan
Whether the distribution's repository actually has the fixed versions is verified, not assumed. During **Resolve** on a local folder:
1. The patched Dockerfile is built in a scratch clone (`docker build`, context = the Dockerfile's folder).
2. The built image is scanned with Trivy (`--scanners vuln`).
3. OS-package findings before and after are compared: a fix passes only if it removes findings and introduces no new High/Critical ones. A build or scan failure fails the validation with the reason.
4. The temporary image is deleted. Without Docker or Trivy the fix is shown as **unverified** and must be acknowledged before it can be accepted.

Example from testing (Debian 12 base pinned to a June 2023 snapshot): the plan covered 138 findings in 31 packages; the rebuilt image went from 388 to 250 OS-package findings (138 fixed, 0 new). The 250 that remain have no distro fix yet.

### 6.4 Where it appears
* **Remediation page** — the proposal and its Dockerfile diff; **Resolve → Accept & Apply Changes** for local folders.
* **Fix Report** — once applied, the Dockerfile change, the findings it fixed and the build/rescan validation record, with a one-page PDF.
