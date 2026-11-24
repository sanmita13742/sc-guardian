# Container Image Vulnerability Scanning Guide

**Document Version:** 2.2.0  
**Status:** Implemented  
**Scope:** Dockerfile discovery, Compose analysis, CI build linking, and Opt-in Trivy image vulnerability scanning  

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

Container image scanning is controlled via environment variables or `scanner.toml`:

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
Container vulnerabilities are converted into `VulnerabilityFinding` records with `asset_type: "container_image"` and merged into `ScanState.vulns`.
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
