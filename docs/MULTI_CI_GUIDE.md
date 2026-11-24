# Multi-CI Platform Integration Guide

**Document Version:** 2.2.0  
**Status:** Implemented  
**Scope:** GitHub Actions, GitLab CI/CD, Jenkins, CircleCI, Azure Pipelines  

---

## 1. Overview & Architectural Principle

SC Guardian provides static, zero-code-execution security analysis of CI/CD configuration files across 5 major enterprise CI platforms:
1. **GitHub Actions** (`.github/workflows/*.yml`)
2. **GitLab CI/CD** (`.gitlab-ci.yml`, `**/.gitlab-ci.yml`)
3. **Jenkins** (`Jenkinsfile`, `Jenkinsfile.*`, `*.jenkinsfile`)
4. **CircleCI** (`.circleci/config.yml`)
5. **Azure Pipelines** (`azure-pipelines.yml`, `.azure-pipelines/**/*.yml`)

CI pipeline analysis operates under strict invariants:
- **Zero Arbitrary Execution:** Configuration files are parsed via static AST, PyYAML, or regex tokenization; no build scripts, pipeline jobs, or docker commands are ever executed.
- **Provider-Adapter Architecture:** Each CI platform is encapsulated by a dedicated adapter implementing `BaseCIAdapter`.
- **Unified Domain Model:** All platform parsers produce canonical `UnifiedPipeline` objects with normalized `UnifiedJob`, `UnifiedStep`, and `CIDockerBuild` models.
- **CI-to-Container Bridge:** Container build commands (`docker build`, `kaniko`, `buildah`, `Docker@2`) are extracted to inform container security analysis.

---

## 2. CI Provider Adapter Architecture

```
src/pipeline_analysis/ci_adapters/
├── __init__.py               # Public exports
├── base.py                   # BaseCIAdapter abstract interface & shared utilities
├── registry.py               # CIAdapterRegistry & analyze_ci_pipeline dispatcher
├── github_actions.py         # GitHub Actions adapter (AST + security rules)
├── gitlab_ci.py              # GitLab CI/CD adapter (.gitlab-ci.yml parser)
├── jenkins.py                # Jenkins adapter (Declarative & Scripted Groovy)
├── circleci.py               # CircleCI adapter (.circleci/config.yml parser)
└── azure_pipelines.py        # Azure DevOps Pipelines adapter
```

### 2.1 Unified Model Schema (`src/pipeline_analysis/ci_models.py`)

* **`UnifiedPipeline`**: Canonical representation containing platform ID, file path, stages, jobs, triggers, external dependencies, container images, security findings, and discovered Docker builds.
* **`CIDockerBuild`**: Captures Dockerfile path, context directory, target image tag, build arguments, and CI job name.
* **`UnifiedJob`**: Captures job name, stage, runner/executor environment, steps, background services, and container builds.

---

## 3. Platform Rule Catalog

### 3.1 GitHub Actions (`github_actions.py`)
- **`GHA001`**: Action is not pinned to a 40-character commit SHA.
- **`GHA002`**: Checking out untrusted PR head in a privileged workflow (`pull_request_target` / `workflow_run`).
- **`GHA003`**: Script injection: untrusted event data expanded directly inside a `run` step.
- **`GHA004`**: Missing explicit token permissions or over-broad `write-all` permissions.
- **`GHA005`**: Passing all secrets to a reusable workflow (`secrets: inherit`).
- **`GHA006`**: Running untrusted pull request code on self-hosted runners.
- **`GHA007`**: Remote script piped into a shell (`curl | sh`).
- **`GHA008`**: TLS verification disabled (`--insecure`).
- **`GHA009`**: Deprecated, injectable `::set-env::` or `::add-path::` commands.
- **`GHA010`**: A secret is echoed in a run step.
- **`GHA012`**: Outdated action major version running on deprecated Node runtime.

### 3.2 GitLab CI/CD (`gitlab_ci.py`)
- **`GL001`**: Unpinned default or job container image (e.g., `image: python:latest`).
- **`GL002`**: Privileged Docker-in-Docker service (`docker:dind` or `privileged: true`).
- **`GL003`**: Remote include template fetched over plain HTTP (`include: remote: 'http://...'`).
- **`GL004`**: Remote script piped into shell in `script` or `before_script` (`curl ... | sh`).
- **`GL005`**: TLS verification disabled (`--insecure`, `GIT_SSL_NO_VERIFY: "true"`).
- **`GL006`**: Untrusted GitLab CI variable expanded directly in script (`$CI_MERGE_REQUEST_TITLE`).
- **`GL007`**: `CI_JOB_TOKEN` printed to logs in shell commands.

### 3.3 Jenkins (`jenkins.py`)
- **`JNK001`**: Unpinned Jenkins Docker agent image (`image 'node:latest'`).
- **`JNK002`**: Remote script piped into shell in `sh` or `bat` steps.
- **`JNK003`**: Potential plain-text secret inside Jenkins step command without `withCredentials`.
- **`JNK004`**: Unsafe Groovy GString interpolation with build params inside `sh` step (`sh "echo ${params.FOO}"`).
- **`JNK005`**: TLS verification disabled or insecure download in Jenkins shell step.

### 3.4 CircleCI (`circleci.py`)
- **`CIR001`**: Unpinned or volatile orb version (`orb@volatile` or floating major tag).
- **`CIR002`**: Unpinned Docker executor image (`image: cimg/python:latest`).
- **`CIR003`**: Remote script piped into shell in `run:` step.
- **`CIR004`**: TLS verification disabled or plain HTTP download.

### 3.5 Azure Pipelines (`azure_pipelines.py`)
- **`AZ001`**: Task missing explicit version specification (missing `@` or floating version).
- **`AZ002`**: Remote script piped into shell in inline script step.
- **`AZ003`**: Untrusted Azure DevOps variable expanded in inline script (`$(Build.SourceVersionMessage)`).
- **`AZ004`**: TLS verification disabled or plain HTTP download.

### 3.6 Universal Secret Detection
- **`SEC001`**: Committed API key, private key, or credential literal detected in pipeline configuration.

---

## 4. Bridge to Container Discovery

When CI pipelines define image build directives, the adapters extract them into `CIDockerBuild` records:
- **Docker CLI**: `docker build -t myorg/api:1.0 -f Dockerfile.prod .`
- **Kaniko**: `/kaniko/executor --dockerfile=Dockerfile --destination=registry/img:tag`
- **Buildah**: `buildah bud -t tag -f Dockerfile .`
- **Azure Tasks**: `task: Docker@2` (`command: buildAndPush`, `dockerfile: '...'`, `repository: '...'`, `tags: '...'`)
- **GitHub Actions**: `uses: docker/build-push-action@...`

These directives feed directly into SC Guardian's `containers.discovery` engine, linking Dockerfiles in the repository with the exact image tags and CI jobs that produce them. When container scanning is enabled, the OS packages found in those images can receive Dockerfile remediation proposals (see [CONTAINER_SCANNING.md](CONTAINER_SCANNING.md), section 6).
