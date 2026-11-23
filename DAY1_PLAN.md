# DAY 1 IMPLEMENTATION PLAN
# Software Supply Chain Guardian
### Phase 1: Build the Guardian's Eyes – Discovery, Mapping & Detection

## 1. Project Overview

We are building an Agentic AI-powered Software Supply Chain Security platform for the Bosch Global Software Technologies (BGSW) hackathon.

The platform will analyze software repositories, understand their dependencies, generate Software Bills of Materials (SBOMs), detect known vulnerabilities and identify suspicious software supply-chain changes.

Our chosen target application for development and testing is:

**OWASP NodeGoat**
https://github.com/OWASP/NodeGoat

NodeGoat is an intentionally vulnerable Node.js application. It will serve as our initial target repository for testing Guardian's capabilities.

The platform must be developed separately from NodeGoat. Do not modify the original target repository as part of Guardian's implementation.

## 2. Core Project Philosophy

The objective is not to build another conventional vulnerability scanner.

Our solution should follow three principles:

1. Evidence-first detection: Every security finding must have supporting evidence.
2. Context-aware analysis: Understand dependencies, their relationships and how they are used.
3. Deterministic security decisions: Use established security tools and rule engines rather than allowing an LLM to independently determine security status.

The long-term vision is to reduce false-positive alerts and safely validate dependency remediation.

Day 1 focuses on discovery, mapping and detection. Advanced reachability reasoning, policy enforcement and remediation verification will be developed in Day 2.

---

## 3. DAY 1 OBJECTIVES

By the end of Day 1, the system must be able to:

1. Accept a local Git repository or repository ZIP.
2. Inspect its structure and identify supported package manifests.
3. Discover direct and transitive dependencies.
4. Generate a CycloneDX SBOM.
5. Build a dependency relationship graph.
6. Detect known dependency vulnerabilities.
7. Detect suspicious dependency and configuration changes.
8. Collect evidence for every finding.
9. Display results through a functional security dashboard.
10. Export scan results and security reports.

The initial target is NodeGoat, but the architecture must allow additional repositories to be analyzed later.

---

## 4. TECHNICAL ARCHITECTURE

| Component | Technology |
|---|---|
| Frontend | React + Vite |
| Styling | Tailwind CSS |
| Backend | Python + FastAPI |
| Agent orchestration | LangGraph (later integration) |
| SBOM generation | Syft |
| Vulnerability scanning | OSV-Scanner + Trivy |
| Static code analysis | Tree-sitter (initial preparation) |
| Dependency graph | NetworkX |
| Database | PostgreSQL |
| Containerization | Docker |
| Data format | JSON + CycloneDX |

---

## 5. MODULE SPECIFICATION

- **Module 1**: Repository Ingestion (Path / ZIP loader, manifest detection, path traversal protection).
- **Module 2**: Dependency Discovery Engine (`package.json`, `package-lock.json`, direct vs transitive, dev vs prod).
- **Module 3**: SBOM Generator (CycloneDX JSON via Syft).
- **Module 4**: Dependency Graph Engine (NetworkX, JSON export for visual representation).
- **Module 5**: Vulnerability Detection Engine (OSV-Scanner + Trivy subprocess wrappers with deduplication).
- **Module 6**: Suspicious Supply-Chain Change Detection:
  - Typosquatting detection (Levenshtein distance vs popular packages).
  - Lifecycle script analysis (`preinstall`, `install`, `postinstall`, remote curl/wget/bash execution).
  - Dockerfile analysis (mutable tags like `latest`, root user, unpinned images).
  - CI/CD analysis (GitHub Actions mutable tags vs commit SHA, permissions).
  - Change detection (Git history branch comparison against baseline).
- **Module 7**: Unified Evidence Collection (every finding includes finding ID, category, severity, file path, line number, detection tool, raw evidence snippet, explanation, recommended action).
- **Module 8**: FastAPI REST Endpoints.
- **Module 9**: React + Tailwind Cybersecurity UI Dashboard.
