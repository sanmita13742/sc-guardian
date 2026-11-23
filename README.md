# Software Supply Chain Guardian

An Agentic AI-powered Software Supply Chain Security platform built for the Bosch Global Software Technologies (BGSW) hackathon.

The platform analyzes software repositories, maps dependency relationships, generates Software Bills of Materials (SBOMs), detects known vulnerabilities, and identifies suspicious supply-chain configuration changes.

---

## 🎯 Core Philosophy

1. **Evidence-First Detection**: Every security finding must have verifiable supporting evidence (file paths, line numbers, exact code context).
2. **Context-Aware Analysis**: Understand dependencies, their transitive relationships, and deployment environments (production vs. development).
3. **Deterministic Security Decisions**: Use established security tools and rule engines rather than allowing an LLM to independently hallucinate security status.

---

## 🛠️ Architecture & Tech Stack

| Component | Technology | Purpose |
|---|---|---|
| **Frontend** | React + Vite + Tailwind CSS | Cybersecurity dashboard & dependency graph explorer |
| **Backend** | Python + FastAPI | REST APIs, analysis pipelines, job manager |
| **SBOM Generation** | Syft | CycloneDX JSON SBOM creation |
| **Vulnerability Scanning** | OSV-Scanner + Trivy | Dependency vulnerability & config security scans |
| **Dependency Graph** | NetworkX | Directed dependency graph modeling & transitives |
| **Static Code Analysis** | Tree-sitter | Ast parsing & syntax verification |
| **Containerization** | Docker / Docker Compose | Isolated execution environment |

---

## 📁 Project Structure

```text
sc-guardian/
│
├── target-repositories/       # Target applications for analysis (e.g., OWASP NodeGoat)
│   └── nodegoat/
│
├── backend/                  # FastAPI analysis server
│   ├── app/
│   │   ├── main.py
│   │   ├── api/routes/       # API endpoints (repository, discovery, sbom, scan, etc.)
│   │   ├── core/             # Configuration, logging, security
│   │   ├── discovery/        # Manifest & lockfile parsers
│   │   ├── sbom/             # CycloneDX SBOM generation & parsing
│   │   ├── graph/            # NetworkX dependency graph engine
│   │   ├── scanners/         # OSV-Scanner & Trivy integrations
│   │   ├── detection/        # Typosquatting, lifecycle scripts, Dockerfile & CI/CD rules
│   │   ├── evidence/         # Normalized evidence collection engine
│   │   ├── reporting/        # Consolidated security report generator
│   │   └── models/           # Pydantic schemas
│   ├── tests/
│   ├── requirements.txt
│   └── Dockerfile
│
├── frontend/                 # React + Vite security dashboard
│   ├── src/
│   │   ├── components/
│   │   ├── pages/
│   │   ├── services/
│   │   └── App.jsx
│   ├── package.json
│   └── vite.config.js
│
├── artifacts/                # Generated scan artifacts
│   ├── sbom/
│   ├── scans/
│   ├── reports/
│   └── graphs/
│
├── docker-compose.yml
├── DAY1_PLAN.md              # Detailed Day 1 implementation specification
└── README.md
```

---

## 🚀 Target Benchmark

Initial testbed target: [OWASP NodeGoat](https://github.com/OWASP/NodeGoat) - an intentionally vulnerable Node.js/Express application.
The platform analyzes target repositories without modifying their original source code.

---

## 📋 Day 1 Deliverables

- [x] Repository setup and ingestion pipeline
- [ ] Manifest & lockfile parser (npm `package.json` & `package-lock.json`)
- [ ] CycloneDX SBOM generator (Syft integration)
- [ ] Dependency graph constructor (NetworkX)
- [ ] Vulnerability scanner integration (OSV-Scanner & Trivy)
- [ ] Suspicious change detectors (typosquatting, lifecycle scripts, unpinned Docker/Actions)
- [ ] Evidence-first normalized findings engine
- [ ] Interactive dark cybersecurity dashboard (React + Tailwind)
- [ ] Consolidated security reporting & export
