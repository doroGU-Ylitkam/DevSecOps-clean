# DevSecOps Pipeline Prototype
**Bachelor Thesis:** Development of a method for automated vulnerability detection in the DevSecOps process

---

## Project Directory Structure

```
devsecops-prototype/
│
├── Jenkinsfile                          # CI/CD pipeline definition (11 stages)
├── pom.xml                              # Maven build + security plugin config
├── README.md
│
├── docker/
│   └── Dockerfile                       # Multi-stage, distroless, non-root image
│
├── k8s/
│   ├── deployment.yaml                  # Kubernetes Deployment (test env)
│   └── service.yaml                     # Kubernetes ClusterIP Service
│
├── src/
│   ├── main/java/com/example/app/
│   │   ├── Application.java             # Spring Boot entry point
│   │   └── HealthController.java        # Sample REST endpoints for DAST target
│   └── test/java/com/example/app/
│       └── HealthControllerTest.java    # Unit tests (JaCoCo coverage)
│
├── security/
│   ├── config/
│   │   └── scanner_config.yaml          # Central tool configuration
│   │
│   ├── orchestrator/
│   │   └── security_orchestrator.py     # [SCRIPT 1] Run & normalise scanners
│   │
│   ├── merger/
│   │   └── report_merger.py             # [SCRIPT 2] Merge + deduplicate reports
│   │
│   ├── triage/
│   │   └── vulnerability_triage.py      # [SCRIPT 3] Priority scoring algorithm
│   │
│   └── reporter/
│       └── report_generator.py          # [SCRIPT 4] HTML + JSON final report
│
└── reports/                             # Generated at runtime (git-ignored)
    ├── sonarqube-report.json
    ├── dependency-check-normalized.json
    ├── trivy-normalized.json
    ├── zap-report.json
    ├── merged-vulnerabilities.json
    ├── triaged-vulnerabilities.json
    ├── final-vulnerability-report.json
    └── final-vulnerability-report.html  # ← Published by Jenkins HTML Publisher
```

---

## Component Interaction Overview

```
SOURCE CODE
    │
    ▼
[Stage 1] Checkout ──────────────────────────────────────────────────
    │
    ▼
[Stage 2] Maven Build (mvn clean package)
    │
    ▼
[Stage 3] Unit Tests + JaCoCo Coverage
    │
    ▼
[Stage 4] SAST ── SonarQube ──► security_orchestrator.py ──► sonarqube-report.json
    │                                    (REST API fetch + normalise)
    ▼
[Stage 5] Dep. Scan ── OWASP DC ──► security_orchestrator.py ──► dep-check-normalized.json
    │                                    (parse raw JSON + normalise)
    ▼
[Stage 6] Docker Build ── builds ${DOCKER_IMAGE}:${BUILD_NUMBER}
    │
    ▼
[Stage 7] Container Scan ── Trivy ──► security_orchestrator.py ──► trivy-normalized.json
    │                                    (parse raw JSON + normalise)
    ▼
[Stage 8] Deploy to Kubernetes test namespace
    │
    ▼
[Stage 9] DAST ── OWASP ZAP ──► security_orchestrator.py ──► zap-report.json
    │                                    (spider + active scan + normalise)
    ▼
[Stage 10] Triage
    │   report_merger.py
    │   ├── Load all 4 normalised reports
    │   ├── Flat-merge into single list
    │   ├── Deduplicate (CVE-ID / title+component fingerprint)
    │   └── merged-vulnerabilities.json
    │
    │   vulnerability_triage.py
    │   ├── PriorityScore = CVSS + Exploitability + SystemImpact
    │   ├── Sort by priority score (descending)
    │   └── triaged-vulnerabilities.json
    │
    ▼
[Stage 11] Report
    │   report_generator.py
    │   ├── final-vulnerability-report.json
    │   └── final-vulnerability-report.html  (published to Jenkins)
    │
    ▼
  Jenkins: Archive artifacts, Publish HTML, Email on failure
```

---

## Priority Score Formula

```
PriorityScore = CVSS_Score + Exploitability_Score + SystemImpact_Score
```

| Component | Range | Description |
|---|---|---|
| CVSS_Score | 0.0 – 10.0 | NVD base score from scanner |
| Exploitability | 0.0 – 5.0 | Based on severity; +0.5 for DAST-confirmed; +0.5 if multi-scanner |
| SystemImpact | 1.0 – 3.0 | 3.0 ZAP (live), 2.5 SonarQube (code), 2.0 Trivy/DC (library) |

| Priority Label | Score Threshold | Action |
|---|---|---|
| 🔴 IMMEDIATE | ≥ 14.0 | Block deployment, fix now |
| 🟠 HIGH | ≥ 9.0 | Fix in current sprint |
| 🟡 MEDIUM | ≥ 5.0 | Plan for next release |
| 🟢 LOW | < 5.0 | Track in backlog |

---

## Quick Start (local demo)

```bash
# 1. Start infrastructure
docker-compose up -d sonarqube jenkins

# 2. Create test reports directory
mkdir -p reports

# 3. Run orchestrator on sample data
python3 security/orchestrator/security_orchestrator.py \
    --tool dependency-check \
    --input sample-data/dependency-check-report.json \
    --output reports/dependency-check-normalized.json

# 4. Merge reports
python3 security/merger/report_merger.py \
    --inputs reports/*.json \
    --output reports/merged-vulnerabilities.json

# 5. Triage
python3 security/triage/vulnerability_triage.py \
    --input  reports/merged-vulnerabilities.json \
    --output reports/triaged-vulnerabilities.json

# 6. Generate final report
python3 security/reporter/report_generator.py \
    --input   reports/triaged-vulnerabilities.json \
    --output  reports/final-vulnerability-report.html \
    --json    reports/final-vulnerability-report.json \
    --build   1 --app spring-boot-app --version 1.0

# Open reports/final-vulnerability-report.html in your browser
```

---

## Security Tools Summary

| Tool | Type | Stage | Output |
|---|---|---|---|
| SonarQube | SAST | 4 | Code vulnerabilities & hotspots |
| OWASP Dependency-Check | SCA | 5 | CVEs in third-party libraries |
| Trivy | Container | 7 | OS + library CVEs in Docker image |
| OWASP ZAP | DAST | 9 | Runtime HTTP attack surface |
