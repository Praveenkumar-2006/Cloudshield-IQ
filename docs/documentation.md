# CloudShield IQ - Project Documentation

**AI-Based Multi-Cloud Security Risk Assessment and Compliance Monitoring Framework**

*Final-Year Information Technology Capstone Project*

---

## Table of Contents

1. [Project Overview & Motivation](#1-project-overview--motivation)
2. [Academic Integrity & Ethical Constraints](#2-academic-integrity--ethical-constraints)
3. [System Architecture & Core Separation of Concerns](#3-system-architecture--core-separation-of-concerns)
4. [Complete Technology Stack Matrix](#4-complete-technology-stack-matrix)
5. [Master Project Phases & Status Matrix](#5-master-project-phases--status-matrix)
6. [Detailed Phase-by-Phase Technical Implementations](#6-detailed-phase-by-phase-technical-implementations)
   - [Phase 0: Environment Setup & Toolchains](#phase-0-environment-setup--toolchains)
   - [Phase 1: Project Skeleton & Architecture](#phase-1-project-skeleton--architecture)
   - [Phase 2: Dataset Discovery, Ingestion & Profiling](#phase-2-dataset-discovery-ingestion--profiling)
   - [Phase 3: Common Data Schema & Normalization](#phase-3-common-data-schema--normalization)
   - [Phase 4: Baseline Rule-Based Risk Engine](#phase-4-baseline-rule-based-risk-engine)
   - [Phase 5: Machine Learning Anomaly Detection](#phase-5-machine-learning-anomaly-detection)
   - [Phase 6: Supervised Risk Classification](#phase-6-supervised-risk-classification)
   - [Phase 7: TreeSHAP Explainability & Risk Attribution](#phase-7-treeshap-explainability--risk-attribution)
   - [Phase 8: Multi-Cloud Compliance Engine](#phase-8-multi-cloud-compliance-engine)
   - [Phase 9: Recommendation Engine](#phase-9-recommendation-engine)
   - [Phase 10: FastAPI Integration & Unified API Gateway](#phase-10-fastapi-integration--unified-api-gateway)
   - [Phase 11: PostgreSQL Integration & Asynchronous Repositories](#phase-11-postgresql-integration--asynchronous-repositories)
   - [Phase 12: React Dashboard & Tactical UI/UX Design System](#phase-12-react-dashboard--tactical-uiux-design-system)
   - [Phase 13: AWS Live Integration (Technical Specification)](#phase-13-aws-live-integration-technical-specification)
   - [Phase 14: Azure & GCP Live Integrations (Technical Specification)](#phase-14-azure--gcp-live-integrations-technical-specification)
   - [Phase 15: Automated Multi-Tier Testing Framework](#phase-15-automated-multi-tier-testing-framework)
   - [Phase 16: Dockerization & Container Orchestration](#phase-16-dockerization--container-orchestration)
   - [Phase 17: Production Deployment & Hardening](#phase-17-production-deployment--hardening)
   - [Phase 18: Documentation, Academic Evaluation & Defense Preparation](#phase-18-documentation-academic-evaluation--defense-preparation)
7. [Mathematical Formulations & Scoring Algorithms](#7-mathematical-formulations--scoring-algorithms)
8. [Compliance Control Catalog & Regulatory Coverage Matrix](#8-compliance-control-catalog--regulatory-coverage-matrix)
9. [Database Schema & Repository Layer Architecture](#9-database-schema--repository-layer-architecture)
10. [Complete REST API Endpoint Directory](#10-complete-rest-api-endpoint-directory)
11. [Local Development, Testing & Operations Runbook](#11-local-development-testing--operations-runbook)
12. [Academic References & Research Literature](#12-academic-references--research-literature)

---

## 1. Project Overview & Motivation

Modern organizations deploy workloads across multiple cloud service providers (Amazon Web Services, Microsoft Azure, Google Cloud Platform) to maximize resiliency and avoid vendor lock-in. However, multi-cloud architectures present critical security challenges:

1. **Telemetry Heterogeneity**: Disparate cloud audit formats (AWS CloudTrail JSON, Azure Activity Logs, GCP Cloud Audit Logs) make unified monitoring difficult without a canonical data taxonomy.
2. **Alert Fatigue & Heuristic Brittleness**: Static security rules fail to capture evolving adversarial tactics, producing false alarms while missing subtle zero-day account compromise indicators.
3. **Black-Box AI Decision Making**: Standard machine learning models classify security threats without explainability, preventing Security Operations Center (SOC) engineers from understanding *why* an event was flagged.
4. **Disconnection from Remediation**: Traditional Cloud Security Posture Management (CSPM) tools highlight vulnerabilities without providing context-aware, parameterized automation scripts for immediate remediation.

**CloudShield IQ** addresses these challenges by introducing a unified framework combining:
- **Canonical Telemetry Ingestion**: A vendor-agnostic data normalization pipeline projecting multi-cloud events into a common representation.
- **Hybrid AI Risk Intelligence**: Unsupervised anomaly detection (Isolation Forest) coupled with dual-head supervised risk regression and classification (XGBoost & HistGradientBoosting).
- **Mathematical Explainability (XAI)**: Exact additive TreeSHAP attribution mapping risk factors to intuitive security domains.
- **Deterministic Compliance Monitoring**: Automated verification against CIS Benchmarks, NIST SP 800-53, ISO/IEC 27001, and PCI-DSS v4.0.
- **Intelligent Remediation**: Parameterized, tri-language automation playbooks (CLI, Terraform, Python SDK) prioritized by risk reduction and operational effort.
- **Tactical SecOps Dashboard**: A high-density dark carbon interface engineered for rapid triage and real-time security posture assessment.

---

## 2. Academic Integrity & Ethical Constraints

This project adheres to strict academic integrity guidelines:
- **No Blockchain or Cryptographic Tokens**: The system is an enterprise cloud security analytics platform; distributed ledger technology is out of scope.
- **No IoT or Physical Hardware**: Focus is strictly on cloud control-plane telemetry and virtualized assets.
- **No LLM as Primary Decision-Maker**: Large Language Models (LLMs) are **never** utilized to compute risk scores, flag anomalies, or evaluate compliance controls. LLMs are restricted strictly to optional secondary natural-language summaries. All risk assessments are produced by verified ML algorithms and deterministic rules.
- **Zero Fabrication of Experimental Results**: All model accuracy metrics, benchmark ROC-AUC scores, and execution latencies are derived from verified test runs and reproducible experimental scripts.
- **Explicit Distinction of Project States**:
  - ✅ **Implemented & Verified**: Code written, unit tested, and fully functional.
  - 📐 **Designed & Specified**: Architecture documented and planned for subsequent implementation.
  - 🔬 **Experimental**: Research benchmarks conducted on synthetic or academic datasets.

---

## 3. System Architecture & Core Separation of Concerns

```text
Multi-Cloud Security Telemetry (AWS CloudTrail / Azure Activity / GCP Audit / CSV / JSON)
                                      │
                                      ▼
                             Data Ingestion Layer
                    (Multipart Upload • Stream Batching • Normalizer)
                                      │
                                      ▼
                        Common Data Schema (Pydantic v2)
               (Canonical Actions • Normalized CloudSecurityEvent)
                                      │
                       ┌──────────────┴──────────────┐
                       ▼                             ▼
           Machine Learning Engine         Compliance Rule Engine
           ┌───────────────────────┐       ┌────────────────────────┐
           │ Isolation Forest (IF) │       │ 17 Concrete Controls   │
           │ (Unsupervised Anomaly)│       │ CIS AWS v1.4           │
           ├───────────────────────┤       │ CIS Azure v2.0         │
           │ Dual-Head XGBoost +   │       │ CIS GCP v1.3           │
           │ HistGradientBoosting  │       │ NIST SP 800-53 (Rev. 5)│
           │ (Supervised Risk)     │       │ ISO/IEC 27001:2022     │
           └───────────┬───────────┘       │ PCI-DSS v4.0           │
                       │                   └───────────┬────────────┘
                       ▼                               ▼
               TreeSHAP Explainer              Pass/Fail/Partial
           (Exact Feature Attribution)                 │
                       │                               │
                       └───────────────┬───────────────┘
                                       ▼
                           Recommendation Engine
                    ┌──────────────────────────────────┐
                    │ 10 Tri-Language Playbooks        │
                    │ Multi-Factor Prioritization      │
                    │ Posture Improvement Simulation   │
                    └──────────────────┬───────────────┘
                                       ▼
                         Async Persistence Layer
                    (PostgreSQL 16 • SQLAlchemy 2.0 • Alembic)
                    (Circuit Breaker • Offline Fallback Mode)
                                       │
                                       ▼
                           FastAPI REST Gateway
                  (App Factory • Lifespan Manager • 6 Routers)
                                       │
                                       ▼
                   Tactical React Dashboard (UI/UX Pro Max)
       (Overview • Findings • Compliance • ML Engine • SecOps • Ingestion)
```

### Separation of Concerns
1. **Probabilistic Security Intelligence (ML)**: Identifies deviations and behavioral risks across high-dimensional feature spaces where deterministic rules are brittle.
2. **Deterministic Compliance (Rules)**: Validates statutory configurations against codified regulatory standards without stochastic variation.
3. **Mathematical Attribution (TreeSHAP)**: Explains the exact numerical contribution of each feature to the model's output, preventing black-box opacity.
4. **Remediation Synthesis (Playbooks)**: Translates findings into verified, multi-language code snippets with dynamic parameter injection.
5. **Resilient Data Access (Repositories)**: Implements asynchronous database transactions backed by a self-healing circuit breaker for uninterrupted local development.
6. **SecOps Interface (React UI)**: Delivers an information-dense, tactical visual command console adhering to cybersecurity design standards.

---

## 4. Complete Technology Stack Matrix

| Architectural Layer | Technology | Version | Purpose & Technical Justification |
|---|---|---|---|
| **Backend Framework** | FastAPI | `^0.115.0` | High-throughput asynchronous REST API gateway, native OpenAPI docs, dependency injection. |
| **Data Validation** | Pydantic v2 | `^2.10.0` | Core schema enforcement, type serialization, Rust-backed validation performance. |
| **Language Runtime** | Python | `3.11+` | Backend business logic, asynchronous task execution, ML engine execution. |
| **Database Engine** | PostgreSQL | `16-alpine` | Relational persistence for events, findings, ML assessments, and compliance audits. |
| **Database Driver** | asyncpg | `^0.29.0` | Non-blocking asynchronous PostgreSQL driver with high-performance connection pooling. |
| **ORM Framework** | SQLAlchemy | `^2.0.38` | Modern asynchronous 2.0 declarative models and async session management. |
| **Database Migrations** | Alembic | `^1.14.0` | Version-controlled async database migrations and composite indexing. |
| **Unsupervised ML** | scikit-learn | `^1.6.0` | `IsolationForest` anomaly detector, standard scalers, feature encoders. |
| **Supervised ML** | XGBoost | `^2.1.0` | `XGBRegressor` continuous calibrated risk score prediction and gradient boosted trees. |
| **Supervised ML** | HistGradientBoosting | `scikit-learn` | Multi-class incident severity classifier (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`). |
| **Model Explainability** | SHAP | `^0.46.0` | `TreeExplainer` providing exact additive Shapley feature attributions. |
| **Numerical Processing** | NumPy / Pandas | `^2.1` / `^2.2` | Vectorized matrix operations, cyclical feature encoding, batch evaluation. |
| **Frontend Framework** | React | `19.0.0` | Declarative component UI, state synchronization, virtual DOM reconciliation. |
| **Build Tooling** | Vite | `^6.0.0` | Next-generation frontend bundler, instant Hot Module Replacement (HMR). |
| **Type Safety** | TypeScript | `^5.6.0` | Strict static typing across frontend models, API clients, and UI components. |
| **Styling & Design** | Tailwind CSS | `^4.0.0` | Tactical dark carbon design system, utility-first styling, CSS custom properties. |
| **Iconography** | Lucide React | `^0.470.0` | Lightweight, consistent cybersecurity glyphs and status indicators. |
| **Data Visualization** | Recharts | `^2.15.0` | Interactive SVG risk posture charts, distribution breakdowns, and area charts. |
| **Backend Testing** | Pytest | `^9.1.0` | Unit and integration test runner, async test fixtures, coverage profiling. |
| **E2E Testing** | Playwright | `^1.50.0` | Multi-browser headless/headed end-to-end integration test runner. |
| **Containerization** | Docker / Compose | `v2` | Multi-container development and production environment orchestration. |

---

## 5. Master Project Phases & Status Matrix

| Phase | Title | Status | Primary Deliverables & Milestones |
|---|---|---|---|
| **0** | Environment Setup & Toolchains | ✅ Done | Python virtual environment, Node 20+, pre-commit hooks, workspace configuration. |
| **1** | Project Skeleton & Repository Layout | ✅ Done | FastAPI application factory, directory structure, config settings, logging system. |
| **2** | Dataset Discovery, Ingestion & Profiling | ✅ Done | Research notes, profiling reports, synthetic multi-cloud dataset generation (8k rows). |
| **3** | Common Data Schema & Normalization | ✅ Done | Canonical Action Taxonomy, Pydantic v2 event models, raw telemetry normalizers. |
| **4** | Baseline Rule-Based Risk Engine | ✅ Done | 7 deterministic heuristic rules, composite risk scoring ($[0.0, 100.0]$), MITRE findings. |
| **5** | Machine Learning Anomaly Detection | ✅ Done | 75-dim feature extractor, Isolation Forest (150 trees), ROC-AUC benchmark (0.7723). |
| **6** | Supervised Risk Classification | ✅ Done | Dual-head model (XGBoost Regressor + HistGradientBoosting Classifier). |
| **7** | TreeSHAP Explainability & Attribution | ✅ Done | Exact additive TreeSHAP explainer, 5 security domain groupings, waterfall card. |
| **8** | Multi-Cloud Compliance Engine | ✅ Done | 17 concrete controls: CIS AWS/Azure/GCP, NIST 800-53, ISO 27001, PCI-DSS v4.0. |
| **9** | Recommendation Engine | ✅ Done | 10 tri-language playbooks, multi-factor prioritizer, posture simulation engine. |
| **10** | FastAPI Integration & API Gateway | ✅ Done | Central app factory, lifespan manager, 6 modular API sub-routers under `/api/v1`. |
| **11** | PostgreSQL Integration & Repositories | ✅ Done | SQLAlchemy 2.0 async models, Alembic migrations, async repositories, circuit breaker. |
| **12** | React Dashboard & UI/UX Design System | ✅ Done | Tactical dark carbon UI (`#0A0D12`), 6 views, SecOps drawer, zero purple gradients. |
| **13** | AWS Live Integration | 📐 Specified | Read-only IAM STS connector, CloudTrail SQS event stream ingestion. |
| **14** | Azure & GCP Live Integrations | 📐 Specified | Azure Event Hub / Activity Log connector, GCP Pub/Sub Audit Log ingestion. |
| **15** | Automated Multi-Tier Testing Framework | ✅ Done | **161 pytest backend tests (100%) + 26 Playwright E2E frontend tests (100%)**. |
| **16** | Dockerization & Container Orchestration | ✅ Done | `docker-compose.dev.yml`, `docker-compose.prod.yml`, multi-stage Dockerfiles for backend and frontend. |
| **17** | Production Deployment & Hardening | ✅ Done | Nginx reverse proxy gateway, CSP/HSTS security headers, token-bucket rate limiting, non-root user execution. |
| **18** | Documentation, Evaluation & Defense | 🟡 Active | Architectural documentation, ADR records, defense slide decks, thesis alignment. |

---

## 6. Detailed Phase-by-Phase Technical Implementations

### Phase 0: Environment Setup & Toolchains
- **Runtime Configuration**: Python 3.11+ isolated virtual environment (`backend/.venv`) and Node.js 20+ runtime for frontend compilation.
- **Pre-commit Quality Gates**: Git pre-commit hooks configured for formatting (Ruff, Prettier) and static analysis (Mypy).
- **Batch Automation Scripts**: Created root automation scripts:
  - `start.bat`: Dual-window launcher spinning up backend on port 8001 and frontend on port 8000.
  - `stop.bat`: Clean termination script killing background Node and Python processes.
  - `test_ui.bat`: Headless and interactive visual test runner wrapper for Playwright.

### Phase 1: Project Skeleton & Architecture
- **Application Factory Pattern**: Structured `create_application()` in `backend/app/main.py` enabling isolated test instantiation without startup side-effects.
- **Typed Configuration (`app/core/config.py`)**: Environment variable management using `pydantic-settings.BaseSettings`, validating database URLs, JWT keys, and CORS origins with crash-fast safety.
- **Structured Structured Logging (`app/core/logging.py`)**: JSON/console formatted logging system with timestamping, level filtering, and contextual metadata tagging.

### Phase 2: Dataset Discovery, Ingestion & Profiling
- **Candidate Evaluation**: Documented in `research/notes/phase2_dataset_notes.md`:
  - *KDD Cup 1999 / NSL-KDD*: Rejected as obsolete (1998 network packet traffic, pre-cloud, 80% redundant records).
  - *UNSW-NB15*: Selected as supplementary network intrusion baseline (257,000 records).
  - *CIC-IDS-2017/2018*: Evaluated and deferred due to massive dimensionality (16M rows).
  - *Synthetic Cloud Telemetry*: Selected as primary dataset (8,000 control-plane records generated with fixed seed 42, calibrated 5% anomaly rate).
- **Profiling Reports**: Statistical characterization in `research/notes/phase2_profiling_results.md` establishing baseline distributions for user roles, geographic IP distributions, and API call frequencies.

### Phase 3: Common Data Schema & Normalization
- **Canonical Action Taxonomy (`app/core/taxonomy.py`)**: Standardized action verbs mapping heterogeneous cloud operations:
  - AWS `RunInstances` / Azure `virtualMachines/write` / GCP `compute.instances.insert` $\rightarrow$ `COMPUTE_INSTANCE_LAUNCH`
  - AWS `PutBucketAcl` / Azure `storageAccounts/blobServices/containers/write` $\rightarrow$ `STORAGE_BUCKET_PERMISSIONS_ALTER`
  - AWS `DeleteKey` / Azure `vaults/keys/delete` $\rightarrow$ `CRYPTO_KEY_DESTROY`
- **Pydantic v2 Core Schemas (`app/schemas/`)**: Strict models for `CloudSecurityEvent`, `RiskAssessment`, `SecurityFinding`, and `ComplianceControlResult`.
- **Telemetry Normalizer (`app/services/ingestion/normalizer.py`)**: Vectorized normalization parsing raw JSON/CSV payloads into canonical `CloudSecurityEvent` objects with validation and error tracking.

### Phase 4: Baseline Rule-Based Risk Engine
- **Heuristic Rule Catalog (`app/ml/rules.py`)**: Deterministic rules targeting high-severity anti-patterns:
  - `RootAccountUsageRule`: Triggers when root credentials perform non-read-only administrative tasks.
  - `PrivilegeEscalationNoMfaRule`: Flags IAM role modifications or policy attachments executed without MFA.
  - `LoggingTamperingRule`: Identifies attempts to disable CloudTrail, delete log groups, or halt diagnostic exports.
  - `KmsKeyDestructionRule`: Detects immediate KMS cryptoKey deletion or disablement actions.
  - `PublicStorageExposureRule`: Intercepts bucket ACL changes granting `AllUsers` or `AuthenticatedUsers` read/write.
- **Composite Risk Scorer**: Calculates bounded risk ($0.0 \le \text{Score} \le 100.0$) with severity classification (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`).
- **Actionable Findings**: Automatic generation of `SecurityFinding` objects with MITRE ATT&CK technique IDs and CLI/Terraform remediation commands.

### Phase 5: Machine Learning Anomaly Detection
- **Feature Engineering Pipeline (`app/ml/features.py`)**: `SecurityFeatureExtractor` generating 75-dimensional numeric arrays:
  - *Cyclical Time Features*: Sine and cosine transformations of hour-of-day ($\sin(2\pi h/24)$, $\cos(2\pi h/24)$) and day-of-week.
  - *Actor Risk Profiling*: Binary flags for root actors, federated users, service principals, and administrative roles.
  - *MFA Posture*: Authentication flags and session duration scaling.
  - *Network Locality*: IP address locality encoding (RFC 1918 private vs public routable IPs).
  - *Categorical One-Hot Encoding*: Canonical action and resource type projection matrices.
- **Isolation Forest Model (`app/ml/anomaly_detector.py`)**: Unsupervised tree ensemble (150 trees, 5% contamination factor), calibrated to output continuous anomaly probabilities $[0.0, 1.0]$.
- **Experimental Verification**: CLI training script (`ml/scripts/train_anomaly_model.py`) achieving ROC-AUC of **0.7723** across 25,000 multi-cloud security telemetry records.
- **Hybrid Risk Scoring**: Weighted combination of rule-based risk scores and ML anomaly probabilities, automatically escalating unexpected zero-day actions.

### Phase 6: Supervised Risk Classification
- **Dual-Head Architecture (`app/ml/risk_classifier.py`)**:
  - *Head 1 (Severity Classification)*: Multi-class `HistGradientBoostingClassifier` predicting discrete severity classes (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`).
  - *Head 2 (Continuous Risk Regression)*: Gradient boosted regression via `XGBRegressor` predicting continuous scores $[0.0, 100.0]$.
- **Integration**: Operates directly on the 75-dimensional `SecurityFeatureExtractor` vector without manual feature conversion.

### Phase 7: TreeSHAP Explainability & Risk Attribution
- **Exact Additive TreeSHAP Explainer (`app/ml/tree_shap.py`)**: Implements `shap.TreeExplainer` over the trained XGBoost tree ensemble, satisfying mathematical Shapley additivity:
  $$\text{Base Value} + \sum_{i=1}^{M} \phi_i = \text{Predicted Risk Score}$$
- **Security Domain Mapping**: Groups 75 features into 5 operational security domains:
  1. `IDENTITY_AND_ACCESS`: MFA presence, root usage, role assumptions, privilege escalation.
  2. `NETWORK_SECURITY`: Public IP origins, security group ingress changes, VPC routing modifications.
  3. `DATA_PROTECTION`: Storage bucket ACLs, KMS key disablement/deletion, database exposures.
  4. `SECURITY_OPERATIONS`: CloudTrail/audit log stoppage, diagnostic setting alterations.
  5. `TEMPORAL_CONTEXT`: Off-hours access, cyclical hour/day-of-week anomalies.
- **Waterfall Decomposition**: Evaluates single and batch incidents to isolate positive (risk-elevating) and negative (risk-mitigating) feature contributions.
- **Global Importance Metrics**: Aggregates mean absolute SHAP values across evaluation sets to identify primary organizational risk drivers.

### Phase 8: Multi-Cloud Compliance Engine
- **Deterministic Control Catalog (`app/compliance/catalog.py`)**: 17 concrete compliance controls across 6 regulatory standards:
  - *CIS AWS Foundations Benchmark v1.4*: Controls 1.5 (Root account), 1.10 (Console MFA), 2.1 (CloudTrail enabled), 3.1 (Public S3 ACLs).
  - *CIS Microsoft Azure Foundations Benchmark v2.0*: Controls 1.1 (Privileged MFA), 3.1 (Storage firewall), 5.1 (Restricted SSH port 22).
  - *CIS Google Cloud Platform Foundation Benchmark v1.3*: Controls 1.1 (Corporate identity), 1.4 (KMS anonymous access), 5.1 (Uniform bucket access).
  - *NIST SP 800-53 (Rev. 5)*: Controls AC-2 (Account Management), AU-2 (Event Logging), SC-28 (Protection at Rest).
  - *ISO/IEC 27001:2022*: Controls A.9.4.2 (Secure Log-on), A.12.4 (Audit Logging).
  - *PCI-DSS v4.0*: Requirements 3.4 (Cardholder Data Protection), 8.3 (Multi-Factor Authentication).
- **Evaluation Engine (`app/compliance/engine.py`)**:
  - Deterministically returns `PASS`, `FAIL`, `PARTIAL`, or `NOT_APPLICABLE` for evaluated resources.
  - Aggregates framework pass rate percentages.
  - Exports structured JSON audit reports for compliance documentation.

### Phase 9: Recommendation Engine
- **Remediation Playbook Catalog (`app/recommendations/catalog.py`)**: 10 production-grade playbooks across AWS, Azure, and GCP. Each playbook includes:
  - Vendor CLI commands (AWS CLI, Azure CLI, gcloud).
  - Declarative Terraform HCL modules.
  - Python SDK automation scripts (Boto3, Azure SDK, Google Cloud Client).
  - Rollback procedures and verification probes.
- **Intelligent Prioritizer (`app/recommendations/prioritizer.py`)**: Multi-factor priority score:
  $$\text{Priority} = 0.45 \times \text{Risk} + 0.25 \times \text{Severity} + 0.15 \times \text{Compliance} + 0.15 \times \text{Effort Factor}$$
  Includes effort inversion boosting "Quick Wins" ($\ge 25.0$ risk drop with low operational effort).
- **Context-Aware Engine (`app/recommendations/engine.py`)**: Matches findings by TreeSHAP feature attributions and compliance violations, dynamically injecting resource IDs, regions, and account IDs into remediation scripts.
- **Perimeter Posture Simulation**: Projects enterprise risk reduction prior to executing changes.

### Phase 10: FastAPI Integration & Unified API Gateway
- **Modular Application Factory**: `create_application()` in `backend/app/main.py` binds middleware, exception handlers, and API routers.
- **Lifespan Context Manager**: Handles startup/shutdown sequences: structured logging, directory initialization, DB probes, and connection pool cleanup.
- **Router Modularization**: Registered sub-routers under `/api/v1` in `app/api/v1/__init__.py`:
  - `/health`: Health and readiness probes.
  - `/ingestion`: Multi-cloud file/stream upload and stats.
  - `/ml`: Model metadata, anomaly detection, risk classification, model training, and TreeSHAP explainability.
  - `/compliance`: Frameworks catalog, concrete controls, deterministic evaluation, posture summary, and audit reports.
  - `/recommendations`: Playbook catalog, recommendation synthesis, priority queue, and posture simulation.
  - `/findings`: Findings list, detail view, and status updates.
- **Security & Error Handling**: Configured CORS origin controls, custom JSON error masking preventing internal exception leakage, and automatic OpenAPI documentation generation at `/api/docs`.

### Phase 11: PostgreSQL Integration & Asynchronous Repositories
- **SQLAlchemy 2.0 Async ORM Models (`app/models/`)**:
  - `SecurityEventModel`: Normalized cloud telemetry records.
  - `RiskAssessmentModel`: Anomaly scores, risk ratings, and JSON-encoded SHAP feature weights.
  - `SecurityFindingModel`: Actionable security findings with CLI and Terraform remediation snippets.
  - `ComplianceResultModel`: Control evaluation outcomes and failed resource identifiers.
- **Alembic Database Migrations (`backend/alembic/`)**:
  - Async migration environment bound to `Base.metadata`.
  - Migration `001_initial_schema.py` creating tables and performance composite indexes (`ix_events_provider_timestamp`, `ix_events_provider_resource`, `ix_events_actor_canonical`, `ix_findings_status`).
- **Asynchronous Repository Pattern (`app/repositories/`)**:
  - `BaseRepository[ModelType]`: Generic async CRUD (`create`, `create_batch`, `get_by_id`, `list`, `count`, `delete`).
  - `EventRepository`: Multi-cloud telemetry queries, provider grouping, high-throughput batching.
  - `FindingRepository`: Multi-cloud filtering, full-text search, status triage lifecycle (`OPEN` -> `INVESTIGATING` -> `RESOLVED` / `FALSE_POSITIVE`).
  - `AssessmentRepository`: Anomaly scores, dual-head risk ratings, SHAP attribution persistence.
  - `ComplianceRepository`: Control evaluations and framework pass rate rollups.
- **Self-Healing Circuit Breaker (`app/core/database.py`)**: Monitors PostgreSQL connection state. If PostgreSQL is offline during development or testing, the circuit breaker instantly trips to degraded dev fallback mode, serving simulated/mock data without 500 errors or connection timeouts.
- **Non-Blocking Background Persistence**: Telemetry uploads schedule event writes via FastAPI `BackgroundTasks`, decoupling database I/O from client response latency.

### Phase 12: React Dashboard & Tactical UI/UX Design System
- **Tactical Carbon Design System (`frontend/src/index.css`)**:
  - Engineered with Vite, React 19, TypeScript, and Tailwind CSS.
  - Deep carbon background (`#0A0D12`), layered dark surfaces (`#111620`, `#161D2A`), 1px hairline borders (`rgba(255, 255, 255, 0.07)`), and elevation shadows.
  - Zero generic purple/blue gradients; strict cybersecurity color identity with emerald (`#10B981`), amber (`#F59E0B`), and rose (`#F43F5E`) tactical accents.
  - Typography powered by Google Fonts Fira Code, JetBrains Mono, and Inter.
- **6 Primary Operational Dashboard Views**:
  1. **Executive Overview**: Real-time composite risk gauge, multi-cloud audited asset counts, MITRE ATT&CK coverage, high-priority alert cards, and posture trend visualizations.
  2. **Security Findings Master-Detail Explorer**: Interactive search, cloud provider filters (AWS/Azure/GCP), severity tabs, deep finding inspector, 1-click CLI and Terraform code copying, and triage lifecycle status updates.
  3. **Multi-Cloud Compliance Matrix**: Framework cards (CIS AWS/Azure/GCP, NIST, ISO, PCI-DSS), passing/failing control chips, failed resource inspector, and audit JSON report export.
  4. **Machine Learning & TreeSHAP Explainer**: Unsupervised Isolation Forest anomaly scanner, Supervised XGBoost risk classifier, interactive TreeSHAP local waterfall attribution breakdown (risk-elevating vs risk-mitigating feature deltas), and global feature importance rankings.
  5. **SecOps Remediation Console Drawer**: Slide-over terminal drawer, contextual playbook synthesis, dynamic parameter substitution, multi-language code tabs (CLI, Terraform, Python), and perimeter posture simulation.
  6. **Telemetry Ingestion & Simulation**: Multi-cloud JSON/CSV upload dropzone, synthetic telemetry generators, live risk parameter sliders (0-100), and immediate hybrid evaluation.

### Phase 13: AWS Live Integration (Technical Specification)
- **Architecture**:
  - Secure, read-only cross-account role assumption using AWS Security Token Service (STS) `AssumeRole` with external ID verification.
  - Ingestion from Amazon CloudTrail via multi-region Amazon S3 bucket notifications routed through Amazon SQS FIFO queues.
  - Periodic polling of AWS Config for resource inventory snapshots.
- **Security Constraints**:
  - Strict `SecurityAudit` and `ViewOnlyAccess` AWS managed IAM policies.
  - Zero write or modify permissions granted to the CloudShield IQ ingestion role.

### Phase 14: Azure & GCP Live Integrations (Technical Specification)
- **Azure Integration**:
  - Microsoft Entra ID (Azure AD) App Registration with read-only `Reader` role assigned at subscription scope.
  - Streaming ingestion of Azure Activity Logs and Microsoft Defender for Cloud alerts via Azure Event Hubs.
- **GCP Integration**:
  - Google Cloud Service Account with `roles/viewer` and `roles/logging.viewer`.
  - Ingestion of Google Cloud Audit Logs routed through Google Cloud Pub/Sub topics.

### Phase 15: Automated Multi-Tier Testing Framework
- **Backend Test Suite (Pytest - 161 Tests Passing)**:
  - 18 integration tests in `tests/integration/test_repositories.py` verifying async CRUD, filtering, and transactions across all repository classes.
  - 143 unit tests across `tests/unit/backend/`, `tests/unit/compliance/`, `tests/unit/ml/`, and `tests/unit/recommendations/`.
  - 100% pass rate achieved with zero regressions.
- **Frontend E2E Test Suite (Playwright - 26 Tests Passing)**:
  - 26 tests across 8 spec files (`navigation.spec.ts`, `theme-styles.spec.ts`, `findings.spec.ts`, `compliance.spec.ts`, `ml-engine.spec.ts`, `secops-console.spec.ts`, `ingestion.spec.ts`, `explainability.spec.ts`).
  - Strict assertions validating tactical `#0A0D12` carbon styles, absence of purple/blue gradients, master-detail selection, TreeSHAP waterfall rendering, and terminal execution.

### Phase 16: Dockerization & Container Orchestration
- **Development Topology (`deployment/docker/docker-compose.dev.yml`)**:
  - `cloudshield_postgres`: PostgreSQL 16 Alpine container with persistent data volume mounting.
  - `cloudshield_backend`: FastAPI backend container running Uvicorn with `--reload` mounted source code.
  - `cloudshield_frontend`: Vite development container with hot-reloading on port 5173 (`frontend/Dockerfile.dev`).
- **Production Topology (`deployment/docker/docker-compose.prod.yml`)**:
  - Multi-tier isolated bridge networks (`internal_net` for isolated database transactions, `frontend_net` for web services).
  - Explicit resource governance limits (CPU/memory constraints) preventing noisy neighbor denial of service.
  - Root `docker-compose.yml` convenience launcher for unified execution.
- **Multi-Stage Production Builds**:
  - `backend/Dockerfile`: Two-stage build (Builder: compiles wheels and installs dependencies; Runtime: `python:3.11-slim`, non-root user `cloudshield` UID 10001, stripped build dependencies, healthcheck probes).
  - `frontend/Dockerfile`: Two-stage build (Builder: Node 20-alpine `npm run build`; Runtime: Nginx 1.27-alpine serving compressed static SPA assets with SPA fallback routing).

### Phase 17: Production Deployment & Hardening
- **Reverse Proxy Gateway (`deployment/nginx/`)**:
  - High-performance Nginx 1.27 reverse proxy terminating public traffic on port 80/443.
  - Upstream connection pooling (`keepalive 32`) and failover policies for backend and frontend services.
  - Dedicated routing rules: `/api/` traffic routed to FastAPI with extended timeouts (120s) for ML inference; `/` routed to SPA.
- **Defense-in-Depth Security Hardening**:
  - Strict HTTP response headers: `X-Frame-Options "DENY"`, `X-Content-Type-Options "nosniff"`, `X-XSS-Protection "1; mode=block"`, `Referrer-Policy "strict-origin-when-cross-origin"`.
  - Granular Content Security Policy (CSP) restricting script execution and font/style sources.
  - Dual token-bucket rate limiting zones: 50 req/s for standard API endpoints; 10 req/s burst limit on telemetry uploads.
  - Unprivileged user execution (`cloudshield:10001`) with read-only root filesystems where applicable.
- **Automation & Operations Runbooks (`deployment/scripts/`)**:
  - `deploy.sh` / `deploy.bat`: Automated environment verification and one-touch multi-container deployment.
  - `healthcheck.sh`: Automated probing of reverse proxy and application health endpoints.
  - `stop.sh`: Clean container graceful shutdown.

### Phase 18: Documentation, Academic Evaluation & Defense Preparation
- **Comprehensive Documentation**: Architectural specifications, API directories, mathematical formulations, and runbooks consolidated in `docs/documentation.md`.
- **Architectural Decision Records (ADRs)**: Version-controlled design rationale in `docs/decisions/` (e.g., `ADR-001-ml-strategy.md`).
- **Academic Defense Deliverables**: Slide deck presentations, benchmark comparison charts, and demonstration scripts for final defense evaluation.

---

## 7. Mathematical Formulations & Scoring Algorithms

### 1. Isolation Forest Anomaly Detection
The anomaly score $s(x, n)$ for an observation $x$ over an ensemble of $n$ isolation trees is defined as:
$$s(x, n) = 2^{-\frac{E(h(x))}{c(n)}}$$
where $h(x)$ is the path length of observation $x$, $E(h(x))$ is the average path length across all isolation trees, and $c(n)$ is the average path length of unsuccessful searches in a Binary Search Tree (BST) of $n$ nodes:
$$c(n) = 2 \ln(n - 1) + 0.5772156649 \text{ (Euler's constant)} - \frac{2(n - 1)}{n}$$
When $E(h(x)) \to 0$, $s \to 1$ (high anomaly likelihood); when $E(h(x)) \to n - 1$, $s \to 0$ (normal behavior).

### 2. XGBoost Objective Function & Additive Trees
The supervised risk score $\hat{y}_i$ is predicted using an ensemble of $K$ regression trees:
$$\hat{y}_i = \sum_{k=1}^{K} f_k(x_i), \quad f_k \in \mathcal{F}$$
The objective function $\mathcal{L}$ minimized at iteration $t$ combines the convex loss function $l$ with tree complexity regularization $\Omega$:
$$\mathcal{L}^{(t)} = \sum_{i=1}^{N} l(y_i, \hat{y}_i^{(t-1)} + f_t(x_i)) + \Omega(f_t)$$
where $\Omega(f_t) = \gamma T + \frac{1}{2}\lambda \sum_{j=1}^{T} w_j^2$ penalizes the number of leaves $T$ and leaf weights $w$.

### 3. Exact Additive TreeSHAP
For a model prediction $f(x)$, TreeSHAP computes the unique additive feature attribution $\phi_i$ for feature $i$ satisfying efficiency, symmetry, dummy, and additivity axioms:
$$\phi_i(f, x) = \sum_{S \subseteq F \setminus \{i\}} \frac{|S|!(|F| - |S| - 1)!}{|F|!} \left[ f_x(S \cup \{i\}) - f_x(S) \right]$$
The sum of feature attributions plus the expected base value equals the exact predicted risk score:
$$f(x) = \phi_0 + \sum_{i=1}^{M} \phi_i(x)$$

### 4. Composite Bounded Risk Scoring
The composite risk score $R(e) \in [0.0, 100.0]$ for event $e$ unifies heuristic severity weights $W_{\text{rule}}$, ML anomaly probability $P_{\text{anomaly}}$, and supervised predicted risk $R_{\text{xgb}}$:
$$R(e) = \min\left(100.0, \quad 0.40 \times W_{\text{rule}}(e) + 0.35 \times R_{\text{xgb}}(e) + 0.25 \times (P_{\text{anomaly}}(e) \times 100)\right)$$

### 5. Remediation Priority Scoring & Quick-Win Inversion
Prioritization score $P \in [0.0, 100.0]$ balances risk urgency against operational deployment friction:
$$P = 0.45 \times R(e) + 0.25 \times S_{\text{num}} + 0.15 \times C_{\text{weight}} + 0.15 \times E_{\text{factor}}$$
where $S_{\text{num}} \in [25, 100]$ is numeric severity, $C_{\text{weight}}$ is compliance impact, and $E_{\text{factor}} \in [20, 100]$ inversely scales with required effort ($E_{\text{factor}} = 100$ for low effort / instant scripts).

---

## 8. Compliance Control Catalog & Regulatory Coverage Matrix

| Control ID | Regulatory Framework | Control Title & Target | Automated Evaluation Logic | Remediation Automation |
|---|---|---|---|---|
| `CIS-AWS-1.5` | CIS AWS v1.4 | Root account usage prohibited | Flags any event where `actor_type == ROOT` and action is non-read-only. | AWS CLI: Lock root access keys; configure MFA on root account. |
| `CIS-AWS-1.10` | CIS AWS v1.4 | Ensure MFA is enabled for console access | Flags console logins (`ConsoleLogin`) where `mfa_used == False`. | AWS CLI / Terraform: Enforce IAM MFA policy for console users. |
| `CIS-AWS-2.1` | CIS AWS v1.4 | Ensure multi-region CloudTrail enabled | Validates that CloudTrail logging is active across all commercial regions. | Terraform: Deploy multi-region `aws_cloudtrail` resource. |
| `CIS-AWS-3.1` | CIS AWS v1.4 | Ensure S3 bucket ACLs disallow public read | Evaluates S3 bucket ACL policies for `AllUsers` or `AuthenticatedUsers`. | AWS CLI / Python: Remove public ACL grant from target bucket. |
| `CIS-AZURE-1.1` | CIS Azure v2.0 | Ensure MFA is enabled for all privileged roles | Flags Azure AD sign-ins by privileged accounts lacking MFA claims. | Azure CLI: Enforce Conditional Access policy requiring MFA. |
| `CIS-AZURE-3.1` | CIS Azure v2.0 | Ensure storage account network access is restricted | Validates that Azure Storage Account default action is `Deny`. | Terraform: Set `default_action = "Deny"` in `azurerm_storage_account_network_rules`. |
| `CIS-AZURE-5.1` | CIS Azure v2.0 | Ensure SSH access is restricted from internet | Intercepts NSG rules allowing inbound TCP port 22 from `*` or `0.0.0.0/0`. | Azure CLI: Update NSG rule restricting SSH to VPN/bastion CIDR. |
| `CIS-GCP-1.1` | CIS GCP v1.3 | Ensure corporate credentials are enforced | Flags GCP IAM policy bindings granting access to `@gmail.com` accounts. | gcloud: Remove personal Gmail identities from project IAM policy. |
| `CIS-GCP-1.4` | CIS GCP v1.3 | Ensure Cloud KMS keys are not publicly accessible | Validates that KMS cryptoKey IAM bindings do not include `allUsers`. | gcloud: Delete public IAM policy binding on KMS key resource. |
| `CIS-GCP-5.1` | CIS GCP v1.3 | Ensure Cloud Storage uniform bucket-level access | Checks that GCS buckets enforce uniform bucket-level access. | gcloud: Enable uniform bucket-level access on target bucket. |
| `NIST-AC-2` | NIST 800-53 r5 | Account Management & Authentication | Flags anomalous privileged account creation or unapproved role assumption. | Terraform: Configure centralized AWS IAM Identity Center or Azure AD SCIM. |
| `NIST-AU-2` | NIST 800-53 r5 | Event Logging Architecture | Validates continuous log export to secure immutable storage repositories. | Terraform: Provision centralized logging S3 bucket with Object Lock. |
| `NIST-SC-28` | NIST 800-53 r5 | Protection of Information at Rest | Flags cloud storage volumes or object buckets provisioned without customer-managed keys (CMK). | Terraform: Enforce KMS customer-managed key encryption on storage. |
| `ISO-A.9.4.2` | ISO 27001:2022 | Secure Log-on Procedures | Validates multi-factor authentication and session inactivity timeouts. | Terraform: Apply identity policy enforcing session duration and MFA. |
| `ISO-A.12.4` | ISO 27001:2022 | Protection of Audit Logs | Intercepts attempts to delete or modify cloud audit trails or log archives. | AWS CLI: Attach SCP preventing `cloudtrail:DeleteTrail` or `cloudtrail:StopLogging`. |
| `PCI-REQ-3.4` | PCI-DSS v4.0 | Encryption of Cardholder Data at Rest | Verifies strong cryptographic cipher suites and key rotation on data stores. | AWS CLI: Enable automated annual key rotation on KMS customer keys. |
| `PCI-REQ-8.3` | PCI-DSS v4.0 | Multi-Factor Authentication for CDE Access | Enforces mandatory MFA for all personnel accessing Cardholder Data Environments. | Terraform: Apply zero-trust conditional access policies for CDE networks. |

---

## 9. Database Schema & Repository Layer Architecture

### Entity-Relationship Architecture

```text
┌──────────────────────────────────────────────────────────┐
│                     security_events                      │
├──────────────────────────────────────────────────────────┤
│ event_id (PK, String(64))                                │
│ timestamp (DateTime with TZ)                             │
│ cloud_provider (String(32))                              │
│ event_source (String(128))                               │
│ resource_type (String(128))                              │
│ resource_id (String(512))                                │
│ canonical_action (String(64))                            │
│ raw_action (String(256))                                 │
│ actor_type (String(32))                                  │
│ actor_name (String(256))                                 │
│ source_ip (String(64))                                   │
│ region (String(64))                                      │
│ mfa_used (Boolean)                                       │
│ outcome (String(32))                                     │
│ metadata_payload (JSON)                                  │
└────────────────────────────┬─────────────────────────────┘
                             │
                             │ 1:1
                             ▼
┌──────────────────────────────────────────────────────────┐
│                    risk_assessments                      │
├──────────────────────────────────────────────────────────┤
│ assessment_id (PK, String(64))                           │
│ event_id (FK -> security_events.event_id)                │
│ risk_score (Float)                                       │
│ anomaly_score (Float)                                    │
│ is_anomaly (Boolean)                                     │
│ severity (String(32))                                    │
│ shap_values (JSON)                                       │
│ top_feature (String(128))                                │
│ top_feature_impact (Float)                               │
│ evaluated_at (DateTime with TZ)                          │
└──────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────┐
│                    security_findings                     │
├──────────────────────────────────────────────────────────┤
│ finding_id (PK, String(64))                              │
│ title (String(256))                                      │
│ cloud_provider (String(32))                              │
│ resource_id (String(512))                                │
│ category (String(64))                                    │
│ severity (String(32))                                    │
│ risk_score (Float)                                       │
│ compliance_violations (JSON)                             │
│ cli_remediation_command (Text)                           │
│ terraform_remediation_snippet (Text)                     │
│ status (String(32): OPEN/INVESTIGATING/RESOLVED)         │
│ detected_at (DateTime with TZ)                           │
└──────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────┐
│                   compliance_results                     │
├──────────────────────────────────────────────────────────┤
│ result_id (PK, String(64))                               │
│ control_id (String(64))                                  │
│ control_name (String(256))                               │
│ framework (String(64))                                   │
│ cloud_provider (String(32))                              │
│ status (String(32): PASS/FAIL/PARTIAL/NA)                │
│ evaluated_resources (Integer)                            │
│ failed_resources (Integer)                               │
│ failed_resource_ids (JSON)                               │
│ evaluated_at (DateTime with TZ)                          │
└──────────────────────────────────────────────────────────┘
```

### Self-Healing Database Circuit Breaker
The system includes a circuit-breaker design pattern in `app/core/database.py`:
- **State: CLOSED (Normal Operation)**: Queries execute against PostgreSQL via async connection pools.
- **State: OPEN (Degraded Dev Fallback)**: If PostgreSQL connection fails on startup or timeout, the engine trips immediately. Requests fall back to in-memory datasets and mock responses. The backend remains 100% operational without throwing 500 internal server errors.
- **State: HALF-OPEN (Self-Healing Probe)**: Periodic health checks attempt reconnection. Once PostgreSQL is available, normal database writes resume automatically.

---

## 10. Complete REST API Endpoint Directory

All endpoints are hosted under `/api/v1` (with `/health` accessible at root for orchestrator probes):

| Method | Endpoint | Description | Phase | Response Codes |
|---|---|---|---|---|
| `GET` | `/health` | Liveness health probe for load balancers and orchestrators | Phase 10 | 200 |
| `GET` | `/api/v1/health` | Service status check | Phase 10 | 200 |
| `GET` | `/api/v1/health/ready` | Readiness probe verifying database and cache connectivity | Phase 10 | 200, 503 |
| `POST` | `/api/v1/ingestion/upload` | Multipart file upload for multi-cloud CSV/JSON telemetry | Ingestion | 200, 400 |
| `POST` | `/api/v1/ingestion/events` | High-throughput batch ingestion of normalized telemetry JSON | Ingestion | 200, 422 |
| `POST` | `/api/v1/ingestion/sample/{sample_type}` | Instant loading of synthetic, CloudTrail, or Azure sample sets | Ingestion | 200, 404 |
| `GET` | `/api/v1/ingestion/stats` | Ingestion metrics and telemetry counts grouped by provider | Ingestion | 200 |
| `GET` | `/api/v1/ingestion/events` | Paginated query of ingested normalized security telemetry | Ingestion | 200 |
| `GET` | `/api/v1/ml/model-info` | Isolation Forest and XGBoost model specifications and feature count | Phase 5, 6 | 200 |
| `POST` | `/api/v1/ml/detect` | Unsupervised anomaly scoring producing continuous probabilities | Phase 5 | 200, 422 |
| `POST` | `/api/v1/ml/classify` | Supervised dual-head risk score regression and severity classification | Phase 6 | 200, 422 |
| `POST` | `/api/v1/ml/classify/batch` | Batch event supervised classification | Phase 6 | 200, 422 |
| `POST` | `/api/v1/ml/train` | Administrative on-demand model retraining pipeline | Phase 5, 6 | 200 |
| `GET` | `/api/v1/ml/explain/global` | TreeSHAP global feature attribution summary and domain distribution | Phase 7 | 200 |
| `POST` | `/api/v1/ml/explain/event` | Single incident TreeSHAP local waterfall attribution breakdown | Phase 7 | 200, 422 |
| `POST` | `/api/v1/ml/explain/batch` | Batch incident TreeSHAP local waterfall explanations | Phase 7 | 200, 422 |
| `GET` | `/api/v1/compliance/frameworks` | Supported regulatory standards catalog and descriptions | Phase 8 | 200 |
| `GET` | `/api/v1/compliance/controls` | Full catalog of 17 compliance controls with remediation guides | Phase 8 | 200 |
| `POST` | `/api/v1/compliance/evaluate` | Deterministic compliance rule evaluation over telemetry events | Phase 8 | 200, 422 |
| `GET` | `/api/v1/compliance/summary` | Multi-cloud compliance posture summary and pass percentages | Phase 8 | 200 |
| `GET` | `/api/v1/compliance/report` | Downloadable structured JSON compliance audit report | Phase 8 | 200 |
| `GET` | `/api/v1/recommendations/playbooks` | Catalog of remediation playbooks with cloud and effort filters | Phase 9 | 200 |
| `GET` | `/api/v1/recommendations/playbooks/{id}` | Detailed playbook retrieval with CLI, Terraform, and Python code | Phase 9 | 200, 404 |
| `POST` | `/api/v1/recommendations/generate` | Context-aware recommendation synthesis for findings | Phase 9 | 200, 422 |
| `POST` | `/api/v1/recommendations/prioritize` | Intelligent multi-factor ranking of findings into an action queue | Phase 9 | 200, 422 |
| `POST` | `/api/v1/recommendations/simulate` | Perimeter risk posture improvement simulation | Phase 9 | 200, 422 |
| `GET` | `/api/v1/recommendations/stats` | Global metrics on playbook coverage, risk reduction, and effort | Phase 9 | 200 |
| `GET` | `/api/v1/findings` | Multi-cloud security findings list with search and filters | Phase 11 | 200 |
| `GET` | `/api/v1/findings/{finding_id}` | Granular finding detail with CLI/Terraform remediation commands | Phase 11 | 200, 404 |
| `PATCH` | `/api/v1/findings/{finding_id}/status` | Triage state update (`OPEN`, `INVESTIGATING`, `RESOLVED`, `FALSE_POSITIVE`) | Phase 11 | 200, 422 |

Interactive Swagger UI documentation is available at: `http://127.0.0.1:8001/api/docs`

---

## 11. Local Development, Testing & Operations Runbook

### Quick Launch Scripts

- **Start All Services**:
  ```cmd
  start.bat
  ```
  Spawns two independent windows: FastAPI backend on port 8001 and React Vite frontend on port 8000.
- **Stop All Services**:
  ```cmd
  stop.bat
  ```
  Gracefully terminates backend and frontend processes.
- **Run Automated UI Tests**:
  ```cmd
  test_ui.bat          :: Headless Playwright run
  test_ui.bat --ui     :: Interactive Playwright Visual Runner
  test_ui.bat --report :: View last generated HTML report
  ```

### Manual Setup & Execution

#### 1. Backend Service
```bash
cd backend

# 1. Activate Python virtual environment
.venv\Scripts\activate       # Windows
source .venv/bin/activate    # Linux / macOS

# 2. Install dependencies with dev tools
pip install -e ".[dev]"

# 3. Start FastAPI server
uvicorn app.main:app --reload --port 8001
```

#### 2. Frontend Application
```bash
cd frontend

# 1. Install Node modules
npm install

# 2. Launch Vite development server
npm run dev
```
Dashboard available at: `http://localhost:8000/`

### Automated Verification Suites

#### 1. Pytest Backend Suite (161 Tests)
```bash
backend\.venv\Scripts\python.exe -m pytest
```
*Verification*: 161 passed in ~25 seconds with 100% success rate across schemas, rules, ML models, TreeSHAP, compliance controls, recommendation playbooks, async repositories, and REST API routes.

#### 2. Playwright Frontend E2E Suite (26 Tests)
```bash
cd frontend
npm run test:e2e
```
*Verification*: 26 passed in ~1.1 minutes verifying dark carbon styles, navigation, finding master-detail filters, TreeSHAP waterfall cards, compliance matrices, and SecOps terminal drawer.

---

## 12. Academic References & Research Literature

1. **Isolation Forest**: Liu, F. T., Ting, K. M., & Zhou, Z. H. (2008). *Isolation Forest*. Eighth IEEE International Conference on Data Mining (ICDM), pp. 413-422. DOI: 10.1109/ICDM.2008.17.
2. **XGBoost**: Chen, T., & Guestrin, C. (2016). *XGBoost: A Scalable Tree Boosting System*. ACM SIGKDD International Conference on Knowledge Discovery and Data Mining (KDD), pp. 785-794. DOI: 10.1145/2939672.2939785.
3. **TreeSHAP**: Lundberg, S. M., et al. (2020). *From local explanations to global understanding with explainable AI for trees*. Nature Machine Intelligence, 2(1), pp. 56-67. DOI: 10.1038/s42256-019-0138-9.
4. **UNSW-NB15 Dataset**: Moustafa, N., & Slay, J. (2015). *UNSW-NB15: A comprehensive data set for network intrusion detection systems*. IEEE Military Communications Conference (MILCOM), pp. 709-714. DOI: 10.1109/MILCOM.2015.7357535.
5. **CIS Benchmarks**: Center for Internet Security. (2023). *CIS Amazon Web Services Foundations Benchmark v1.4.0*, *CIS Microsoft Azure Foundations Benchmark v2.0.0*, *CIS Google Cloud Platform Foundation Benchmark v1.3.0*.
6. **NIST Security Framework**: National Institute of Standards and Technology. (2020). *Security and Privacy Controls for Information Systems and Organizations*. NIST Special Publication 800-53, Revision 5. DOI: 10.6028/NIST.SP.800-53r5.
