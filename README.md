# CloudShield IQ

**AI-Based Multi-Cloud Security Risk Assessment and Compliance Monitoring Framework**

Final-Year Information Technology Project

---

## What This Is

CloudShield IQ is a software platform that assesses the security posture of multi-cloud environments. It detects anomalous security behaviour, evaluates compliance against defined security controls, explains ML-based risk decisions, and provides actionable remediation guidance through a centralized dashboard.

**This project is in active development. Features listed below reflect the design target, not current implementation status.**

---

## Architecture

```
Cloud Security Sources (AWS / Azure / GCP / CSV / JSON)
           │
           ▼
   Data Ingestion Layer
           │
           ▼
  Validation + Normalization
           │
    ┌──────┴──────┐
    ▼             ▼
 ML Engine    Compliance Engine
    │             │
    ▼             ▼
Risk Score    Pass/Fail/Partial
    │
    ▼
SHAP Explainability
    │
    ▼
Recommendation Engine
    │
    ▼
  Dashboard ──► Optional LLM (natural-language explanation only)
    │
    ▼
  Reports
```

**Core separation of responsibilities:**
- **ML** → Security risk and anomaly intelligence (probabilistic)
- **Rules** → Compliance verification (deterministic)
- **SHAP** → Model explanation (derived from ML model)
- **LLM** → Optional natural-language explanation ONLY — not a decision-maker

---

## Technology Stack

| Layer | Technology |
|---|---|
| Backend API | Python 3.11, FastAPI, Pydantic v2 |
| Database | PostgreSQL 16, SQLAlchemy 2.0 (async), Alembic |
| ML | scikit-learn, XGBoost, SHAP |
| Frontend | React, TypeScript, Tailwind CSS, Recharts |
| Auth | Argon2id password hashing, JWT |
| Containers | Docker, Docker Compose |
| CI/CD | GitHub Actions |

---

## Project Status

| Phase | Description | Status |
|---|---|---|
| 0 | Environment setup | ✅ Done |
| 1 | Project skeleton | ✅ Done |
| 2 | Dataset discovery and profiling | ✅ Done |
| 3 | Common data schema | ✅ Done |
| 4 | Baseline rule-based risk engine | ✅ Done |
| 5 | ML anomaly detection | ✅ Done |
| 6 | Supervised risk classification | ✅ Done |
| 7 | SHAP explainability | ✅ Done |
| 8 | Compliance engine | ✅ Done |
| 9 | Recommendation engine | ✅ Done |
| 10 | FastAPI integration | ✅ Done |
| 11 | PostgreSQL integration | ✅ Done |
| 12 | React dashboard | ✅ Done |
| 13 | AWS live integration | ⬜ Pending |
| 14 | Azure/GCP (if scope permits) | ⬜ Pending |
| 15 | Testing | ✅ Done |
| 16 | Dockerization | ✅ Done |
| 17 | Deployment | ✅ Done |
| 18 | Documentation + final evaluation | 🟡 In Progress |

---

## Prerequisites

- Python 3.11+
- Node.js 20+
- Docker Desktop
- PostgreSQL 16 (via Docker or local)
- Git

---

## Local Development Setup

### 1. Clone and configure

```bash
git clone <your-repo-url> cloudshield-iq
cd cloudshield-iq
```

### 2. Backend setup

```bash
cd backend

# Create virtual environment
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate

# Install dependencies (includes dev tools)
pip install -e ".[dev]"

# Configure environment
cp .env.example .env
# Edit .env — fill in SECRET_KEY, JWT_SECRET_KEY, DATABASE_URL
```

### 3. Start database (Docker)

```bash
docker run -d \
  --name cloudshield_postgres \
  -e POSTGRES_DB=cloudshield_iq \
  -e POSTGRES_USER=cloudshield \
  -e POSTGRES_PASSWORD=devpassword \
  -p 5432:5432 \
  postgres:16-alpine
```

### 4. Run database migrations

```bash
cd backend
alembic upgrade head
```

### 5. Start backend

```bash
uvicorn app.main:app --reload --port 8000
```

API docs available at: http://localhost:8000/api/docs

### 6. Frontend setup

```bash
cd frontend
npm install
npm run dev
```

Frontend available at: http://localhost:5173

### 7. Run with Docker Containers

**Option A: Development Mode (with hot-reloading):**
```bash
# Using root compose launcher
docker compose up

# Or explicit compose file:
docker compose -f deployment/docker/docker-compose.dev.yml up
```
- Backend API: http://localhost:8000
- Frontend UI: http://localhost:5173
- Postgres DB: localhost:5432

**Option B: Hardened Production Mode (with Nginx Gateway reverse proxy):**
```bash
# Linux / macOS / WSL
./deployment/scripts/deploy.sh prod

# Windows Command Prompt
deployment\scripts\deploy.bat prod
```
- Unified Gateway URL: http://localhost (Port 80)
- API Health Endpoint: http://localhost/api/v1/health
- Swagger Docs: http://localhost/docs

---

## Running Tests

```bash
cd backend
pytest                    # All tests with coverage
pytest tests/unit/        # Unit tests only
pytest tests/integration/ # Integration tests only
pytest -k test_health     # Specific test
```

---

## Project Structure

```
cloudshield-iq/
├── backend/                    # FastAPI backend
│   ├── app/
│   │   ├── main.py             # Application factory
│   │   ├── core/               # Config, logging, database
│   │   ├── api/v1/endpoints/   # Route handlers
│   │   ├── models/             # SQLAlchemy ORM models
│   │   ├── schemas/            # Pydantic request/response schemas
│   │   ├── services/           # Business logic
│   │   ├── ml/                 # ML models, features, SHAP
│   │   ├── compliance/         # Compliance engine and controls
│   │   └── recommendations/    # Recommendation engine
│   ├── pyproject.toml
│   ├── .env.example            # Copy to .env — never commit .env
│   └── Dockerfile.dev
├── frontend/                   # React frontend
├── ml/                         # ML experimentation (Jupyter, scripts)
├── datasets/                   # Dataset storage (raw files not committed)
├── database/                   # Migrations, seeds, schemas
├── docs/                       # Architecture, API, research docs
├── tests/                      # All tests
├── deployment/                 # Docker, CI/CD
└── research/                   # Dataset analysis, research notes
```

---

## Security Notes

- Never commit `.env` files or any credentials
- Passwords are hashed with Argon2id — never stored in plaintext
- All API routes require authentication except `/health` and `/api/docs`
- File uploads are validated by MIME type, extension, and size
- Database access uses parameterized queries via SQLAlchemy ORM
- CORS is restricted to configured origins

---

## Academic Integrity

This project distinguishes between:
- ✅ **Implemented** — built and tested
- 📐 **Designed** — architecture planned, not yet built
- 🔬 **Experimental** — results pending measurement
- 📚 **Literature** — from published research

No experimental results, benchmark claims, or dataset statistics are fabricated.

---

## Constraints

- No blockchain
- No IoT / hardware components
- No LLM as primary security decision-maker
- No claims of live multi-cloud monitoring before implementation
- No accuracy claims without experimental measurement

---

## License

Academic project — not licensed for production use.
