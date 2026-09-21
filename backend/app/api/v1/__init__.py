"""
CloudShield IQ — API v1 Router
================================
Central router for all v1 endpoints.

Each feature area has its own sub-router in app/api/v1/endpoints/.
Add new routers here as modules are built — do not add route
handlers directly to this file.

Current registration status:
  [x] health          — infrastructure readiness probes
  [ ] auth            — authentication (Phase: Auth module)
  [ ] users           — user management (Phase: Auth module)
  [ ] cloud-sources   — cloud account management (Phase: Ingestion)
  [ ] ingestion       — data upload and ingestion (Phase: Ingestion)
  [ ] assessments     — security assessments (Phase: ML)
  [x] findings        — security findings (Phase 11: Repositories & API)
  [ ] risk            — risk analysis (Phase: ML)
  [ ] compliance      — compliance evaluation (Phase: Compliance)
  [ ] recommendations — remediation recommendations (Phase: Recommendations)
  [ ] reports         — report generation (Phase: Reports)
"""

from fastapi import APIRouter

from app.api.v1.endpoints import compliance, findings, health, ingestion, ml, recommendations

router = APIRouter()

# Infrastructure & Modules
router.include_router(health.router, prefix="/health", tags=["Health"])
router.include_router(ingestion.router, prefix="/ingestion", tags=["Data Ingestion"])
router.include_router(ml.router, prefix="/ml", tags=["Machine Learning"])
router.include_router(compliance.router, prefix="/compliance", tags=["Compliance"])
router.include_router(recommendations.router, prefix="/recommendations", tags=["Recommendations"])
router.include_router(findings.router, prefix="/findings", tags=["Security Findings"])

# Stub routers below — uncomment as each module is implemented
# from app.api.v1.endpoints import auth
# router.include_router(auth.router, prefix="/auth", tags=["Authentication"])

# from app.api.v1.endpoints import users
# router.include_router(users.router, prefix="/users", tags=["Users"])

# from app.api.v1.endpoints import assessments
# router.include_router(assessments.router, prefix="/assessments", tags=["Assessments"])
