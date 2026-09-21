"""
CloudShield IQ — FastAPI Application Entry Point
=================================================
Application factory pattern: the app object is created by
create_application() so it can be imported cleanly in tests
without triggering startup side-effects.

Startup sequence:
1. Logging configured
2. Settings validated (will crash-fast if misconfigured)
3. Database engine created
4. Upload directory created
5. Routers registered
6. Middleware applied
"""

from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.core.config import get_settings
from app.core.logging import configure_logging, get_logger

logger = get_logger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """
    Application lifespan manager.

    Everything before 'yield' runs at startup.
    Everything after 'yield' runs at shutdown.
    """
    settings = get_settings()

    # 1. Configure logging first so all subsequent logs are structured
    configure_logging()
    logger.info("Starting CloudShield IQ", version="0.1.0", env=settings.APP_ENV)

    # 2. Ensure upload directory exists
    settings.UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
    settings.MODEL_DIR.mkdir(parents=True, exist_ok=True)

    # 3. Verify database connectivity
    from app.core.database import engine
    from sqlalchemy import text
    try:
        async with engine.connect() as conn:
            await conn.execute(text("SELECT 1"))
        logger.info("Database connection verified")
    except Exception as exc:
        if settings.APP_ENV == "production":
            logger.error("Database connection failed — startup aborted", error=str(exc))
            raise
        logger.warning("Database connection failed — continuing in dev mode (DB offline)", error=str(exc))

    logger.info("CloudShield IQ started successfully")
    yield

    # Shutdown
    logger.info("Shutting down CloudShield IQ")
    await engine.dispose()
    logger.info("Database connections closed")


def create_application() -> FastAPI:
    """
    Create and configure the FastAPI application.

    Returns a fully configured app instance. This function is the
    single place where all application-level concerns are wired up.
    """
    settings = get_settings()

    app = FastAPI(
        title="CloudShield IQ API",
        description=(
            "AI-Based Multi-Cloud Security Risk Assessment and Compliance Monitoring. "
            "Provides security posture assessment, anomaly detection, compliance "
            "evaluation, and remediation recommendations for multi-cloud environments."
        ),
        version="0.1.0",
        docs_url="/api/docs" if settings.APP_ENV != "production" else None,
        redoc_url="/api/redoc" if settings.APP_ENV != "production" else None,
        openapi_url="/api/openapi.json" if settings.APP_ENV != "production" else None,
        lifespan=lifespan,
    )

    # ------------------------------------------------------------------ #
    # Middleware — order matters: outermost middleware runs first
    # ------------------------------------------------------------------ #

    # CORS — restrict to configured origins in production
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.CORS_ALLOWED_ORIGINS,
        allow_credentials=True,
        allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE"],
        allow_headers=["Authorization", "Content-Type", "X-Request-ID"],
        expose_headers=["X-Request-ID"],
    )

    # ------------------------------------------------------------------ #
    # Exception Handlers
    # ------------------------------------------------------------------ #

    @app.exception_handler(Exception)
    async def unhandled_exception_handler(request: Request, exc: Exception) -> JSONResponse:
        """
        Catch-all for unhandled exceptions.

        Returns a generic error to the client — never expose internal
        error details in production. The full exception is logged.
        """
        log = get_logger(__name__)
        log.error(
            "Unhandled exception",
            path=str(request.url),
            method=request.method,
            error=str(exc),
            exc_info=True,
        )
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={
                "detail": "An internal server error occurred.",
                "code": "INTERNAL_ERROR",
            },
        )

    # ------------------------------------------------------------------ #
    # Routers — registered here as modules are built
    # ------------------------------------------------------------------ #
    from app.api.v1 import router as api_v1_router
    app.include_router(api_v1_router, prefix="/api/v1")

    # ------------------------------------------------------------------ #
    # Health endpoint — outside /api/v1 so load balancers can reach it
    # ------------------------------------------------------------------ #
    @app.get("/health", tags=["Infrastructure"])
    async def health_check() -> dict:
        """
        Liveness probe for load balancers and Docker healthchecks.
        Returns 200 if the application process is alive.
        Does NOT check database connectivity (use /api/v1/health/ready for that).
        """
        return {"status": "ok", "service": "cloudshield-iq"}

    return app


# Module-level app instance for uvicorn
app = create_application()
