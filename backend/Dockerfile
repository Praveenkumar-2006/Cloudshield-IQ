# ============================================================
# Stage 1: Build virtualenv & dependencies
# ============================================================
FROM python:3.11-slim AS builder

WORKDIR /build

# Install build tools required for native C/C++ extensions
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Create virtual environment
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Upgrade pip and install production dependencies
COPY pyproject.toml .
RUN pip install --no-cache-dir --upgrade pip setuptools wheel && \
    pip install --no-cache-dir .

# ============================================================
# Stage 2: Final minimal runtime
# ============================================================
FROM python:3.11-slim AS runtime

LABEL maintainer="CloudShield IQ Project"
LABEL description="CloudShield IQ Backend — Production"

# Install minimal runtime libraries (libmagic for file type detection, curl for healthcheck)
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    libmagic1 \
    && rm -rf /var/lib/apt/lists/*

# Create unprivileged system user for container security hardening
RUN groupadd -g 10001 cloudshield && \
    useradd -u 10001 -g cloudshield -s /bin/bash -m cloudshield

WORKDIR /app

# Copy virtualenv from builder
COPY --from=builder /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH" \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

# Copy application source code
COPY --chown=cloudshield:cloudshield app/ ./app/
COPY --chown=cloudshield:cloudshield ml/ ./ml/
COPY --chown=cloudshield:cloudshield alembic/ ./alembic/
COPY --chown=cloudshield:cloudshield alembic.ini pyproject.toml ./

# Ensure data directories exist with proper write permissions for non-root user
RUN mkdir -p /app/uploads /app/ml/models && \
    chown -R cloudshield:cloudshield /app/uploads /app/ml/models

# Switch to non-root user
USER cloudshield

EXPOSE 8000

# Container healthcheck
HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
    CMD curl -f http://localhost:8000/api/v1/health || exit 1

# Launch production server with Uvicorn
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "2", "--no-access-log"]
