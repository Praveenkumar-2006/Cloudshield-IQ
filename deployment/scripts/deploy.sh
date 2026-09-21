#!/usr/bin/env bash
# ============================================================
# CloudShield IQ — Automated Deployment Script
# ============================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

echo "================================================================"
echo "          CloudShield IQ — Production Deployment"
echo "================================================================"

# 1. Verify Docker and Docker Compose
echo "[*] Verifying Docker environment..."
if ! command -v docker &> /dev/null; then
    echo "[ERROR] Docker is not installed or not in PATH."
    exit 1
fi

if ! docker compose version &> /dev/null; then
    echo "[ERROR] Docker Compose (v2) is not available."
    exit 1
fi

# 2. Check if daemon is active
if ! docker info &> /dev/null; then
    echo "[ERROR] Docker daemon is not running. Please start Docker."
    exit 1
fi

echo "[OK] Docker environment verified."

# 3. Mode Selection (default: production)
MODE="${1:-prod}"
COMPOSE_FILE="${PROJECT_ROOT}/deployment/docker/docker-compose.${MODE}.yml"

if [[ ! -f "${COMPOSE_FILE}" ]]; then
    echo "[ERROR] Compose file not found: ${COMPOSE_FILE}"
    echo "Available modes: prod, dev"
    exit 1
fi

echo "[*] Deploying stack in '${MODE}' mode..."
echo "[*] Using compose file: ${COMPOSE_FILE}"

# 4. Pull and build containers
cd "${PROJECT_ROOT}"
docker compose -f "${COMPOSE_FILE}" build

# 5. Spin up services in detached mode
docker compose -f "${COMPOSE_FILE}" up -d

# 6. Verify health
echo "[*] Waiting for services to become healthy..."
sleep 10
docker compose -f "${COMPOSE_FILE}" ps

echo "================================================================"
echo " Deployment successful!"
if [[ "${MODE}" == "prod" ]]; then
    echo " CloudShield IQ Gateway: http://localhost (Port 80)"
    echo " Backend API Endpoint:   http://localhost/api/v1/health"
    echo " API Documentation:      http://localhost/docs"
else
    echo " Frontend Dashboard:     http://localhost:5173"
    echo " Backend API URL:        http://localhost:8000"
fi
echo "================================================================"
