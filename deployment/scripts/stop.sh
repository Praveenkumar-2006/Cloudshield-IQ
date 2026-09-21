#!/usr/bin/env bash
# ============================================================
# CloudShield IQ — Stop Containers Script
# ============================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

MODE="${1:-prod}"
COMPOSE_FILE="${PROJECT_ROOT}/deployment/docker/docker-compose.${MODE}.yml"

echo "[*] Stopping CloudShield IQ (${MODE} mode)..."
if [[ -f "${COMPOSE_FILE}" ]]; then
    docker compose -f "${COMPOSE_FILE}" down
else
    docker compose -f "${PROJECT_ROOT}/deployment/docker/docker-compose.dev.yml" down 2>/dev/null || true
    docker compose -f "${PROJECT_ROOT}/deployment/docker/docker-compose.prod.yml" down 2>/dev/null || true
fi

echo "[OK] CloudShield IQ containers stopped cleanly."
