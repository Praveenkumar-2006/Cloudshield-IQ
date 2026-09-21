#!/usr/bin/env bash
# ============================================================
# CloudShield IQ — Container & Service Health Probing Script
# ============================================================
set -euo pipefail

TARGET_HOST="${1:-http://localhost}"
API_URL="${TARGET_HOST}/api/v1/health"
NGINX_URL="${TARGET_HOST}/nginx-health"

echo "================================================================"
echo "         CloudShield IQ — Production Health Probe"
echo "================================================================"
echo "[*] Checking Target Host: ${TARGET_HOST}"

# 1. Probe Nginx Gateway
echo -n "[*] Probing Nginx Gateway (${NGINX_URL})... "
if command -v curl &> /dev/null; then
    NGINX_STATUS=$(curl -s -o /dev/null -w "%{http_code}" "${NGINX_URL}" || true)
elif command -v wget &> /dev/null; then
    NGINX_STATUS=$(wget -q -S --spider "${NGINX_URL}" 2>&1 | awk '/HTTP\// {print $2}' | tail -1 || true)
fi

if [[ "${NGINX_STATUS}" == "200" ]]; then
    echo "[OK] (HTTP 200)"
else
    echo "[WARN] Gateway responded with HTTP ${NGINX_STATUS}"
fi

# 2. Probe FastAPI Backend Health
echo -n "[*] Probing Backend API (${API_URL})... "
if command -v curl &> /dev/null; then
    API_RESPONSE=$(curl -s -w "\n%{http_code}" "${API_URL}" || true)
    HTTP_CODE=$(echo "${API_RESPONSE}" | tail -n1)
    BODY=$(echo "${API_RESPONSE}" | sed '$d')
else
    HTTP_CODE="unknown"
    BODY=""
fi

if [[ "${HTTP_CODE}" == "200" ]]; then
    echo "[OK] (HTTP 200)"
    echo "[*] API Response: ${BODY}"
else
    echo "[FAIL] Backend API returned HTTP ${HTTP_CODE}"
    exit 1
fi

echo "================================================================"
echo " All CloudShield IQ production endpoints verified operational."
echo "================================================================"
