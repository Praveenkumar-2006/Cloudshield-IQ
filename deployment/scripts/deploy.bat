@echo off
setlocal enabledelayedexpansion

title CloudShield IQ - Production Docker Deployment

echo ================================================================
echo           CloudShield IQ - Docker Deployment Script
echo ================================================================
echo.

set "SCRIPT_DIR=%~dp0"
set "PROJECT_ROOT=%SCRIPT_DIR%..\..\"

:: 1. Check Docker CLI
where docker >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Docker CLI was not found in PATH!
    echo Please install Docker Desktop from https://www.docker.com/products/docker-desktop
    pause
    exit /b 1
)

:: 2. Check Docker Daemon
echo [*] Checking Docker daemon status...
docker info >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Docker daemon is offline!
    echo Please start Docker Desktop and run this script again.
    pause
    exit /b 1
)
echo [OK] Docker daemon is running.

:: 3. Mode Selection (default: prod)
set "MODE=%~1"
if "%MODE%"=="" set "MODE=prod"

set "COMPOSE_FILE=%PROJECT_ROOT%deployment\docker\docker-compose.%MODE%.yml"
if not exist "%COMPOSE_FILE%" (
    echo [ERROR] Compose file not found: %COMPOSE_FILE%
    echo Available modes: prod, dev
    pause
    exit /b 1
)

echo [*] Target mode: %MODE%
echo [*] Compose file: %COMPOSE_FILE%
echo.

:: 4. Build containers
echo [*] Building container images...
docker compose -f "%COMPOSE_FILE%" build
if errorlevel 1 (
    echo [ERROR] Docker build failed!
    pause
    exit /b 1
)

:: 5. Launch containers
echo [*] Starting containers in detached mode...
docker compose -f "%COMPOSE_FILE%" up -d
if errorlevel 1 (
    echo [ERROR] Failed to start containers!
    pause
    exit /b 1
)

echo.
echo [*] Services status:
docker compose -f "%COMPOSE_FILE%" ps

echo.
echo ================================================================
echo   Deployment Completed Successfully!
if "%MODE%"=="prod" (
    echo   CloudShield IQ Gateway: http://localhost (Port 80)
    echo   Backend API Health:     http://localhost/api/v1/health
    echo   API Documentation:      http://localhost/docs
) else (
    echo   Frontend Dashboard:     http://localhost:5173
    echo   Backend API URL:        http://localhost:8000
)
echo ================================================================
echo.
pause
