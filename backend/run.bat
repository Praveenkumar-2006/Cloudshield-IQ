@echo off
setlocal
title CloudShield IQ - Backend API (Port 8001)

cd /d "%~dp0"
echo ================================================================
echo   Starting CloudShield IQ - Backend API
echo   Swagger Documentation: http://127.0.0.1:8001/api/docs
echo   Health Check:          http://127.0.0.1:8001/api/v1/health
echo ================================================================
echo.

if exist ".venv\Scripts\activate.bat" (
    echo Activating virtual environment in .venv...
    call ".venv\Scripts\activate.bat"
    python -m uvicorn app.main:app --reload --port 8001
) else (
    echo Running with system Python...
    python -m uvicorn app.main:app --reload --port 8001
)

if errorlevel 1 (
    echo.
    echo [ERROR] Backend server stopped with an error.
    pause
)
