@echo off
setlocal
title CloudShield IQ - Frontend UI (Port 8000)

cd /d "%~dp0"
echo ================================================================
echo   Starting CloudShield IQ - Frontend UI
echo   Dashboard URL: http://localhost:8000
echo ================================================================
echo.

if not exist "node_modules" (
    echo [*] node_modules not found. Installing dependencies...
    call npm install
)

call npm run dev

if errorlevel 1 (
    echo.
    echo [ERROR] Frontend server stopped with an error.
    pause
)
