@echo off
setlocal

title CloudShield IQ - Playwright Test Runner

if exist "%~dp0frontend\package.json" (
    set "FRONTEND_DIR=%~dp0frontend"
) else if exist "%~dp0cloudshield-iq-phase0-1\cloudshield-iq\frontend\package.json" (
    set "FRONTEND_DIR=%~dp0cloudshield-iq-phase0-1\cloudshield-iq\frontend"
) else (
    echo [ERROR] Cannot locate frontend folder.
    exit /b 1
)

cd /d "%FRONTEND_DIR%"

set "ARG1=%~1"

if "%ARG1%"=="--ui" (
    echo [*] Starting Playwright Interactive UI Mode...
    call npx playwright test --ui
) else if "%ARG1%"=="--report" (
    echo [*] Opening Playwright HTML Test Report...
    call npx playwright show-report
) else if "%ARG1%"=="--headed" (
    echo [*] Running Playwright E2E tests in headed browser mode...
    call npx playwright test --headed
) else (
    echo [*] Running Playwright tests...
    call npx playwright test %*
)
