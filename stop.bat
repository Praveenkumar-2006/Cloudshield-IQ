@echo off
setlocal

title CloudShield IQ - Shutdown

echo ================================================================
echo            CloudShield IQ - Service Shutdown
echo ================================================================
echo.

:: 1. Terminate processes listening on port 8000 (Frontend)
echo [*] Stopping processes on port 8000 (Frontend)...
for /f "tokens=5" %%p in ('netstat -ano ^| findstr ":8000 "') do (
    echo [*] Terminating PID %%p on port 8000...
    taskkill /f /pid %%p >nul 2>&1
)

:: 2. Terminate processes listening on port 8001 (Backend)
echo [*] Stopping processes on port 8001 (Backend)...
for /f "tokens=5" %%p in ('netstat -ano ^| findstr ":8001 "') do (
    echo [*] Terminating PID %%p on port 8001...
    taskkill /f /pid %%p >nul 2>&1
)

:: 3. Close windows if still open
taskkill /FI "WINDOWTITLE eq CloudShield IQ - Backend API*" /F >nul 2>&1
taskkill /FI "WINDOWTITLE eq CloudShield IQ - Frontend UI*" /F >nul 2>&1

echo.
echo [OK] All CloudShield IQ services have been stopped.
echo.
pause
