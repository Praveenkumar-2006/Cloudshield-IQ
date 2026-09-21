@echo off
setlocal

title CloudShield IQ Launcher

echo ================================================================
echo            CloudShield IQ - Startup Launcher
echo    AI-Based Multi-Cloud Security Risk and Compliance
echo ================================================================
echo.

:: 1. Locate project root directory
if exist "%~dp0backend\run.bat" (
    set "PROJECT_ROOT=%~dp0"
) else if exist "%~dp0cloudshield-iq-phase0-1\cloudshield-iq\backend\run.bat" (
    set "PROJECT_ROOT=%~dp0cloudshield-iq-phase0-1\cloudshield-iq\"
) else (
    echo [ERROR] Cannot locate CloudShield IQ project folders.
    echo Please make sure this script is in the project directory.
    echo.
    pause
    exit /b 1
)

echo [*] Project root: "%PROJECT_ROOT%"

:: 2. Check Node.js and npm
echo [*] Checking Node.js environment...
where node >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Node.js is not installed or not found in PATH!
    echo Please install Node.js 20+ from https://nodejs.org
    pause
    exit /b 1
)

where npm >nul 2>&1
if errorlevel 1 (
    echo [ERROR] npm is not installed or not found in PATH!
    pause
    exit /b 1
)

:: 3. Check Python
echo [*] Checking Python backend environment...
if exist "%PROJECT_ROOT%backend\.venv\Scripts\python.exe" (
    echo [OK] Python virtual environment found in backend\.venv
) else (
    echo [!] Virtual environment not found in backend\.venv. Checking system Python...
    where python >nul 2>&1
    if errorlevel 1 (
        echo [ERROR] Python is not installed or not found in PATH!
        echo Please install Python 3.11+ from https://python.org
        pause
        exit /b 1
    )
)

:: 4. Optional Docker Check
echo [*] Checking Docker status...
docker info >nul 2>&1
if not errorlevel 1 (
    echo [OK] Docker daemon is running.
) else (
    echo [i] Docker is offline - Backend will start in development mode with offline DB.
)

echo.
echo [*] Launching CloudShield IQ services in separate windows...

:: 5. Launch Backend API in new window
start "CloudShield IQ - Backend API" cmd /k call "%PROJECT_ROOT%backend\run.bat"

:: 6. Launch Frontend UI in new window
start "CloudShield IQ - Frontend UI" cmd /k call "%PROJECT_ROOT%frontend\run.bat"

:: 7. Summary Display
echo.
echo ================================================================
echo               CloudShield IQ is Running!
echo ================================================================
echo   Frontend Dashboard:    http://localhost:8000
echo   Backend API URL:       http://127.0.0.1:8001
echo   Swagger API Docs:      http://127.0.0.1:8001/api/docs
echo   Health Status:         http://127.0.0.1:8001/api/v1/health
echo ================================================================
echo.
echo Launching Frontend Dashboard in your browser in 3 seconds...
ping -n 4 127.0.0.1 >nul
start http://localhost:8000

echo.
echo Both services are running in their own windows.
echo To shut down all services, run stop.bat.
echo.
pause
