@echo off
chcp 65001 >nul
echo ========================================
echo   LIB Analyzer Web Server
echo ========================================
echo.

python --version >nul 2>&1
if errorlevel 1 (
    echo [Error] Python not found, please install Python 3.7+
    pause
    exit /b 1
)

echo [Check] Checking dependencies...
echo.

python -m pip install -r requirements.txt --quiet
if errorlevel 1 (
    echo [Error] Failed to install dependencies
    pause
    exit /b 1
)

echo [Success] Dependencies check completed
echo.

echo [Starting] Launching Web Server...
echo.
echo Server URL: http://localhost:5000
echo Press Ctrl+C to stop
echo.
echo ========================================
echo.

python web_server.py

pause
