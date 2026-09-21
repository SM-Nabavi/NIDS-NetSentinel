@echo off
title NIDS NetSentinel - Dashboard Launcher
color 0A
cls
echo ======================================================================
echo           NIDS NetSentinel - Real-Time Intrusion Detection System
echo ======================================================================
echo.
echo [1/4] Checking Python installation...
python --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Python is not installed or not added to PATH!
    echo Please install Python from https://www.python.org/ and check 'Add Python to PATH'
    pause
    exit /b 1
)

if not exist "%~dp0data" mkdir "%~dp0data"

echo.
echo [2/4] Initializing database (creating tables if missing)...
python "%~dp0detection-service\src\init_db.py"
if errorlevel 1 (
    echo [ERROR] Database initialization failed!
    pause
    exit /b 1
)

echo.
echo [3/4] Stopping any existing pipeline processes...
taskkill /F /IM flow-capture.exe >nul 2>&1
taskkill /F /IM python.exe /FI "WINDOWTITLE eq NIDS Buffer Writer*" >nul 2>&1
taskkill /F /IM python.exe /FI "WINDOWTITLE eq NIDS Main Processor*" >nul 2>&1

echo.
echo [4/4] Launching SOC Server (Dashboard)...
start http://127.0.0.1:3000

python "%~dp0detection-service\src\soc_server.py" 3000


pause