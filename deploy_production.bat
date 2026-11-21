@echo off
title NETGUARD — Production Deployment
color 0B
cls

echo ==============================================================================
echo          NETGUARD — Network Security & ARP Threat Detection System
echo                       Production Deployment Launcher
echo ==============================================================================
echo.

:: Change to script directory
cd /d "%~dp0"

echo [*] Checking Python environment...
where python >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] Python is not found in system PATH.
    echo Please install Python 3.10+ from python.org or the Microsoft Store.
    pause
    exit /b 1
)

:: Test Python version
python -c "import sys; print(f'[*] Python version: {sys.version.split()[0]}')"

echo [*] Verifying production dependencies (Flask, Scapy, Waitress)...
python -m pip install -q -r requirements.txt
if %errorlevel% neq 0 (
    echo [WARN] Global pip install failed, trying virtual environment...
    if exist "venv\Scripts\pip.exe" (
        venv\Scripts\pip.exe install -q -r requirements.txt
    )
)

echo [*] Checking Npcap / WinPcap packet capture driver...
if exist "%SystemRoot%\System32\Npcap" (
    echo [*] Npcap driver verified in System32.
) else (
    echo [NOTE] Npcap recommended for high-speed raw packet capture on Windows.
)

echo.
echo ==============================================================================
echo  Launching NETGUARD Enterprise Production Server (Waitress WSGI)...
echo ==============================================================================
echo.

:: Open the browser after 2 seconds in the background
start "" cmd /c "timeout /t 2 /nobreak >nul & start http://127.0.0.1:5000"

:: Start the production WSGI server
python server.py

pause
