@echo off
title AllTools-CyberSec Server Stopper
cd /d "%~dp0"

echo =====================================================================
echo              ALLTOOLS-CYBERSEC SERVER SHUTDOWN
echo =====================================================================
echo.

set KILLED=0

echo [*] Memeriksa dan menghentikan proses Backend (Port 8000)...
for /f "tokens=5" %%a in ('netstat -ano 2^>nul ^| findstr :8000 ^| findstr LISTENING') do (
    echo [*] Menghentikan PID %%a (Backend)
    taskkill /F /PID %%a >nul 2>nul
    set KILLED=1
)

echo [*] Memeriksa dan menghentikan proses Frontend (Port 5173)...
for /f "tokens=5" %%a in ('netstat -ano 2^>nul ^| findstr :5173 ^| findstr LISTENING') do (
    echo [*] Menghentikan PID %%a (Frontend)
    taskkill /F /PID %%a >nul 2>nul
    set KILLED=1
)

echo.
echo =====================================================================
echo  [OK] Seluruh server AllTools-CyberSec telah dihentikan.
echo =====================================================================
echo.
timeout /t 3
