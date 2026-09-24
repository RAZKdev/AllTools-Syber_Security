@echo off
title AllTools-CyberSec Frontend (Port 5173)
cd /d "%~dp0\..\frontend"

echo =====================================================================
echo  AllTools-CyberSec Frontend (React + Vite)
echo =====================================================================
echo  Port        : 5173
echo  UI URL      : http://localhost:5173
echo =====================================================================
echo.

if not exist "node_modules\" (
    echo [*] Dependensi frontend belum terpasang. Menjalankan npm install...
    call npm install
)

echo [*] Menjalankan Vite dev server...
call npm run dev

if %errorlevel% neq 0 (
    echo.
    echo [ERROR] Frontend terhenti atau gagal dijalankan (Exit Code: %errorlevel%).
    pause
)
