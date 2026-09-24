@echo off
title AllTools-CyberSec Backend (Port 8000)
cd /d "%~dp0\.."

echo =====================================================================
echo  AllTools-CyberSec Backend (FastAPI + Scope Guard Engine)
echo =====================================================================
echo  Port        : 8000
echo  API Docs    : http://localhost:8000/docs
echo  Health Check: http://localhost:8000/health
echo =====================================================================
echo.

set "ROOT_DIR=%cd%"
set "PYTHONPATH=%ROOT_DIR%;%ROOT_DIR%\backend"
set "PYTHON_EXE=%ROOT_DIR%\backend\.venv\Scripts\python.exe"

if not exist "%PYTHON_EXE%" (
    echo [!] Virtual environment di backend\.venv tidak ditemukan.
    echo [*] Mencoba menggunakan Python global dari PATH...
    set "PYTHON_EXE=python"
)

echo [*] Menjalankan Uvicorn server pada http://127.0.0.1:8000 ...
"%PYTHON_EXE%" -m uvicorn app.main:app --app-dir backend --host 127.0.0.1 --port 8000 --reload

if %errorlevel% neq 0 (
    echo.
    echo [ERROR] Backend terhenti atau gagal dijalankan (Exit Code: %errorlevel%).
    pause
)
