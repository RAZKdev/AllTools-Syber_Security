@echo off
setlocal enabledelayedexpansion
title AllTools-CyberSec Launcher
cd /d "%~dp0"

echo =====================================================================
echo           ALLTOOLS-CYBERSEC DEFENSIVE SECURITY WORKBENCH
echo =====================================================================
echo.
echo [*] Memeriksa dependensi sistem...

:: 1. Verifikasi Python
where python >nul 2>nul
if %errorlevel% neq 0 (
    echo [ERROR] Python tidak ditemukan di PATH sistem!
    echo Silakan install Python 3.10+ dan pastikan dicentang "Add Python to PATH".
    echo.
    pause
    exit /b 1
)

:: 2. Verifikasi Node.js / NPM
where npm >nul 2>nul
if %errorlevel% neq 0 (
    echo [ERROR] Node.js / NPM tidak ditemukan di PATH sistem!
    echo Silakan install Node.js (v18+) dari https://nodejs.org/
    echo.
    pause
    exit /b 1
)

:: 3. Setup Virtual Environment Backend jika belum ada
set "VENV_DIR=%~dp0backend\.venv"
set "PYTHON_EXE=%VENV_DIR%\Scripts\python.exe"

if not exist "%PYTHON_EXE%" (
    echo [*] backend\.venv belum ditemukan. Membuat virtual environment...
    python -m venv "%VENV_DIR%"
    if %errorlevel% neq 0 (
        echo [ERROR] Gagal membuat virtual environment di %VENV_DIR%!
        pause
        exit /b 1
    )
    echo [*] Menginstal dependensi backend dari requirements.txt...
    "%PYTHON_EXE%" -m pip install --upgrade pip
    "%PYTHON_EXE%" -m pip install -r "%~dp0backend\requirements.txt"
)

:: 4. Setup node_modules frontend jika belum ada
if not exist "%~dp0frontend\node_modules\" (
    echo [*] node_modules frontend belum ditemukan. Menjalankan npm install...
    cd /d "%~dp0frontend"
    call npm install
    cd /d "%~dp0"
)

echo.
echo [*] Menyalakan Backend Service (FastAPI + Scope Guard)...
start "AllTools-CyberSec Backend (Port 8000)" "%~dp0scripts\run-backend.bat"

echo [*] Menyalakan Frontend Service (React + Vite)...
start "AllTools-CyberSec Frontend (Port 5173)" "%~dp0scripts\run-frontend.bat"

echo.
echo [*] Menunggu inisialisasi server (3 detik)...
timeout /t 3 /nobreak >nul

echo [*] Membuka AllTools-CyberSec di browser default...
start http://localhost:5173

echo.
echo =====================================================================
echo               ALLTOOLS-CYBERSEC WORKBENCH AKTIF!
echo =====================================================================
echo  - Frontend Web UI : http://localhost:5173
echo  - Backend REST API: http://localhost:8000
echo  - Swagger API Docs: http://localhost:8000/docs
echo  - Scope Guard     : ACTIVE (Default-Deny Enforced)
echo =====================================================================
echo.
echo Server berjalan di latar belakang (jendela Backend & Frontend).
echo Untuk menghentikan semua server, jalankan stop.bat atau tutup jendela terkait.
echo.
echo Tekan tombol apa saja untuk menutup jendela peluncur ini...
pause >nul
