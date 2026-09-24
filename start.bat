@echo off
setlocal enabledelayedexpansion
title AllTools-CyberSec Workbench
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
    echo [*] backend\.venv belum ditemukan. Membuat virtual environment baru...
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

:: 5. Jalankan Workbench Launcher Supervisor
"%PYTHON_EXE%" "%~dp0scripts\launcher.py"

exit /b 0
