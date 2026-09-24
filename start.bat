@echo off
setlocal enabledelayedexpansion
title AllTools-CyberSec Workbench
cd /d "%~dp0"

:: Prevent stdout buffering in Python
set PYTHONUNBUFFERED=1

echo =====================================================================
echo           ALLTOOLS-CYBERSEC DEFENSIVE SECURITY WORKBENCH
echo =====================================================================
echo.
echo [*] Memeriksa dependensi sistem...

:: 1. Verifikasi Virtual Environment atau Python sistem
set "VENV_DIR=%~dp0backend\.venv"
set "PYTHON_EXE=%VENV_DIR%\Scripts\python.exe"

if exist "%PYTHON_EXE%" (
    goto :check_frontend
)

where python >nul 2>nul
if %errorlevel% neq 0 (
    echo.
    echo =====================================================================
    echo  [ERROR] Python tidak ditemukan di PATH sistem maupun backend\.venv!
    echo  Silakan install Python 3.10+ dari https://www.python.org/
    echo  Pastikan centang opsi "Add python.exe to PATH" saat instalasi.
    echo =====================================================================
    echo.
    pause
    exit /b 1
)

echo [*] backend\.venv belum ditemukan. Menyiapkan virtual environment...
python -m venv "%VENV_DIR%"
if %errorlevel% neq 0 (
    echo [ERROR] Gagal membuat virtual environment di %VENV_DIR%!
    pause
    exit /b 1
)
echo [*] Menginstal dependensi backend...
"%PYTHON_EXE%" -m pip install --upgrade pip
"%PYTHON_EXE%" -m pip install -r "%~dp0backend\requirements.txt"

:check_frontend
:: 2. Verifikasi Node.js / NPM
where npm >nul 2>nul
if %errorlevel% neq 0 (
    echo.
    echo =====================================================================
    echo  [ERROR] Node.js / NPM tidak ditemukan di PATH sistem!
    echo  Silakan install Node.js (v18+) dari https://nodejs.org/
    echo =====================================================================
    echo.
    pause
    exit /b 1
)

:: 3. Setup node_modules frontend jika belum ada
if not exist "%~dp0frontend\node_modules\" (
    echo [*] node_modules frontend belum terpasang. Menjalankan npm install...
    cd /d "%~dp0frontend"
    call npm install
    cd /d "%~dp0"
)

:: 4. Jalankan Workbench Launcher Supervisor
"%PYTHON_EXE%" "%~dp0scripts\launcher.py"
set LAUNCHER_EXIT=%errorlevel%

if %LAUNCHER_EXIT% neq 0 (
    echo.
    echo =====================================================================
    echo  [ERROR] Terjadi kendala saat menjalankan AllTools-CyberSec (Exit Code: %LAUNCHER_EXIT%).
    echo  Jendela ini tidak langsung tertutup agar Anda dapat membaca pesan di atas.
    echo =====================================================================
    echo.
    pause
)

exit /b %LAUNCHER_EXIT%
