@echo off
setlocal
title AllTools-CyberSec Workbench
cd /d "%~dp0"

set PYTHONUNBUFFERED=1

echo =====================================================================
echo           ALLTOOLS-CYBERSEC DEFENSIVE SECURITY WORKBENCH
echo =====================================================================
echo.
echo [*] Memeriksa dependensi sistem...

:: 1. Cek Virtual Environment lokal
set "VENV_DIR=%~dp0backend\.venv"
set "PYTHON_EXE=%VENV_DIR%\Scripts\python.exe"

if exist "%PYTHON_EXE%" goto :check_frontend

:: 2. Cek Python global jika venv belum ada
where python >nul 2>nul
if errorlevel 1 goto :err_no_python

echo [*] Menyiapkan virtual environment backend...
python -m venv "%VENV_DIR%"
if errorlevel 1 goto :err_venv_failed

echo [*] Menginstal dependensi backend...
"%PYTHON_EXE%" -m pip install --upgrade pip
"%PYTHON_EXE%" -m pip install -r "%~dp0backend\requirements.txt"

:check_frontend
:: 3. Cek Node.js / NPM
where npm >nul 2>nul
if errorlevel 1 goto :err_no_npm

:: 4. Cek node_modules frontend
if not exist "%~dp0frontend\node_modules\" (
    echo [*] Menginstal dependensi frontend...
    cd /d "%~dp0frontend"
    call npm install
    cd /d "%~dp0"
)

:: 5. Jalankan Workbench Runner Supervisor
echo [*] Memulai server AllTools-CyberSec...
"%PYTHON_EXE%" "%~dp0scripts\runner.py"
goto :eof

:err_no_python
echo.
echo [ERROR] Python tidak ditemukan di PATH sistem maupun backend\.venv!
echo Silakan install Python 3.10+ dari https://www.python.org/
echo Pastikan opsi "Add python.exe to PATH" dicentang saat instalasi.
echo.
pause
exit /b 1

:err_venv_failed
echo.
echo [ERROR] Gagal membuat virtual environment di backend\.venv!
echo.
pause
exit /b 1

:err_no_npm
echo.
echo [ERROR] Node.js dan NPM tidak ditemukan di PATH sistem!
echo Silakan install Node.js v18+ dari https://nodejs.org/
echo.
pause
exit /b 1
