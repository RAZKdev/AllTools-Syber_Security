import os
import sys
import time
import socket
import subprocess
import urllib.request
import webbrowser

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
BACKEND_DIR = os.path.join(ROOT_DIR, "backend")
FRONTEND_DIR = os.path.join(ROOT_DIR, "frontend")

VENV_PYTHON = os.path.join(BACKEND_DIR, ".venv", "Scripts", "python.exe")
PYTHON_EXE = VENV_PYTHON if os.path.isfile(VENV_PYTHON) else sys.executable
NPM_CMD = "npm.cmd" if os.name == "nt" else "npm"


def is_port_open(port: int, host: str = "127.0.0.1") -> bool:
    """Check if a TCP port is open."""
    try:
        with socket.create_connection((host, port), timeout=0.8):
            return True
    except OSError:
        return False


def wait_for_url(url: str, timeout: int = 30) -> bool:
    """Poll a URL until it returns 200/OK."""
    start = time.time()
    while time.time() - start < timeout:
        try:
            with urllib.request.urlopen(url, timeout=1.0) as resp:
                if resp.status in (200, 304):
                    return True
        except Exception:
            pass
        time.sleep(0.5)
    return False


def kill_port(port: int):
    """Forcefully kill any process occupying the given port on Windows."""
    if os.name == "nt":
        cmd = f'for /f "tokens=5" %a in (\'netstat -ano 2^>nul ^| findstr :{port} ^| findstr LISTENING\') do taskkill /F /PID %a >nul 2>nul'
        subprocess.run(cmd, shell=True, capture_output=True)


def main():
    print("=====================================================================")
    print("      ALLTOOLS-CYBERSEC DEFENSIVE SECURITY WORKBENCH LAUNCHER")
    print("=====================================================================")
    print()

    # Pre-clean ports if occupied
    kill_port(8000)
    kill_port(5173)

    # Configure environment
    env = os.environ.copy()
    env["ALLTOOLS_AUTO_SHUTDOWN"] = "1"
    existing_pythonpath = env.get("PYTHONPATH", "")
    env["PYTHONPATH"] = f"{ROOT_DIR};{BACKEND_DIR}" + (f";{existing_pythonpath}" if existing_pythonpath else "")

    print("[*] Menyalakan Backend Service (FastAPI + Scope Guard)...")
    backend_proc = subprocess.Popen(
        [
            PYTHON_EXE,
            "-m",
            "uvicorn",
            "app.main:app",
            "--app-dir",
            "backend",
            "--host",
            "127.0.0.1",
            "--port",
            "8000",
        ],
        cwd=ROOT_DIR,
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    print("[*] Menyalakan Frontend Service (React + Vite)...")
    frontend_proc = subprocess.Popen(
        [NPM_CMD, "run", "dev"],
        cwd=FRONTEND_DIR,
        env=env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )

    print("[*] Menunggu server Backend siap...")
    if not wait_for_url("http://127.0.0.1:8000/health", timeout=25):
        print("[ERROR] Backend tidak merespons dalam waktu 25 detik.")
        backend_proc.kill()
        frontend_proc.kill()
        kill_port(8000)
        kill_port(5173)
        sys.exit(1)

    print("[*] Menunggu server Frontend siap...")
    frontend_ready = False
    for _ in range(40):
        if is_port_open(5173):
            frontend_ready = True
            break
        time.sleep(0.5)

    if not frontend_ready:
        print("[ERROR] Frontend tidak merespons pada port 5173 dalam waktu 20 detik.")
        backend_proc.kill()
        frontend_proc.kill()
        kill_port(8000)
        kill_port(5173)
        sys.exit(1)

    print()
    print("=====================================================================")
    print("  STATUS: APLIKASI AKTIF & TERHUBUNG KE BROWSER")
    print("  - Frontend UI    : http://localhost:5173")
    print("  - Backend API    : http://localhost:8000")
    print("  - Scope Guard    : ACTIVE (Default-Deny)")
    print("=====================================================================")
    print()
    print("[*] Membuka AllTools-CyberSec di browser default...")
    webbrowser.open("http://localhost:5173")

    print()
    print("---------------------------------------------------------------------")
    print(" [PETUNJUK PENGGUNAAN]")
    print(" >> CUKUP TUTUP TAB / JENDELA WEB BROWSER UNTUK MEMATIKAN APLIKASI <<")
    print(" Seluruh server dan jendela ini akan otomatis berhenti sendiri.")
    print("---------------------------------------------------------------------")
    print()

    try:
        # Wait for the backend process to terminate (triggered when web is closed)
        backend_proc.wait()
    except KeyboardInterrupt:
        print("\n[*] Menerima sinyal keyboard (Ctrl+C)...")
    finally:
        print("[*] Web ditutup. Menghentikan seluruh proses server...")
        try:
            frontend_proc.terminate()
            frontend_proc.kill()
        except Exception:
            pass
        kill_port(8000)
        kill_port(5173)
        print("[OK] Seluruh server telah dimatikan secara bersih. Selesai.")
        time.sleep(1.2)


if __name__ == "__main__":
    main()
