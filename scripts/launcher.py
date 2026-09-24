import os
import sys
import time
import socket
import subprocess
import urllib.request

# Ensure real-time unbuffered output in terminal
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(line_buffering=True)

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
BACKEND_DIR = os.path.join(ROOT_DIR, "backend")
FRONTEND_DIR = os.path.join(ROOT_DIR, "frontend")

VENV_PYTHON = os.path.join(BACKEND_DIR, ".venv", "Scripts", "python.exe")
PYTHON_EXE = VENV_PYTHON if os.path.isfile(VENV_PYTHON) else sys.executable
NPM_CMD = "npm.cmd" if os.name == "nt" else "npm"


def kill_port(port: int):
    """Forcefully kill any process occupying the given port on Windows."""
    if os.name != "nt":
        return
    try:
        flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
        res = subprocess.run(["netstat", "-ano"], capture_output=True, text=True, creationflags=flags)
        pids = set()
        for line in res.stdout.splitlines():
            if f":{port}" in line and "LISTENING" in line:
                parts = line.strip().split()
                if len(parts) >= 5:
                    pid = parts[-1]
                    if pid.isdigit() and int(pid) != os.getpid():
                        pids.add(pid)
        for pid in pids:
            subprocess.run(["taskkill", "/F", "/PID", pid], capture_output=True, creationflags=flags)
    except Exception:
        pass


def is_port_open(port: int, host: str = "127.0.0.1") -> bool:
    """Check if a TCP port is open."""
    for h in (host, "localhost"):
        try:
            with socket.create_connection((h, port), timeout=0.6):
                return True
        except OSError:
            pass
    return False


def wait_for_service(url: str, timeout: float = 25.0) -> bool:
    """Poll an HTTP URL until it returns 200."""
    start = time.time()
    while time.time() - start < timeout:
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "Workbench-Supervisor"})
            with urllib.request.urlopen(req, timeout=1.0) as resp:
                if resp.status in (200, 304):
                    return True
        except Exception:
            pass
        time.sleep(0.4)
    return False


def print_log_tail(file_path: str, lines: int = 15):
    """Print the last few lines of a log file if an error occurred."""
    if os.path.isfile(file_path):
        try:
            with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                content = f.readlines()
                print("".join(content[-lines:]))
        except Exception:
            pass


def main():
    print("=====================================================================")
    print("      ALLTOOLS-CYBERSEC DEFENSIVE SECURITY WORKBENCH")
    print("=====================================================================")
    print()

    # Pre-clean stale ports if occupied
    kill_port(8000)
    kill_port(5173)

    # Configure environment
    env = os.environ.copy()
    env["ALLTOOLS_AUTO_SHUTDOWN"] = "1"
    existing_pythonpath = env.get("PYTHONPATH", "")
    env["PYTHONPATH"] = f"{ROOT_DIR};{BACKEND_DIR}" + (f";{existing_pythonpath}" if existing_pythonpath else "")

    backend_log_path = os.path.join(ROOT_DIR, "backend.log")
    frontend_log_path = os.path.join(ROOT_DIR, "frontend.log")

    backend_log = open(backend_log_path, "w", encoding="utf-8", errors="replace")
    frontend_log = open(frontend_log_path, "w", encoding="utf-8", errors="replace")

    print("[*] Menyalakan Backend (FastAPI + Scope Guard Engine)...")
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
        stdout=backend_log,
        stderr=backend_log,
    )

    print("[*] Menyalakan Frontend (React + Vite)...")
    frontend_proc = subprocess.Popen(
        [NPM_CMD, "run", "dev"],
        cwd=FRONTEND_DIR,
        env=env,
        stdout=frontend_log,
        stderr=frontend_log,
    )

    print("[*] Menunggu layanan Backend siap...")
    if not wait_for_service("http://127.0.0.1:8000/health", timeout=20.0):
        print("\n[ERROR] Server Backend gagal dimulai dalam batas waktu!")
        print("Log Backend terakhir:")
        backend_log.flush()
        print_log_tail(backend_log_path)
        backend_proc.kill()
        frontend_proc.kill()
        kill_port(8000)
        kill_port(5173)
        sys.exit(1)

    print("[*] Menunggu layanan Frontend siap...")
    frontend_ready = False
    start_t = time.time()
    while time.time() - start_t < 25.0:
        if is_port_open(5173):
            frontend_ready = True
            break
        time.sleep(0.4)

    if not frontend_ready:
        print("\n[ERROR] Server Frontend gagal dimulai dalam batas waktu!")
        print("Log Frontend terakhir:")
        frontend_log.flush()
        print_log_tail(frontend_log_path)
        backend_proc.kill()
        frontend_proc.kill()
        kill_port(8000)
        kill_port(5173)
        sys.exit(1)

    print()
    print("=====================================================================")
    print("  STATUS: APLIKASI AKTIF & TERHUBUNG KE BROWSER")
    print("  - Web UI        : http://127.0.0.1:5173")
    print("  - Backend API   : http://127.0.0.1:8000")
    print("  - Scope Guard   : ACTIVE (Default-Deny Enforced)")
    print("=====================================================================")
    print()
    print("[*] Membuka web aplikasi di browser default...")
    if os.name == "nt":
        os.system("start http://127.0.0.1:5173")
    else:
        import webbrowser
        webbrowser.open("http://127.0.0.1:5173")

    print()
    print("---------------------------------------------------------------------")
    print(" [PETUNJUK PENGGUNAAN]")
    print(" >> CUKUP TUTUP TAB / JENDELA WEB BROWSER UNTUK KELUAR <<")
    print(" Aplikasi dan jendela terminal ini akan otomatis berhenti sendiri.")
    print("---------------------------------------------------------------------")
    print()

    try:
        # Blocks until backend exits (which happens when the browser is closed)
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
        backend_log.close()
        frontend_log.close()
        print("[OK] Seluruh server telah dimatikan secara bersih. Selesai.")
        time.sleep(1.0)


if __name__ == "__main__":
    main()
