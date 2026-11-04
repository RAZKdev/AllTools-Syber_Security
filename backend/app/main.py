import os
import sys
import time
import threading
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Optional
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api import api_router
from app.core import (
    check_database_health,
    ensure_storage_directories,
    get_storage_paths,
)
from app.dependencies import ensure_database_initialized, get_db_path


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    FastAPI lifespan manager.
    Enforces ADR-01, ADR-04, and P0 Process Ownership:
    - Validates storage directory and fails closed if invalid.
    - Acquires OS-level exclusive process lock for the configured data directory.
    - Rejects multi-worker or concurrent backend processes.
    - Applies SQLite schema migrations to the target database file.
    - Reconciles any orphaned in-flight executions left over from previous process termination.
    - Releases process lock cleanly on graceful shutdown.
    - Never silently falls back to in-memory repositories.
    """
    paths = get_storage_paths()
    ensure_storage_directories(paths)

    from app.core.instance_lock import InstanceLock, ProcessLockError
    lock = InstanceLock(paths.lock_file)
    try:
        lock.acquire()
    except ProcessLockError as e:
        print(f"[FATAL] Process lock failure: {e}", file=sys.stderr)
        raise RuntimeError(f"AllTools-CyberSec process lock failure: {e}") from e

    try:
        ensure_database_initialized(paths.database_file)

        # P0 Lifecycle: Reconcile any in-flight stale records left over from previous process termination
        from app.repositories.sqlite_execution_repository import SqliteExecutionRepository
        reconciled = SqliteExecutionRepository(db_path=paths.database_file).reconcile_stale_executions()
        if reconciled > 0:
            print(f"[RECONCILE] Reconciled {reconciled} stale in-flight execution(s) to INTERRUPTED state.", file=sys.stderr)

        # F-03 Lifecycle: Reconcile any abandoned backup staging folders and stranded IN_PROGRESS records
        from app.services.backup_engine import BackupEngine
        reconciled_backups = BackupEngine(paths=paths).cleanup_stale_staging(max_age_seconds=0)
        if reconciled_backups > 0:
            print(f"[RECONCILE] Reconciled {reconciled_backups} stale backup staging folder(s).", file=sys.stderr)
    except Exception as e:
        lock.release()
        print(f"[FATAL] Storage or SQLite initialization failed: {e}", file=sys.stderr)
        raise RuntimeError(f"Storage or SQLite initialization failed: {e}") from e

    try:
        yield
    finally:
        lock.release()


app = FastAPI(
    title="AllTools-CyberSec Workbench API",
    description="Practical Defensive Security Workbench API with Scope Guard enforcement.",
    version="0.1.0",
    lifespan=lifespan,
)

# Configure CORS for local development and frontend access
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(api_router)

# Auto-shutdown & Heartbeat mechanism for seamless desktop-like web experience
_last_heartbeat: float = time.time()
_has_connected: bool = False
_shutdown_timer: Optional[threading.Timer] = None
_auto_shutdown_enabled: bool = os.environ.get("ALLTOOLS_AUTO_SHUTDOWN") == "1"


def _do_exit():
    """Terminate the process when the browser is closed."""
    print("[Workbench] Browser closed. Shutting down backend...")
    time.sleep(0.5)
    os._exit(0)


def _watchdog_loop():
    """Watchdog thread that checks if browser was disconnected or never opened."""
    global _last_heartbeat, _has_connected
    start_time = time.time()

    # Grace period before enforcing watchdog (allows Vite & browser to launch)
    time.sleep(15.0)

    while True:
        time.sleep(2.0)
        now = time.time()
        if _has_connected:
            # If no heartbeat for > 8s after connection was established, browser was closed
            if now - _last_heartbeat > 8.0:
                print("[Workbench Watchdog] Heartbeat lost for > 8s. Closing server.")
                _do_exit()
        else:
            # If never connected within 120s, terminate idle server
            if now - start_time > 120.0:
                print("[Workbench Watchdog] Initial connection timeout. Closing server.")
                _do_exit()


if _auto_shutdown_enabled:
    watchdog_thread = threading.Thread(target=_watchdog_loop, daemon=True)
    watchdog_thread.start()


@app.api_route("/api/heartbeat", methods=["GET", "POST"], tags=["System"])
def heartbeat():
    """Heartbeat endpoint pinged by UI every 2.5s. Cancels pending shutdown on reload."""
    global _last_heartbeat, _has_connected, _shutdown_timer
    _last_heartbeat = time.time()
    _has_connected = True

    if _shutdown_timer is not None and _shutdown_timer.is_alive():
        _shutdown_timer.cancel()
        _shutdown_timer = None

    return {"status": "alive", "timestamp": _last_heartbeat}


@app.api_route("/api/shutdown", methods=["GET", "POST"], tags=["System"])
def schedule_shutdown():
    """Triggered on browser beforeunload. Schedules shutdown with 3s grace window for F5 reload."""
    global _shutdown_timer
    if not _auto_shutdown_enabled:
        return {"status": "ignored", "reason": "auto_shutdown_disabled"}

    if _shutdown_timer is not None and _shutdown_timer.is_alive():
        _shutdown_timer.cancel()

    _shutdown_timer = threading.Timer(3.0, _do_exit)
    _shutdown_timer.daemon = True
    _shutdown_timer.start()

    return {"status": "shutdown_scheduled", "delay": 3.0}


@app.get("/health", tags=["System"])
def health_check():
    """System health check endpoint with database status verification."""
    db_file = get_db_path()
    db_health = check_database_health(db_file)
    is_healthy = db_health.get("healthy", False)
    return {
        "status": "healthy" if is_healthy else "degraded",
        "service": "alltools-cybersec-backend",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "version": "0.1.0",
        "database": db_health,
    }


@app.get("/", tags=["System"])
def root():
    """Root info endpoint."""
    return {
        "name": "AllTools-CyberSec",
        "role": "Practical Defensive Security Workbench",
        "scopeGuard": "Active (Default-Deny)",
        "docsUrl": "/docs",
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app.main:app", host="0.0.0.0", port=8000, reload=True)
