import os
import sys
import time
import threading
from datetime import datetime, timezone
from typing import Optional
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api import api_router

app = FastAPI(
    title="AllTools-CyberSec Workbench API",
    description="Practical Defensive Security Workbench API with Scope Guard enforcement.",
    version="0.1.0",
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
    """System health check endpoint."""
    return {
        "status": "healthy",
        "service": "alltools-cybersec-backend",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "version": "0.1.0",
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
