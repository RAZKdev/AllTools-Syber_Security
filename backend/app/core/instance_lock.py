import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional


class ProcessLockError(RuntimeError):
    """Raised when an exclusive process lock cannot be acquired or multi-worker operation is attempted."""
    pass


class InstanceLock:
    """
    OS-level exclusive process lock for an AllTools-CyberSec storage directory.
    Enforces that exactly one backend process accesses a given storage directory.
    Uses msvcrt.locking on Windows and fcntl.flock on POSIX platforms.
    The operating system kernel automatically releases file locks on process termination or crash.
    """

    def __init__(self, lock_path: Path) -> None:
        self.lock_path = Path(lock_path)
        self.fd: Optional[int] = None
        self._acquired = False
        self.pid: Optional[int] = None

    @property
    def is_acquired(self) -> bool:
        """Returns True if the exclusive OS lock is actively held by this instance."""
        return self._acquired and self.fd is not None

    def acquire(self) -> None:
        """
        Acquire an exclusive OS-level process lock on the lock file.
        Rejects multi-worker Uvicorn configurations.
        Raises ProcessLockError if another process holds the lock.
        """
        if self._acquired:
            return

        # 1. Reject multi-worker Uvicorn environment configuration upfront
        web_concurrency = os.environ.get("WEB_CONCURRENCY")
        if web_concurrency and web_concurrency.strip().isdigit() and int(web_concurrency.strip()) > 1:
            raise ProcessLockError(
                f"Uvicorn multi-worker operation is strictly prohibited (WEB_CONCURRENCY={web_concurrency}). "
                "AllTools-CyberSec requires single-worker execution to preserve deterministic SQLite persistence and Scope Guard validation."
            )

        uvicorn_workers = os.environ.get("UVICORN_WORKERS")
        if uvicorn_workers and uvicorn_workers.strip().isdigit() and int(uvicorn_workers.strip()) > 1:
            raise ProcessLockError(
                f"Uvicorn multi-worker operation is strictly prohibited (UVICORN_WORKERS={uvicorn_workers}). "
                "AllTools-CyberSec requires single-worker execution to preserve deterministic SQLite persistence and Scope Guard validation."
            )

        self.lock_path.parent.mkdir(parents=True, exist_ok=True)
        try:
            self.fd = os.open(str(self.lock_path), os.O_RDWR | os.O_CREAT)
        except Exception as e:
            raise ProcessLockError(f"Failed to open process lock file at '{self.lock_path}': {e}") from e

        locked = False
        if os.name == "nt":
            import msvcrt
            try:
                os.lseek(self.fd, 0, os.SEEK_SET)
                msvcrt.locking(self.fd, msvcrt.LK_NBLCK, 1)
                locked = True
            except (OSError, PermissionError):
                locked = False
        else:
            import fcntl
            try:
                fcntl.flock(self.fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                locked = True
            except (OSError, BlockingIOError):
                locked = False

        if not locked:
            if self.fd is not None:
                try:
                    os.close(self.fd)
                except Exception:
                    pass
                self.fd = None

            raise ProcessLockError(
                f"Lock acquisition failed: Another AllTools-CyberSec process is already running and holds the exclusive lock on '{self.lock_path}'. "
                "Only one backend process per data directory is permitted."
            )

        # Write process diagnostic metadata into the lock file using the current file descriptor
        self.pid = os.getpid()
        try:
            os.ftruncate(self.fd, 0)
            os.lseek(self.fd, 0, os.SEEK_SET)
            meta = (
                f"pid={self.pid}\n"
                f"started_at={datetime.now(timezone.utc).isoformat()}\n"
                f"data_dir={self.lock_path.parent}\n"
            )
            os.write(self.fd, meta.encode("utf-8"))
            os.lseek(self.fd, 0, os.SEEK_SET)
        except Exception:
            pass

        self._acquired = True

    def release(self) -> None:
        """Release the OS-level lock and close the file descriptor."""
        if not self._acquired or self.fd is None:
            return

        try:
            if os.name == "nt":
                import msvcrt
                try:
                    os.lseek(self.fd, 0, os.SEEK_SET)
                    msvcrt.locking(self.fd, msvcrt.LK_UNLCK, 1)
                except Exception:
                    pass
            else:
                import fcntl
                try:
                    fcntl.flock(self.fd, fcntl.LOCK_UN)
                except Exception:
                    pass
        finally:
            try:
                os.close(self.fd)
            except Exception:
                pass
            self.fd = None
            self._acquired = False

    def __enter__(self) -> "InstanceLock":
        self.acquire()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.release()


class MaintenanceSession:
    """
    Enforceable maintenance session proving exclusive ownership of a storage directory.
    Guarantees OS-level InstanceLock is actively held before any filesystem or database mutation.
    """

    def __init__(self, lock: InstanceLock) -> None:
        if not lock.is_acquired:
            raise ProcessLockError(
                f"Cannot establish MaintenanceSession: InstanceLock on '{lock.lock_path}' is not actively acquired."
            )
        self.lock = lock

    @property
    def lock_path(self) -> Path:
        return self.lock.lock_path

    @property
    def is_active(self) -> bool:
        """Returns True if the underlying lock remains acquired."""
        return self.lock.is_acquired

    def assert_active(self) -> None:
        """Asserts that maintenance lock ownership is active and held; fails closed if released or lost."""
        if not self.lock.is_acquired:
            raise ProcessLockError(
                f"Maintenance session invalid: lock on '{self.lock.lock_path}' is not actively held."
            )


class MaintenanceContext:
    """
    Context manager that acquires an exclusive InstanceLock, establishes a MaintenanceSession,
    and automatically releases the lock upon context exit.
    """

    def __init__(self, lock_or_path: Path | InstanceLock) -> None:
        if isinstance(lock_or_path, InstanceLock):
            self.lock = lock_or_path
        else:
            self.lock = InstanceLock(lock_or_path)
        self.session: Optional[MaintenanceSession] = None

    def __enter__(self) -> MaintenanceSession:
        self.lock.acquire()
        self.session = MaintenanceSession(self.lock)
        return self.session

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.lock.release()
        self.session = None
