import logging
import threading
import time
from contextlib import contextmanager
from typing import Generator, Optional, Set

logger = logging.getLogger(__name__)


class WriteFenceTimeoutError(Exception):
    """Raised when in-flight writes fail to drain within the designated write-fence timeout."""
    pass


class WriteFence:
    """
    Coordinated write-fence barrier (ADR-06).
    Coordinates in-flight evidence writes, quarantine mutations, and purge operations
    with SQLite Online Backup snapshot generation.
    Target coordination window: < 500 ms.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._write_cond = threading.Condition(self._lock)
        self._active_writers = 0
        self._fence_active = False
        self._thread_writers: dict = {}

    @property
    def is_fenced(self) -> bool:
        with self._lock:
            return self._fence_active

    @contextmanager
    def acquire_write(self, timeout_seconds: float = 5.0) -> Generator[None, None, None]:
        """
        Acquired by normal mutating operations (evidence writes, quarantine operations).
        Waits if a backup snapshot write-fence is currently active.
        Thread-reentrant: if the current thread already holds a write lease, it proceeds without blocking.
        """
        tid = threading.get_ident()
        start = time.time()
        with self._write_cond:
            if tid in self._thread_writers:
                self._thread_writers[tid] += 1
                reentered = True
            else:
                while self._fence_active:
                    remaining = timeout_seconds - (time.time() - start)
                    if remaining <= 0:
                        raise TimeoutError("Timed out waiting for backup write-fence to release.")
                    self._write_cond.wait(timeout=remaining)
                self._active_writers += 1
                self._thread_writers[tid] = 1
                reentered = False

        try:
            yield
        finally:
            with self._write_cond:
                if reentered:
                    self._thread_writers[tid] -= 1
                    if self._thread_writers[tid] == 0:
                        del self._thread_writers[tid]
                else:
                    if tid in self._thread_writers:
                        self._thread_writers[tid] -= 1
                        if self._thread_writers[tid] == 0:
                            del self._thread_writers[tid]
                    self._active_writers -= 1
                    if self._active_writers == 0:
                        self._write_cond.notify_all()

    @contextmanager
    def fence_writes(
        self, timeout_ms: int = 500
    ) -> Generator[dict, None, None]:
        """
        Exclusive snapshot coordination barrier.
        Blocks new writers and waits for active in-flight writers to drain.
        Measures total coordination duration and reports whether the 500 ms target was met.
        """
        fence_start = time.time()
        fence_info = {
            "drained_writers": 0,
            "coordination_duration_ms": 0,
            "target_exceeded": False,
        }

        timeout_sec = timeout_ms / 1000.0

        with self._write_cond:
            # Block new writers immediately
            self._fence_active = True
            drain_start = time.time()

            # Wait for existing in-flight writers to drain
            while self._active_writers > 0:
                elapsed = time.time() - drain_start
                if elapsed > timeout_sec:
                    self._fence_active = False
                    self._write_cond.notify_all()
                    raise WriteFenceTimeoutError(
                        f"In-flight writes failed to drain within {timeout_ms} ms target (active: {self._active_writers})."
                    )
                self._write_cond.wait(timeout=timeout_sec - elapsed)

        drain_duration_ms = int((time.time() - fence_start) * 1000)
        fence_info["coordination_duration_ms"] = drain_duration_ms

        try:
            yield fence_info
        finally:
            duration_ms = int((time.time() - fence_start) * 1000)
            fence_info["coordination_duration_ms"] = duration_ms
            if duration_ms > timeout_ms:
                fence_info["target_exceeded"] = True
                logger.warning(
                    "Backup snapshot write-fence coordination duration (%d ms) exceeded target (%d ms).",
                    duration_ms, timeout_ms
                )
            else:
                logger.info("Backup snapshot write-fence successfully established in %d ms.", duration_ms)

            # Re-open barrier for normal writers
            with self._write_cond:
                self._fence_active = False
                self._write_cond.notify_all()


class BackupHoldManager:
    """
    Thread-safe tracker for evidence artifacts actively protected from physical
    deletion during background backup copying (ADR-05, ADR-06).
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._held_paths: Set[str] = set()

    def hold_paths(self, paths: Set[str]) -> None:
        with self._lock:
            self._held_paths.update(paths)

    def release_paths(self, paths: Set[str]) -> None:
        with self._lock:
            self._held_paths.difference_update(paths)

    def clear(self) -> None:
        with self._lock:
            self._held_paths.clear()

    def is_held(self, artifact_path: str) -> bool:
        with self._lock:
            return artifact_path in self._held_paths


# Global singletons for runtime coordination
global_write_fence = WriteFence()
global_backup_hold = BackupHoldManager()
