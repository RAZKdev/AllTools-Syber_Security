import os
import sys
import subprocess
import time
from pathlib import Path
import pytest

from app.core.instance_lock import InstanceLock, ProcessLockError


def test_first_instance_acquires_lock(tmp_path: Path):
    """1. First instance acquires lock successfully."""
    lock_file = tmp_path / "workbench.lock"
    lock = InstanceLock(lock_file)
    lock.acquire()
    try:
        assert lock._acquired is True
        assert lock.pid == os.getpid()
        assert lock_file.exists()
    finally:
        lock.release()
    assert lock._acquired is False
    content = lock_file.read_text(encoding="utf-8")
    assert f"pid={os.getpid()}" in content


def test_second_instance_is_rejected(tmp_path: Path):
    """2. Second instance attempting to access the same lock file is rejected."""
    lock_file = tmp_path / "workbench.lock"
    lock1 = InstanceLock(lock_file)
    lock1.acquire()

    lock2 = InstanceLock(lock_file)
    with pytest.raises(ProcessLockError) as exc_info:
        lock2.acquire()

    assert "holds the exclusive lock" in str(exc_info.value)
    assert str(lock_file) in str(exc_info.value)

    lock1.release()


def test_lock_is_released_after_graceful_shutdown(tmp_path: Path):
    """3. Lock is released after graceful shutdown, allowing another instance to acquire it."""
    lock_file = tmp_path / "workbench.lock"

    with InstanceLock(lock_file) as lock1:
        assert lock1._acquired is True

    # After exit of with block, lock1 has released the lock
    lock2 = InstanceLock(lock_file)
    lock2.acquire()
    assert lock2._acquired is True
    lock2.release()


def test_lock_is_released_after_process_termination(tmp_path: Path):
    """4. Lock is released automatically by the OS following abnormal process termination."""
    lock_file = tmp_path / "workbench.lock"

    # Launch a separate child process that acquires the lock and waits
    code = f"""
import sys, time
from pathlib import Path
from app.core.instance_lock import InstanceLock
lock = InstanceLock(Path(r'{lock_file}'))
lock.acquire()
sys.stdout.write('ACQUIRED\\n')
sys.stdout.flush()
time.sleep(10)
"""
    env = os.environ.copy()
    env["PYTHONPATH"] = "backend"
    proc = subprocess.Popen(
        [sys.executable, "-c", code],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env=env,
    )

    try:
        # Wait for child process to acquire lock
        line = proc.stdout.readline()
        assert "ACQUIRED" in line

        # Verify parent cannot acquire lock while child is running
        parent_lock = InstanceLock(lock_file)
        with pytest.raises(ProcessLockError):
            parent_lock.acquire()

        # Kill child process abruptly (simulating crash / termination)
        proc.kill()
        proc.wait(timeout=5)
        proc.stdout.close()
        time.sleep(0.2)

        # OS kernel must have released the file lock automatically
        fresh_lock = InstanceLock(lock_file)
        fresh_lock.acquire()
        assert fresh_lock._acquired is True
        fresh_lock.release()
    finally:
        if proc.poll() is None:
            proc.kill()


def test_separate_data_directories_operate_independently(tmp_path: Path):
    """5. Separate data directories can acquire locks independently without collision."""
    dir1 = tmp_path / "data1"
    dir2 = tmp_path / "data2"
    dir1.mkdir()
    dir2.mkdir()

    lock1 = InstanceLock(dir1 / "workbench.lock")
    lock2 = InstanceLock(dir2 / "workbench.lock")

    lock1.acquire()
    lock2.acquire()

    assert lock1._acquired is True
    assert lock2._acquired is True

    lock1.release()
    lock2.release()


def test_multi_worker_configuration_is_rejected(tmp_path: Path, monkeypatch):
    """6. Multi-worker Uvicorn configuration (WEB_CONCURRENCY > 1) is rejected immediately."""
    lock_file = tmp_path / "workbench.lock"
    lock = InstanceLock(lock_file)

    monkeypatch.setenv("WEB_CONCURRENCY", "4")
    with pytest.raises(ProcessLockError) as exc_info:
        lock.acquire()

    assert "Uvicorn multi-worker operation is strictly prohibited" in str(exc_info.value)
    assert "WEB_CONCURRENCY=4" in str(exc_info.value)
