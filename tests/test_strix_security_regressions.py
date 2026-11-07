"""
Regression tests for security findings raised by the Strix review of PR #1.

Covers:
1. Production data-directory detection must honor ALLTOOLS_DATA_DIR and the
   POSIX XDG default, not only Windows LOCALAPPDATA.
2. The production migration authorization gate must fail closed when no pinned
   Ed25519 public key is configured.
"""

import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric import ed25519

from app.core.instance_lock import InstanceLock, MaintenanceSession
from app.core.storage_paths import get_default_data_dir, is_production_data_dir
from app.services.migration_authorization import (
    AuthorizationKeyError,
    AuthorizationLedger,
    ProductionMigrationAuthorization,
    ProductionMigrationAuthorizationGate,
)
from app.services.migration_engine import MigrationEngine
from app.services.migration_models import MigrationSafetyError


@pytest.fixture
def maintenance_session(tmp_path: Path):
    """Acquire an isolated maintenance lock before any os.name patching occurs."""
    lock = InstanceLock(tmp_path / "workbench.lock")
    lock.acquire()
    session = MaintenanceSession(lock)
    try:
        yield session
    finally:
        lock.release()


def _authorization_token(destination: Path, source: Path) -> ProductionMigrationAuthorization:
    now = datetime.now(timezone.utc)
    return ProductionMigrationAuthorization(
        approval_id="AUTH-STRIX-REGRESSION-001",
        approval_timestamp=now.isoformat(),
        expiration_timestamp=(now + timedelta(hours=1)).isoformat(),
        one_time_nonce=uuid.uuid4().hex,
        source_root=str(source),
        destination_root=str(destination),
        inventory_sha256="0" * 64,
        migration_plan_sha256="0" * 64,
        exact_artifact_count=173,
        excluded_active_candidate_path="ASM-001/EVD-3965036b.json",
        destination_volume_identity="VOL-TEST",
        verified_independent_backup_id="ABKP-TEST",
        operator_role="Lead Security Engineer",
        operator_name="Operator",
        operator_confirmation=True,
    )


def test_production_guard_honors_alltools_data_dir_override(
    tmp_path: Path, maintenance_session, monkeypatch: pytest.MonkeyPatch
):
    """ALLTOOLS_DATA_DIR is the real production resolver override and must be guarded."""
    production_dir = tmp_path / "relocated_production"
    production_dir.mkdir()
    monkeypatch.setenv("ALLTOOLS_DATA_DIR", str(production_dir))

    with pytest.raises(MigrationSafetyError, match="production data directory"):
        MigrationEngine(data_dir=production_dir, maintenance_session=maintenance_session)


def test_production_detection_honors_posix_xdg_default(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    """On POSIX the default production directory is under XDG_DATA_HOME, not LOCALAPPDATA."""
    xdg_data_home = tmp_path / "xdg_data_home"
    monkeypatch.delenv("ALLTOOLS_DATA_DIR", raising=False)
    monkeypatch.setenv("XDG_DATA_HOME", str(xdg_data_home))

    expected_production_dir = (xdg_data_home / "AllTools-CyberSec").resolve()

    assert get_default_data_dir(platform="posix") == expected_production_dir
    assert is_production_data_dir(expected_production_dir / "evidence", platform="posix") is True
    assert is_production_data_dir(tmp_path / "isolated_sandbox", platform="posix") is False


def test_authorization_gate_requires_pinned_public_key(tmp_path: Path):
    """A gate without an independently pinned key must fail closed at construction."""
    ledger = AuthorizationLedger(tmp_path / "authorization_ledger.jsonl")

    with pytest.raises(AuthorizationKeyError, match="pinned public key"):
        ProductionMigrationAuthorizationGate(ledger)


def test_migration_engine_fails_closed_without_pinned_public_key(
    tmp_path: Path, maintenance_session, monkeypatch: pytest.MonkeyPatch
):
    """An authorization token alone must not authorize migration without a pinned key."""
    destination = tmp_path / "production_runtime"
    destination.mkdir()
    source = tmp_path / "source_evidence"
    source.mkdir()
    monkeypatch.setenv("ALLTOOLS_DATA_DIR", str(destination))

    token = _authorization_token(destination=destination, source=source)

    with pytest.raises(MigrationSafetyError, match="pinned public key"):
        MigrationEngine(
            data_dir=destination,
            maintenance_session=maintenance_session,
            authorization=token,
        )


def test_migration_engine_accepts_pinned_public_key(
    tmp_path: Path, maintenance_session, monkeypatch: pytest.MonkeyPatch
):
    """The engine must be able to pass an explicitly pinned key to the gate."""
    destination = tmp_path / "production_runtime"
    destination.mkdir()
    source = tmp_path / "source_evidence"
    source.mkdir()
    monkeypatch.setenv("ALLTOOLS_DATA_DIR", str(destination))

    private_key = ed25519.Ed25519PrivateKey.generate()
    token = _authorization_token(destination=destination, source=source)

    with pytest.raises(MigrationSafetyError, match="[Ss]ignature"):
        MigrationEngine(
            data_dir=destination,
            maintenance_session=maintenance_session,
            authorization=token,
            authorization_public_key=private_key.public_key(),
        )
