import hashlib
import json
import pytest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from app.core.database_init import initialize_database
from app.core.storage_paths import StoragePaths
from app.repositories.sqlite_scope_repository import SqliteScopeRepository
from app.repositories.sqlite_evidence_repository import SqliteEvidenceRepository
from app.repositories.sqlite_quarantine_repository import SqliteQuarantineRepository
from app.schemas.assessment import AssessmentCreate
from app.schemas.engagement import EngagementCreate
from app.schemas.evidence import EvidenceCreate, EvidenceType
from app.schemas.quarantine import QuarantineReason
from app.services.durable_evidence_writer import DurableEvidenceWriter
from app.services.quarantine_service import QuarantineError, QuarantineService
from app.services.evidence_reconciliation import EvidenceIntegrityReconciler


@pytest.fixture
def recon_env(tmp_path: Path):
    data_dir = tmp_path / "recon_data"
    data_dir.mkdir(parents=True)
    paths = StoragePaths(
        data_dir=data_dir,
        database_file=data_dir / "workbench.db",
        evidence_dir=data_dir / "evidence",
        quarantine_dir=data_dir / "quarantine",
        backups_dir=data_dir / "backups",
    )
    paths.evidence_dir.mkdir(parents=True)
    paths.quarantine_dir.mkdir(parents=True)
    paths.backups_dir.mkdir(parents=True)

    initialize_database(db_path=paths.database_file)
    scope_repo = SqliteScopeRepository(db_path=paths.database_file)
    evidence_repo = SqliteEvidenceRepository(db_path=paths.database_file)
    quarantine_repo = SqliteQuarantineRepository(db_path=paths.database_file)
    quarantine_service = QuarantineService(paths=paths, quarantine_repo=quarantine_repo)
    writer = DurableEvidenceWriter(paths=paths, evidence_repo=evidence_repo, quarantine_repo=quarantine_repo)
    reconciler = EvidenceIntegrityReconciler(
        paths=paths, evidence_repo=evidence_repo, quarantine_service=quarantine_service
    )

    eng = scope_repo.create_engagement(
        EngagementCreate(
            name="Recon Test Engagement",
            client="Recon Corp",
            startDate=datetime.now(timezone.utc),
            endDate=datetime.now(timezone.utc) + timedelta(days=7),
            workspaceId="WKS-RECON-01",
        )
    )
    asm = scope_repo.create_assessment(
        AssessmentCreate(
            engagementId=eng.id,
            name="Recon Test Assessment",
            type="web",
        )
    )

    return {
        "paths": paths,
        "scope_repo": scope_repo,
        "evidence_repo": evidence_repo,
        "quarantine_repo": quarantine_repo,
        "quarantine_service": quarantine_service,
        "writer": writer,
        "reconciler": reconciler,
        "assessment": asm,
    }


def test_quarantine_cryptographic_hash_chain_and_manifest(recon_env):
    q_service: QuarantineService = recon_env["quarantine_service"]
    paths: StoragePaths = recon_env["paths"]

    # Create dummy artifacts to quarantine
    temp_dir = paths.data_dir / "temp_files"
    temp_dir.mkdir()

    items = []
    for i in range(3):
        f = temp_dir / f"bad_artifact_{i}.dat"
        f.write_bytes(f"corrupt_data_{i}".encode("utf-8"))
        item = q_service.quarantine_file(
            source_path=f,
            reason=QuarantineReason.HASH_MISMATCH,
            details=f"Test quarantine item {i}",
        )
        items.append(item)

    # 1. Check sequence and hash chaining
    assert items[0].seq == 1
    assert items[0].prevEntryHash == "0" * 64

    assert items[1].seq == 2
    assert items[1].prevEntryHash == items[0].entryHash

    assert items[2].seq == 3
    assert items[2].prevEntryHash == items[1].entryHash

    # 2. Check secondary JSONL manifest
    assert q_service.manifest_file.is_file()
    lines = q_service.manifest_file.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 3
    parsed_lines = [json.loads(l) for l in lines]
    assert parsed_lines[0]["seq"] == 1
    assert parsed_lines[1]["prevEntryHash"] == parsed_lines[0]["entryHash"]

    # 3. Comprehensive integrity audit passes
    is_valid, errors = q_service.verify_quarantine_integrity()
    assert is_valid is True
    assert len(errors) == 0


def test_quarantine_detects_manifest_tampering(recon_env):
    q_service: QuarantineService = recon_env["quarantine_service"]
    paths: StoragePaths = recon_env["paths"]

    temp_dir = paths.data_dir / "temp_files"
    temp_dir.mkdir()
    f = temp_dir / "suspect.json"
    f.write_text("{\"suspicious\": true}", encoding="utf-8")

    q_service.quarantine_file(
        source_path=f,
        reason=QuarantineReason.UNKNOWN_SCHEMA,
    )

    # Tamper with the manifest file by altering the entryHash
    lines = q_service.manifest_file.read_text(encoding="utf-8").strip().splitlines()
    tampered_entry = json.loads(lines[0])
    tampered_entry["entryHash"] = "f" * 64
    q_service.manifest_file.write_text(json.dumps(tampered_entry) + "\n", encoding="utf-8")

    # Integrity verification must catch the discrepancy
    is_valid, errors = q_service.verify_quarantine_integrity()
    assert is_valid is False
    assert any("entryHash mismatch" in err for err in errors)


def test_quarantine_item_recovery(recon_env):
    q_service: QuarantineService = recon_env["quarantine_service"]
    evidence_repo: SqliteEvidenceRepository = recon_env["evidence_repo"]
    asm = recon_env["assessment"]
    paths: StoragePaths = recon_env["paths"]

    temp_dir = paths.data_dir / "temp_files"
    temp_dir.mkdir()
    f = temp_dir / "recovering_item.json"
    valid_content = b'{"analysis": "valid_after_all"}'
    f.write_bytes(valid_content)

    q_item = q_service.quarantine_file(
        source_path=f,
        reason=QuarantineReason.MANUAL_QUARANTINE,
    )

    # Recover into assessment
    recovered_ev = q_service.recover_item(
        quarantine_id=q_item.quarantineId,
        target_assessment_id=asm.id,
        evidence_repo=evidence_repo,
    )

    assert recovered_ev.id.startswith("EVD-")
    assert recovered_ev.assessmentId == asm.id
    assert recovered_ev.syncStatus == "COMMITTED"
    assert recovered_ev.sha256 == hashlib.sha256(valid_content).hexdigest()

    # Quarantine ledger updated with recovery target
    updated_q = q_service.inspect_quarantine(q_item.quarantineId)
    assert updated_q.recoveredAt is not None
    assert updated_q.recoveryTargetId == asm.id


def test_quarantine_recovery_rejects_path_traversal_assessment_id(recon_env):
    """Recovery must not join an untrusted assessment ID into the evidence path."""
    q_service: QuarantineService = recon_env["quarantine_service"]
    paths: StoragePaths = recon_env["paths"]

    temp_dir = paths.data_dir / "temp_files"
    temp_dir.mkdir(exist_ok=True)
    source_file = temp_dir / "traversal_recovery.json"
    source_file.write_bytes(b'{"analysis": "must_stay_inside_evidence_root"}')

    q_item = q_service.quarantine_file(
        source_path=source_file,
        reason=QuarantineReason.MANUAL_QUARANTINE,
    )

    class _AcceptingEvidenceRepo:
        def create_evidence(self, data, sync_status="COMMITTED"):
            return data

    with pytest.raises(QuarantineError, match="assessment|invalid|path"):
        q_service.recover_item(
            quarantine_id=q_item.quarantineId,
            target_assessment_id="../temp_files",
            evidence_repo=_AcceptingEvidenceRepo(),
        )

    assert Path(q_item.quarantinePath).exists()
    assert not list(temp_dir.glob("EVD-*.json"))


def test_integrity_reconciler_comprehensive(recon_env):
    reconciler: EvidenceIntegrityReconciler = recon_env["reconciler"]
    writer: DurableEvidenceWriter = recon_env["writer"]
    evidence_repo: SqliteEvidenceRepository = recon_env["evidence_repo"]
    asm = recon_env["assessment"]
    paths: StoragePaths = recon_env["paths"]

    # 1. Create a healthy artifact
    healthy_ev = writer.write_evidence(
        assessment_id=asm.id,
        evidence_type=EvidenceType.JSON_RESULT,
        source="healthy_check",
        raw_content={"status": "healthy"},
    )

    # 2. Create an artifact and then delete the physical file (Missing file scenario)
    missing_ev = writer.write_evidence(
        assessment_id=asm.id,
        evidence_type=EvidenceType.JSON_RESULT,
        source="missing_check",
        raw_content={"status": "will_be_deleted"},
    )
    missing_file = paths.evidence_dir / asm.id / f"{missing_ev.id}.json"
    missing_file.unlink()

    # 3. Create an artifact and corrupt its contents (Hash mismatch scenario)
    corrupted_ev = writer.write_evidence(
        assessment_id=asm.id,
        evidence_type=EvidenceType.JSON_RESULT,
        source="corrupted_check",
        raw_content={"status": "original_good_data"},
    )
    corrupted_file = paths.evidence_dir / asm.id / f"{corrupted_ev.id}.json"
    corrupted_file.write_bytes(b'{"status": "tampered_data_on_disk"}')

    # 4. Create an orphan file on disk with NO database record
    orphan_file = paths.evidence_dir / asm.id / "EVD-ORPHAN-999.json"
    orphan_file.write_text("{\"orphan\": \"rogue_file\"}", encoding="utf-8")

    # Run reconciliation
    summary = reconciler.reconcile()

    # Verify counts
    assert summary.matched_count == 1
    assert summary.missing_count == 1
    assert summary.corrupted_count == 1
    assert summary.orphaned_count == 1
    assert summary.quarantined_count == 2  # 1 corrupted + 1 orphan
    assert summary.is_healthy is False

    # Check database status updates
    h_rec = evidence_repo.get_evidence(healthy_ev.id)
    assert h_rec.syncStatus == "COMMITTED"

    m_rec = evidence_repo.get_evidence(missing_ev.id)
    assert m_rec.syncStatus == "MISSING_FILE"

    c_rec = evidence_repo.get_evidence(corrupted_ev.id)
    assert c_rec.syncStatus == "CORRUPTED"

    # Corrupted file moved to quarantine
    assert not corrupted_file.exists()

    # Orphan file moved to quarantine (never automatically adopted!)
    assert not orphan_file.exists()
