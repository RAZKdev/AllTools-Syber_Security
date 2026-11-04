import pytest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from app.core.database_init import initialize_database
from app.core.storage_paths import StoragePaths
from app.repositories.sqlite_scope_repository import SqliteScopeRepository
from app.repositories.sqlite_findings_repository import SqliteFindingsRepository
from app.repositories.sqlite_evidence_repository import SqliteEvidenceRepository
from app.schemas.assessment import AssessmentCreate
from app.schemas.engagement import EngagementCreate
from app.schemas.evidence import EvidenceCreate, EvidenceType
from app.schemas.finding import FindingCreate
from app.schemas.common import Severity, Confidence


@pytest.fixture
def repo_env(tmp_path: Path):
    db_file = tmp_path / "test_evidence.db"
    initialize_database(db_path=db_file)
    scope_repo = SqliteScopeRepository(db_path=db_file)
    findings_repo = SqliteFindingsRepository(db_path=db_file)
    evidence_repo = SqliteEvidenceRepository(db_path=db_file)

    # Seed parent engagement and assessment
    eng = scope_repo.create_engagement(
        EngagementCreate(
            name="Evidence Test Engagement",
            client="Test Corp",
            startDate=datetime.now(timezone.utc),
            endDate=datetime.now(timezone.utc) + timedelta(days=7),
            workspaceId="WKS-EVD-01",
        )
    )
    asm = scope_repo.create_assessment(
        AssessmentCreate(
            engagementId=eng.id,
            name="Evidence Test Assessment",
            type="web",
        )
    )
    fnd = findings_repo.create_finding(
        FindingCreate(
            assessmentId=asm.id,
            ruleId="SEC-WEB-001",
            title="Missing Security Headers",
            severity=Severity.MEDIUM,
            confidence=Confidence.HIGH,
            description="Missing headers on target",
            assetId="AST-EVD-01",
        )
    )

    return {
        "db_file": db_file,
        "scope_repo": scope_repo,
        "findings_repo": findings_repo,
        "evidence_repo": evidence_repo,
        "engagement": eng,
        "assessment": asm,
        "finding": fnd,
    }


def test_create_and_retrieve_evidence(repo_env):
    repo: SqliteEvidenceRepository = repo_env["evidence_repo"]
    asm = repo_env["assessment"]
    fnd = repo_env["finding"]

    sha_dummy = "a" * 64
    ev_create = EvidenceCreate(
        assessmentId=asm.id,
        findingId=fnd.id,
        type=EvidenceType.JSON_RESULT,
        source="https://target.local",
        artifactPath=f"evidence/{asm.id}/test_artifact.json",
        sha256=sha_dummy,
        notes="Automated test evidence",
    )

    created = repo.create_evidence(ev_create, sync_status="COMMITTED")
    assert created.id.startswith("EVD-")
    assert created.assessmentId == asm.id
    assert created.findingId == fnd.id
    assert created.sha256 == sha_dummy
    assert created.syncStatus == "COMMITTED"
    assert created.legalHold is False
    assert created.isDeleted is False

    # Retrieve by ID
    retrieved = repo.get_evidence(created.id)
    assert retrieved is not None
    assert retrieved.id == created.id
    assert retrieved.sha256 == sha_dummy

    # Retrieve by sha256
    by_sha = repo.get_by_sha256(sha_dummy)
    assert by_sha is not None
    assert by_sha.id == created.id

    # Retrieve by artifact path
    by_path = repo.get_by_artifact_path(created.artifactPath)
    assert by_path is not None
    assert by_path.id == created.id


def test_list_and_filter_evidence(repo_env):
    repo: SqliteEvidenceRepository = repo_env["evidence_repo"]
    asm = repo_env["assessment"]
    fnd = repo_env["finding"]

    # Create 3 records
    for i in range(3):
        repo.create_evidence(
            EvidenceCreate(
                assessmentId=asm.id,
                findingId=fnd.id if i == 0 else None,
                type=EvidenceType.JSON_RESULT,
                source=f"https://target.local/{i}",
                artifactPath=f"evidence/{asm.id}/item_{i}.json",
                sha256=f"{i}" * 64,
            )
        )

    all_ev = repo.list_evidence(assessment_id=asm.id)
    assert len(all_ev) == 3

    finding_ev = repo.list_evidence(finding_id=fnd.id)
    assert len(finding_ev) == 1
    assert finding_ev[0].findingId == fnd.id


def test_soft_delete_and_retention_period(repo_env):
    repo: SqliteEvidenceRepository = repo_env["evidence_repo"]
    asm = repo_env["assessment"]

    ev = repo.create_evidence(
        EvidenceCreate(
            assessmentId=asm.id,
            type=EvidenceType.LOG_EXCERPT,
            source="server.log",
            artifactPath=f"evidence/{asm.id}/server.log.json",
            sha256="b" * 64,
        )
    )

    # Soft delete
    deleted = repo.soft_delete_evidence(ev.id)
    assert deleted is True

    # Active lookup excludes soft-deleted
    assert repo.get_evidence(ev.id) is None
    assert repo.get_by_sha256("b" * 64) is None

    # Include deleted returns record with 90-day retention eligibility
    soft_record = repo.get_evidence(ev.id, include_deleted=True)
    assert soft_record is not None
    assert soft_record.isDeleted is True
    assert soft_record.deletedAt is not None
    assert soft_record.purgeEligibleAt is not None

    # Check 90 days interval
    delta = soft_record.purgeEligibleAt - soft_record.deletedAt
    assert 89 <= delta.days <= 91


def test_legal_hold_protects_against_hard_delete(repo_env):
    repo: SqliteEvidenceRepository = repo_env["evidence_repo"]
    asm = repo_env["assessment"]

    ev = repo.create_evidence(
        EvidenceCreate(
            assessmentId=asm.id,
            type=EvidenceType.HTTP_RESPONSE,
            source="api",
            artifactPath=f"evidence/{asm.id}/api.json",
            sha256="c" * 64,
        )
    )

    # Attempt hard delete without soft-delete fails
    with pytest.raises(ValueError, match="must be soft-deleted before purge"):
        repo.hard_delete_evidence(ev.id)

    # Soft delete first
    repo.soft_delete_evidence(ev.id)

    # Set legal hold
    repo.set_legal_hold(ev.id, hold=True)
    held_record = repo.get_evidence(ev.id, include_deleted=True)
    assert held_record.legalHold is True

    # Hard delete fails closed while under legal hold
    with pytest.raises(PermissionError, match="protected by active Legal Hold"):
        repo.hard_delete_evidence(ev.id)

    # Release legal hold allows operator purge
    repo.set_legal_hold(ev.id, hold=False)
    purged = repo.hard_delete_evidence(ev.id)
    assert purged is True

    # Record completely unlinked from database
    assert repo.get_evidence(ev.id, include_deleted=True) is None
