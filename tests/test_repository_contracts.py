import pytest
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Tuple

from app.core.database_init import initialize_database
from app.repositories.interfaces import IFindingsRepository, IScopeRepository
from app.repositories.findings_repository import InMemoryFindingsRepository
from app.repositories.scope_repository import InMemoryScopeRepository
from app.repositories.sqlite_findings_repository import SqliteFindingsRepository
from app.repositories.sqlite_scope_repository import SqliteScopeRepository

from app.schemas.assessment import AssessmentCreate, AssessmentStatus, AssessmentType
from app.schemas.engagement import EngagementCreate, EngagementStatus
from app.schemas.finding import FindingCreate
from app.schemas.scope import ScopeItemCreate, ScopeType
from app.schemas.common import FindingStatus


# ============================================================================
# Scope Repository Contract Tests
# ============================================================================

@pytest.fixture(params=["in_memory", "sqlite"])
def scope_repo(request, tmp_path: Path) -> IScopeRepository:
    if request.param == "in_memory":
        repo = InMemoryScopeRepository()
        # Clear default seed to test pure repository behavior
        repo._engagements.clear()
        repo._assessments.clear()
        repo._scope_items.clear()
        return repo
    else:
        db_file = tmp_path / f"scope_{request.node.name}.db"
        initialize_database(db_path=db_file)
        return SqliteScopeRepository(db_path=db_file)


def test_scope_repo_engagement_lifecycle(scope_repo: IScopeRepository):
    # 1. Create
    eng = scope_repo.create_engagement(
        EngagementCreate(
            workspaceId="WS-DEFAULT",
            name="Contract Engagement",
            description="Testing contract",
            assessor="Auditor",
            status=EngagementStatus.ACTIVE,
        )
    )
    assert eng.id.startswith("ENG-")
    assert eng.name == "Contract Engagement"
    assert eng.status == EngagementStatus.ACTIVE

    # 2. Get
    retrieved = scope_repo.get_engagement(eng.id)
    assert retrieved is not None
    assert retrieved.id == eng.id
    assert retrieved.name == eng.name

    # 3. Missing Lookup
    assert scope_repo.get_engagement("ENG-NONEXISTENT") is None

    # 4. Update Status
    updated = scope_repo.update_engagement_status(eng.id, EngagementStatus.COMPLETED)
    assert updated.status == EngagementStatus.COMPLETED
    assert scope_repo.get_engagement(eng.id).status == EngagementStatus.COMPLETED

    # 5. Missing Update raises KeyError
    with pytest.raises(KeyError):
        scope_repo.update_engagement_status("ENG-NONEXISTENT", EngagementStatus.ARCHIVED)

    # 6. List
    engs = scope_repo.list_engagements()
    assert len(engs) == 1
    assert engs[0].id == eng.id

    # 7. Soft Delete
    deleted = scope_repo.soft_delete_engagement(eng.id)
    assert deleted is True
    assert scope_repo.get_engagement(eng.id) is None
    assert len(scope_repo.list_engagements()) == 0


def test_scope_repo_assessment_and_scope_cascade(scope_repo: IScopeRepository):
    # Create parent engagement
    eng = scope_repo.create_engagement(
        EngagementCreate(
            workspaceId="WS-DEFAULT",
            name="Parent Engagement",
            assessor="Auditor",
            status=EngagementStatus.ACTIVE,
        )
    )

    # Create assessment
    asm = scope_repo.create_assessment(
        AssessmentCreate(
            engagementId=eng.id,
            name="Child Assessment",
            type=AssessmentType.WEB,
            status=AssessmentStatus.DRAFT,
        )
    )
    assert asm.id.startswith("ASM-")
    assert asm.engagementId == eng.id
    assert asm.status == AssessmentStatus.DRAFT

    # Create scope items
    s1 = scope_repo.create_scope_item(
        ScopeItemCreate(
            engagementId=eng.id,
            type=ScopeType.DOMAIN,
            value="target.local",
            inScope=True,
        )
    )
    s2 = scope_repo.create_scope_item(
        ScopeItemCreate(
            engagementId=eng.id,
            type=ScopeType.IP,
            value="10.0.0.1",
            inScope=False,
        )
    )

    # Scope for assessment
    scope_list = scope_repo.get_scope_for_assessment(asm.id)
    assert len(scope_list) == 2
    assert {s.id for s in scope_list} == {s1.id, s2.id}

    # Assessment status transition: DRAFT -> RUNNING auto sets startedAt
    running_asm = scope_repo.update_assessment_status(asm.id, AssessmentStatus.RUNNING)
    assert running_asm.status == AssessmentStatus.RUNNING
    assert running_asm.startedAt is not None

    # Soft delete engagement cascades to assessment and scope items
    scope_repo.soft_delete_engagement(eng.id)
    assert scope_repo.get_engagement(eng.id) is None
    assert scope_repo.get_assessment(asm.id) is None
    assert len(scope_repo.list_assessments(eng.id)) == 0
    assert scope_repo.get_scope_item(s1.id) is None
    assert len(scope_repo.list_scope_items(eng.id)) == 0
    assert len(scope_repo.get_scope_for_assessment(asm.id)) == 0


# ============================================================================
# Findings Repository Contract Tests
# ============================================================================

@pytest.fixture(params=["in_memory", "sqlite"])
def findings_repo_and_asm(request, tmp_path: Path) -> Tuple[IFindingsRepository, str]:
    if request.param == "in_memory":
        repo = InMemoryFindingsRepository()
        return repo, "ASM-CONTRACT-1"
    else:
        db_file = tmp_path / f"findings_{request.node.name}.db"
        initialize_database(db_path=db_file)
        # Create an engagement and assessment so foreign keys succeed in SQLite
        scope = SqliteScopeRepository(db_path=db_file)
        eng = scope.create_engagement(
            EngagementCreate(workspaceId="WS-DEFAULT", name="E", assessor="A", status=EngagementStatus.ACTIVE)
        )
        asm = scope.create_assessment(
            AssessmentCreate(engagementId=eng.id, name="A", type=AssessmentType.GENERAL, status=AssessmentStatus.RUNNING)
        )
        return SqliteFindingsRepository(db_path=db_file), asm.id


def test_findings_repo_lifecycle_and_filtering(findings_repo_and_asm):
    repo, asm_id = findings_repo_and_asm

    f_high = repo.create_finding(
        FindingCreate(
            assessmentId=asm_id,
            assetId="AST-1",
            ruleId="SEC-WEB-001",
            title="High Severity Finding",
            status=FindingStatus.CONFIRMED,
            severity="high",
            confidence="high",
            createdAt=datetime(2026, 1, 1, 10, 0, tzinfo=timezone.utc),
        )
    )

    f_low = repo.create_finding(
        FindingCreate(
            assessmentId=asm_id,
            assetId="AST-2",
            ruleId="SEC-WEB-002",
            title="Low Severity Finding",
            status=FindingStatus.CONFIRMED,
            severity="low",
            confidence="medium",
            createdAt=datetime(2026, 1, 1, 11, 0, tzinfo=timezone.utc),
        )
    )

    # 1. Get by ID
    assert repo.get_finding(f_high.id).title == "High Severity Finding"
    assert repo.get_finding("FND-NONEXISTENT") is None

    # 2. List all
    all_findings = repo.list_findings(assessment_id=asm_id)
    assert len(all_findings) == 2
    # Deterministic order: newest created first (f_low created at 11:00, f_high at 10:00)
    assert all_findings[0].id == f_low.id
    assert all_findings[1].id == f_high.id

    # 3. Severity Filtering
    high_findings = repo.list_findings(assessment_id=asm_id, severity="high")
    assert len(high_findings) == 1
    assert high_findings[0].id == f_high.id

    low_findings = repo.list_findings(assessment_id=asm_id, severity="low")
    assert len(low_findings) == 1
    assert low_findings[0].id == f_low.id

    # 4. Soft Delete
    deleted = repo.soft_delete_finding(f_high.id)
    assert deleted is True
    assert repo.get_finding(f_high.id) is None
    assert len(repo.list_findings(assessment_id=asm_id)) == 1
    assert repo.list_findings(assessment_id=asm_id)[0].id == f_low.id
