import pytest
from datetime import datetime, timezone
from fastapi.testclient import TestClient

from app.main import app
from app.repositories.scope_repository import scope_repository
from app.schemas.assessment import AssessmentCreate, AssessmentStatus, AssessmentType
from app.schemas.engagement import EngagementCreate, EngagementStatus
from app.schemas.scope import ScopeItemCreate, ScopeType


@pytest.fixture
def client():
    return TestClient(app)


@pytest.fixture
def test_setup():
    """Setup dedicated engagement and assessments in different states."""
    now = datetime.now(timezone.utc)
    # Active engagement
    eng_active = scope_repository.create_engagement(
        EngagementCreate(
            id="ENG-TEST-ACTIVE",
            workspaceId="WKS-TEST",
            name="Active Test Engagement",
            status=EngagementStatus.ACTIVE,
        )
    )
    # Inactive/completed engagement
    eng_archived = scope_repository.create_engagement(
        EngagementCreate(
            id="ENG-TEST-ARCHIVED",
            workspaceId="WKS-TEST",
            name="Archived Test Engagement",
            status=EngagementStatus.ARCHIVED,
        )
    )

    # Assessment in RUNNING state under ACTIVE engagement
    asm_running = scope_repository.create_assessment(
        AssessmentCreate(
            id="ASM-TEST-RUNNING",
            engagementId="ENG-TEST-ACTIVE",
            name="Running Assessment",
            type=AssessmentType.GENERAL,
            status=AssessmentStatus.RUNNING,
        )
    )
    # Assessment in DRAFT state under ACTIVE engagement
    asm_draft = scope_repository.create_assessment(
        AssessmentCreate(
            id="ASM-TEST-DRAFT",
            engagementId="ENG-TEST-ACTIVE",
            name="Draft Assessment",
            type=AssessmentType.GENERAL,
            status=AssessmentStatus.DRAFT,
        )
    )
    # Assessment in COMPLETED state under ACTIVE engagement
    asm_completed = scope_repository.create_assessment(
        AssessmentCreate(
            id="ASM-TEST-COMPLETED",
            engagementId="ENG-TEST-ACTIVE",
            name="Completed Assessment",
            type=AssessmentType.GENERAL,
            status=AssessmentStatus.COMPLETED,
        )
    )
    # Assessment in RUNNING state under ARCHIVED engagement
    asm_under_archived = scope_repository.create_assessment(
        AssessmentCreate(
            id="ASM-UNDER-ARCHIVED",
            engagementId="ENG-TEST-ARCHIVED",
            name="Running under Archived Engagement",
            type=AssessmentType.GENERAL,
            status=AssessmentStatus.RUNNING,
        )
    )

    # Scope rule for active engagement
    scope_repository.create_scope_item(
        ScopeItemCreate(
            id="SCP-TEST-1",
            engagementId="ENG-TEST-ACTIVE",
            type=ScopeType.DOMAIN,
            value="target.lab.local",
            inScope=True,
        )
    )

    return {
        "eng_active": eng_active,
        "eng_archived": eng_archived,
        "asm_running": asm_running,
        "asm_draft": asm_draft,
        "asm_completed": asm_completed,
        "asm_under_archived": asm_under_archived,
    }


def test_execution_on_running_assessment_succeeds(client, test_setup):
    """Running check on RUNNING assessment in ACTIVE engagement succeeds."""
    payload = {
        "assessmentId": "ASM-TEST-RUNNING",
        "ruleId": "SEC-WEB-001",
        "target": "target.lab.local",
    }
    res = client.post("/api/v1/executions/run", json=payload)
    assert res.status_code == 200
    data = res.json()
    assert data["allowed"] is True
    assert data["executionRecord"]["status"] == "FAIL"  # Mock check evaluated finding


def test_execution_on_nonexistent_assessment_returns_404(client):
    """Execution against non-existent assessment returns 404."""
    payload = {
        "assessmentId": "ASM-DOES-NOT-EXIST",
        "ruleId": "SEC-WEB-001",
        "target": "target.lab.local",
    }
    res = client.post("/api/v1/executions/run", json=payload)
    assert res.status_code == 404
    assert "not found" in res.json()["detail"].lower()


def test_execution_on_draft_assessment_returns_409(client, test_setup):
    """Execution against assessment in DRAFT state returns 409 conflict."""
    payload = {
        "assessmentId": "ASM-TEST-DRAFT",
        "ruleId": "SEC-WEB-001",
        "target": "target.lab.local",
    }
    res = client.post("/api/v1/executions/run", json=payload)
    assert res.status_code == 409
    assert "draft" in res.json()["detail"].lower()
    assert "running" in res.json()["detail"].lower()


def test_execution_on_completed_assessment_returns_409(client, test_setup):
    """Execution against assessment in COMPLETED state returns 409 conflict."""
    payload = {
        "assessmentId": "ASM-TEST-COMPLETED",
        "ruleId": "SEC-WEB-001",
        "target": "target.lab.local",
    }
    res = client.post("/api/v1/executions/run", json=payload)
    assert res.status_code == 409
    assert "completed" in res.json()["detail"].lower()


def test_execution_under_archived_engagement_returns_409(client, test_setup):
    """Execution against assessment where parent engagement is ARCHIVED returns 409 conflict."""
    payload = {
        "assessmentId": "ASM-UNDER-ARCHIVED",
        "ruleId": "SEC-WEB-001",
        "target": "target.lab.local",
    }
    res = client.post("/api/v1/executions/run", json=payload)
    assert res.status_code == 409
    assert "archived" in res.json()["detail"].lower()
    assert "active" in res.json()["detail"].lower()


def test_execution_engagement_mismatch_returns_409(client, test_setup):
    """Supplying an engagementId that does not match assessment returns 409 conflict."""
    payload = {
        "assessmentId": "ASM-TEST-RUNNING",
        "engagementId": "ENG-OTHER-MISMATCH",
        "ruleId": "SEC-WEB-001",
        "target": "target.lab.local",
    }
    res = client.post("/api/v1/executions/run", json=payload)
    assert res.status_code == 409
    assert "does not belong" in res.json()["detail"].lower()


def test_assessment_status_transition_workflow(client, test_setup):
    """Verify legitimate lifecycle state transition via PATCH endpoint."""
    # 1. Update DRAFT -> RUNNING
    patch_res = client.patch(
        "/api/v1/assessments/ASM-TEST-DRAFT/status",
        json={"status": "running"},
    )
    assert patch_res.status_code == 200
    assert patch_res.json()["status"] == "running"
    assert patch_res.json()["startedAt"] is not None

    # 2. Execution now succeeds
    run_res = client.post(
        "/api/v1/executions/run",
        json={"assessmentId": "ASM-TEST-DRAFT", "ruleId": "SEC-WEB-001", "target": "target.lab.local"},
    )
    assert run_res.status_code == 200
    assert run_res.json()["allowed"] is True

    # 3. Update RUNNING -> COMPLETED
    comp_res = client.patch(
        "/api/v1/assessments/ASM-TEST-DRAFT/status",
        json={"status": "completed"},
    )
    assert comp_res.status_code == 200
    assert comp_res.json()["status"] == "completed"

    # 4. Execution now blocked again with 409
    blocked_res = client.post(
        "/api/v1/executions/run",
        json={"assessmentId": "ASM-TEST-DRAFT", "ruleId": "SEC-WEB-001", "target": "target.lab.local"},
    )
    assert blocked_res.status_code == 409
