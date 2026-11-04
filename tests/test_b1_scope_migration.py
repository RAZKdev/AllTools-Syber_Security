import os
import pytest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from fastapi.testclient import TestClient

from app.main import app
from app.core import (
    ConfigurationError,
    get_storage_paths,
    initialize_database,
    resolve_data_dir,
)
from app.dependencies import get_scope_repository, set_db_path
from app.repositories.interfaces import IScopeRepository
from app.repositories.sqlite_scope_repository import SqliteScopeRepository
from app.schemas.assessment import AssessmentCreate, AssessmentStatus, AssessmentType
from app.schemas.common import ScopeDecision
from app.schemas.engagement import EngagementCreate, EngagementStatus
from app.schemas.scope import ScopeItemCreate, ScopeType
from app.services.scope_guard import ScopeGuard


@pytest.fixture
def fresh_db_env(tmp_path: Path):
    """Provide a dedicated, isolated fresh database file for each B1 test."""
    db_file = tmp_path / "b1_test.db"
    initialize_database(db_path=db_file)
    set_db_path(db_file)
    client = TestClient(app)
    yield db_file, client
    set_db_path(None)


def test_b1_fresh_database_has_empty_lists(fresh_db_env):
    """
    Requirement: Fresh database startup must have empty engagement and assessment lists,
    and zero authorized scope rules by default.
    """
    db_file, client = fresh_db_env

    # 1. Engagements list is empty
    res_eng = client.get("/api/v1/engagements")
    assert res_eng.status_code == 200
    assert res_eng.json() == []

    # 2. Assessments list is empty
    res_asm = client.get("/api/v1/assessments")
    assert res_asm.status_code == 200
    assert res_asm.json() == []

    # 3. Scope items list is empty
    res_scp = client.get("/api/v1/scope/items")
    assert res_scp.status_code == 200
    assert res_scp.json() == []


def test_b1_strict_default_deny_on_fresh_database(fresh_db_env):
    """
    Requirement: Zero authorized scope rules by default; Default-Deny evaluation must hold.
    Any scope evaluation request on an unknown assessment must 404,
    and ScopeGuard evaluation against empty scope must return BLOCK.
    """
    db_file, client = fresh_db_env

    # API evaluation with non-existent assessment fails closed (404)
    res_eval = client.post(
        "/api/v1/scope/evaluate",
        json={"assessmentId": "ASM-UNKNOWN", "target": "example.com"},
    )
    assert res_eval.status_code == 404

    # Domain ScopeGuard evaluation against empty scope items must strictly BLOCK
    guard = ScopeGuard()
    result = guard.evaluate_target("ASM-EMPTY", "192.168.1.1", scope_items=[])
    assert result.decision == ScopeDecision.BLOCK
    assert not result.is_allowed
    assert "Target does not match any active authorized scope rule" in result.reason


def test_b1_engagement_creation_and_persistence(fresh_db_env):
    """
    Requirement: Engagement creation persists deterministically to SQLite.
    """
    db_file, client = fresh_db_env

    payload = {
        "workspaceId": "WKS-PROD-01",
        "name": "Production Red Team Assessment",
        "description": "Authorized defensive assessment for production environment.",
        "assessor": "Senior Security Analyst",
        "status": "active",
    }
    res = client.post("/api/v1/engagements", json=payload)
    assert res.status_code == 201
    created = res.json()
    assert created["id"].startswith("ENG-")
    assert created["name"] == payload["name"]
    assert created["status"] == "active"

    # Verify retrieval by ID
    res_get = client.get(f"/api/v1/engagements/{created['id']}")
    assert res_get.status_code == 200
    assert res_get.json()["id"] == created["id"]

    # Verify presence in list
    res_list = client.get("/api/v1/engagements")
    assert len(res_list.json()) == 1
    assert res_list.json()[0]["id"] == created["id"]


def test_b1_assessment_creation_and_status_transitions(fresh_db_env):
    """
    Requirement: Assessment creation under active engagement, and status transition validation.
    """
    db_file, client = fresh_db_env

    # 1. Create active engagement
    eng_res = client.post(
        "/api/v1/engagements",
        json={"workspaceId": "WKS-1", "name": "Active Eng", "status": "active"},
    )
    eng_id = eng_res.json()["id"]

    # 2. Create assessment in DRAFT
    asm_res = client.post(
        "/api/v1/assessments",
        json={
            "engagementId": eng_id,
            "name": "Web Infrastructure Scan",
            "type": "web",
            "status": "draft",
        },
    )
    assert asm_res.status_code == 201
    asm = asm_res.json()
    assert asm["status"] == "draft"
    assert asm["startedAt"] is None

    # 3. Transition DRAFT -> RUNNING
    patch_run = client.patch(
        f"/api/v1/assessments/{asm['id']}/status",
        json={"status": "running"},
    )
    assert patch_run.status_code == 200
    asm_running = patch_run.json()
    assert asm_running["status"] == "running"
    assert asm_running["startedAt"] is not None

    # 4. Transition RUNNING -> COMPLETED
    patch_done = client.patch(
        f"/api/v1/assessments/{asm['id']}/status",
        json={"status": "completed"},
    )
    assert patch_done.status_code == 200
    asm_completed = patch_done.json()
    assert asm_completed["status"] == "completed"
    assert asm_completed["completedAt"] is not None


def test_b1_assessment_cannot_start_under_inactive_engagement(fresh_db_env):
    """
    Requirement: Preserves status-transition validation: cannot start assessment under draft or archived engagement.
    """
    db_file, client = fresh_db_env

    # Create draft engagement
    eng_res = client.post(
        "/api/v1/engagements",
        json={"workspaceId": "WKS-1", "name": "Draft Eng", "status": "draft"},
    )
    eng_id = eng_res.json()["id"]

    # Create draft assessment
    asm_res = client.post(
        "/api/v1/assessments",
        json={"engagementId": eng_id, "name": "Scan", "status": "draft"},
    )
    asm_id = asm_res.json()["id"]

    # Attempt to transition to RUNNING while engagement is DRAFT must fail with 409
    patch_res = client.patch(
        f"/api/v1/assessments/{asm_id}/status",
        json={"status": "running"},
    )
    assert patch_res.status_code == 409
    assert "must be ACTIVE" in patch_res.json()["detail"]


def test_b1_scope_rules_lifecycle_and_evaluation(fresh_db_env):
    """
    Requirement: Scope rule creation, listing, explicit exclusion priority, and expiration.
    """
    db_file, client = fresh_db_env

    # 1. Create active engagement and running assessment
    eng_res = client.post(
        "/api/v1/engagements",
        json={"workspaceId": "WKS-1", "name": "Eng", "status": "active"},
    )
    eng_id = eng_res.json()["id"]
    asm_res = client.post(
        "/api/v1/assessments",
        json={"engagementId": eng_id, "name": "Asm", "status": "running"},
    )
    asm_id = asm_res.json()["id"]

    # 2. Add in-scope rule for target.local
    res_s1 = client.post(
        "/api/v1/scope/items",
        json={"engagementId": eng_id, "type": "domain", "value": "target.local", "inScope": True},
    )
    assert res_s1.status_code == 201

    # 3. Add explicit exclusion rule for secret.target.local
    res_s2 = client.post(
        "/api/v1/scope/items",
        json={"engagementId": eng_id, "type": "domain", "value": "secret.target.local", "inScope": False},
    )
    assert res_s2.status_code == 201

    # 4. Add expired in-scope rule
    expired_time = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()
    res_s3 = client.post(
        "/api/v1/scope/items",
        json={
            "engagementId": eng_id,
            "type": "domain",
            "value": "expired.target.local",
            "inScope": True,
            "expiresAt": expired_time,
        },
    )
    assert res_s3.status_code == 201

    # 5. Evaluate: target.local -> ALLOW
    ev1 = client.post("/api/v1/scope/evaluate", json={"assessmentId": asm_id, "target": "target.local"})
    assert ev1.status_code == 200
    assert ev1.json()["decision"] == "ALLOW"

    # 6. Evaluate: secret.target.local -> BLOCK (explicit exclusion takes absolute precedence)
    ev2 = client.post("/api/v1/scope/evaluate", json={"assessmentId": asm_id, "target": "secret.target.local"})
    assert ev2.status_code == 200
    assert ev2.json()["decision"] == "BLOCK"
    assert "explicitly excluded" in ev2.json()["reason"]

    # 7. Evaluate: expired.target.local -> BLOCK (expired rule cannot authorize)
    ev3 = client.post("/api/v1/scope/evaluate", json={"assessmentId": asm_id, "target": "expired.target.local"})
    assert ev3.status_code == 200
    assert ev3.json()["decision"] == "BLOCK"

    # 8. Evaluate: out-of-scope target -> BLOCK (Default-Deny)
    ev4 = client.post("/api/v1/scope/evaluate", json={"assessmentId": asm_id, "target": "google.com"})
    assert ev4.status_code == 200
    assert ev4.json()["decision"] == "BLOCK"


def test_b1_restart_persistence(tmp_path: Path):
    """
    Requirement: Restart persistence — verify data written to SQLite persists
    after closing and re-opening connections.
    """
    db_file = tmp_path / "restart_persist.db"
    initialize_database(db_path=db_file)

    # Operator session 1: Create engagement and assessment
    repo1 = SqliteScopeRepository(db_path=db_file)
    eng = repo1.create_engagement(
        EngagementCreate(workspaceId="WKS-P", name="Persistent Eng", status=EngagementStatus.ACTIVE)
    )
    asm = repo1.create_assessment(
        AssessmentCreate(engagementId=eng.id, name="Persistent Asm", status=AssessmentStatus.RUNNING)
    )
    repo1.create_scope_item(
        ScopeItemCreate(engagementId=eng.id, type=ScopeType.DOMAIN, value="persist.local", inScope=True)
    )
    del repo1

    # Operator session 2: Restart backend, initialize new repository instance on exact same db_file
    repo2 = SqliteScopeRepository(db_path=db_file)
    restored_eng = repo2.get_engagement(eng.id)
    assert restored_eng is not None
    assert restored_eng.name == "Persistent Eng"

    restored_asm = repo2.get_assessment(asm.id)
    assert restored_asm is not None
    assert restored_asm.name == "Persistent Asm"

    scope_items = repo2.get_scope_for_assessment(asm.id)
    assert len(scope_items) == 1
    assert scope_items[0].value == "persist.local"


def test_b1_foreign_key_integrity(fresh_db_env):
    """
    Requirement: Foreign-key integrity — creating an assessment or scope item
    referencing a non-existent engagement must fail closed.
    """
    db_file, client = fresh_db_env

    # 1. Assessment referencing non-existent engagement
    res_asm = client.post(
        "/api/v1/assessments",
        json={"engagementId": "ENG-NONEXISTENT", "name": "Orphan Asm"},
    )
    assert res_asm.status_code == 404

    # 2. Scope item referencing non-existent engagement
    res_scp = client.post(
        "/api/v1/scope/items",
        json={"engagementId": "ENG-NONEXISTENT", "type": "domain", "value": "test.com", "inScope": True},
    )
    assert res_scp.status_code == 404


def test_b1_soft_delete_cascade_behavior(fresh_db_env):
    """
    Requirement: Soft-delete behavior — deleting an engagement cascades soft-delete
    to associated assessments and scope items, removing them from active listings.
    """
    db_file, client = fresh_db_env

    # 1. Create hierarchy
    eng_res = client.post(
        "/api/v1/engagements",
        json={"workspaceId": "WKS-1", "name": "To Delete", "status": "active"},
    )
    eng_id = eng_res.json()["id"]

    asm_res = client.post(
        "/api/v1/assessments",
        json={"engagementId": eng_id, "name": "Child Asm", "status": "draft"},
    )
    asm_id = asm_res.json()["id"]

    scp_res = client.post(
        "/api/v1/scope/items",
        json={"engagementId": eng_id, "type": "domain", "value": "child.local", "inScope": True},
    )
    scp_id = scp_res.json()["id"]

    # 2. Soft-delete engagement via DELETE endpoint
    del_res = client.delete(f"/api/v1/engagements/{eng_id}")
    assert del_res.status_code == 204

    # 3. Engagement is gone from active lookups and listings
    assert client.get(f"/api/v1/engagements/{eng_id}").status_code == 404
    assert len(client.get("/api/v1/engagements").json()) == 0

    # 4. Child assessment is cascaded and removed from lookups and listings
    assert client.get(f"/api/v1/assessments/{asm_id}").status_code == 404
    assert len(client.get(f"/api/v1/assessments?engagementId={eng_id}").json()) == 0

    # 5. Child scope item is cascaded and removed from listings
    assert len(client.get(f"/api/v1/scope/items?engagementId={eng_id}").json()) == 0


def test_b1_storage_configuration_error_fails_closed():
    """
    Requirement: Invalid storage path or initialization failure must fail closed (ConfigurationError),
    never silently falling back to in-memory storage.
    """
    invalid_path = "Z:\\nonexistent_unwritable_volume_path_alltools\\cybersec"
    with pytest.raises(ConfigurationError):
        resolve_data_dir(env_override=invalid_path)
