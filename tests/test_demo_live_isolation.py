import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.repositories.scope_repository import scope_repository


@pytest.fixture
def client():
    return TestClient(app)


def test_demo_ids_isolated_from_live_backend_stores(client):
    """
    Mandate: Demo fixtures must NEVER enter live backend data stores.
    Requests specifying DEMO- prefix resources must fail with 404 on live endpoints.
    """
    # 1. Assessment check
    res_asm = client.get("/api/v1/assessments/DEMO-ASM-001")
    assert res_asm.status_code == 404

    # 2. Scope evaluation on demo assessment ID
    res_eval = client.post(
        "/api/v1/scope/evaluate",
        json={"assessmentId": "DEMO-ASM-001", "target": "lab.local"},
    )
    assert res_eval.status_code == 404

    # 3. Execution attempt on demo assessment ID
    res_exec = client.post(
        "/api/v1/executions/run",
        json={
            "assessmentId": "DEMO-ASM-001",
            "ruleId": "SEC-WEB-001",
            "target": "lab.local",
        },
    )
    assert res_exec.status_code == 404

    # 4. Live repository contains zero DEMO- prefixed records
    all_engagements = scope_repository.list_engagements()
    assert not any(e.id.startswith("DEMO-") for e in all_engagements)

    all_assessments = scope_repository.list_assessments()
    assert not any(a.id.startswith("DEMO-") for a in all_assessments)

    all_scope_items = scope_repository.list_scope_items()
    assert not any(s.id.startswith("DEMO-") for s in all_scope_items)
