import pytest
from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def test_health_check():
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert data["service"] == "alltools-cybersec-backend"


def test_engagement_and_scope_workflow():
    # 1. Create engagement
    eng_res = client.post(
        "/api/v1/engagements",
        json={
            "workspaceId": "WKS-01",
            "name": "Local Lab Assessment",
            "description": "Authorized local security audit",
            "assessor": "Operator",
            "status": "active",
        },
    )
    assert eng_res.status_code == 201
    eng_data = eng_res.json()
    eng_id = eng_data["id"]

    # 2. Add Scope items
    scope_res1 = client.post(
        "/api/v1/scope/items",
        json={
            "engagementId": eng_id,
            "type": "domain",
            "value": "authorized.local",
            "inScope": True,
        },
    )
    assert scope_res1.status_code == 201

    scope_res2 = client.post(
        "/api/v1/scope/items",
        json={
            "engagementId": eng_id,
            "type": "domain",
            "value": "critical.authorized.local",
            "inScope": False,
            "notes": "Strictly excluded sensitive host",
        },
    )
    assert scope_res2.status_code == 201

    # 3. Create Assessment
    asm_res = client.post(
        "/api/v1/assessments",
        json={
            "engagementId": eng_id,
            "name": "Web Infrastructure Scan",
            "type": "web",
            "status": "running",
        },
    )
    assert asm_res.status_code == 201
    asm_id = asm_res.json()["id"]

    # 4. Scope Evaluation via API - Allowed target
    eval_allow = client.post(
        "/api/v1/scope/evaluate",
        json={
            "assessmentId": asm_id,
            "target": "web.authorized.local",
        },
    )
    assert eval_allow.status_code == 200
    assert eval_allow.json()["decision"] == "ALLOW"

    # 5. Scope Evaluation via API - Excluded target
    eval_excl = client.post(
        "/api/v1/scope/evaluate",
        json={
            "assessmentId": asm_id,
            "target": "critical.authorized.local",
        },
    )
    assert eval_excl.status_code == 200
    assert eval_excl.json()["decision"] == "BLOCK"
    assert "explicitly excluded" in eval_excl.json()["reason"]

    # 6. Scope Evaluation via API - Out-of-scope target (Default Deny)
    eval_out = client.post(
        "/api/v1/scope/evaluate",
        json={
            "assessmentId": asm_id,
            "target": "unauthorized.external.com",
        },
    )
    assert eval_out.status_code == 200
    assert eval_out.json()["decision"] == "BLOCK"

    # 7. Pre-flight check endpoint - Execution with allowed target
    pre_allow = client.post(
        "/api/v1/executions/pre-flight",
        json={
            "assessmentId": asm_id,
            "ruleId": "SEC-WEB-001",
            "target": "web.authorized.local",
        },
    )
    assert pre_allow.status_code == 200
    data_allow = pre_allow.json()
    assert data_allow["allowed"] is True
    assert data_allow["executionRecord"]["scopeDecision"] == "ALLOW"
    assert data_allow["executionRecord"]["status"] == "PASS"

    # 8. Pre-flight check endpoint - Execution with blocked target
    pre_block = client.post(
        "/api/v1/executions/pre-flight",
        json={
            "assessmentId": asm_id,
            "ruleId": "SEC-WEB-001",
            "target": "external-attacker.com",
        },
    )
    assert pre_block.status_code == 200
    data_block = pre_block.json()
    assert data_block["allowed"] is False
    assert data_block["executionRecord"]["scopeDecision"] == "BLOCK"
    assert data_block["executionRecord"]["status"] == "BLOCKED_OUT_OF_SCOPE"
    assert "BLOCKED — OUT OF SCOPE" in data_block["message"]

    # 9. Run check endpoint - Allowed execution yielding observation & evidence
    run_res = client.post(
        "/api/v1/executions/run",
        json={
            "assessmentId": asm_id,
            "ruleId": "SEC-WEB-001",
            "target": "web.authorized.local",
            "simulatedData": {
                "strict-transport-security": "max-age=31536000",
                "content-security-policy": "default-src 'self'",
                "x-content-type-options": "nosniff",
                "x-frame-options": "DENY",
            },
        },
    )
    assert run_res.status_code == 200
    run_data = run_res.json()
    assert run_data["allowed"] is True
    assert run_data["executionRecord"]["status"] == "PASS"
    assert run_data["observation"] is not None
    assert run_data["evidence"] is not None

    # 10. Run check endpoint - Blocked execution (Scope Guard fails closed)
    run_blocked = client.post(
        "/api/v1/executions/run",
        json={
            "assessmentId": asm_id,
            "ruleId": "SEC-WEB-001",
            "target": "unauthorized.net",
        },
    )
    assert run_blocked.status_code == 200
    assert run_blocked.json()["allowed"] is False
    assert run_blocked.json()["executionRecord"]["status"] == "BLOCKED_OUT_OF_SCOPE"

    # 11. Run check endpoint - Finding generation on missing headers
    run_vuln = client.post(
        "/api/v1/executions/run",
        json={
            "assessmentId": asm_id,
            "ruleId": "SEC-WEB-001",
            "target": "web.authorized.local",
            "simulatedData": {
                "server": "Apache",
            },
        },
    )
    assert run_vuln.status_code == 200
    vuln_data = run_vuln.json()
    assert vuln_data["executionRecord"]["status"] == "FAIL"
    assert vuln_data["finding"] is not None
    fnd_id = vuln_data["finding"]["id"]

    # 12. Query Findings API
    fnd_res = client.get(f"/api/v1/findings/{fnd_id}")
    assert fnd_res.status_code == 200
    assert fnd_res.json()["title"].startswith("Missing Defensive HTTP Security Headers")

    # 13. Query Evidence API
    evd_res = client.get(f"/api/v1/evidence?findingId={fnd_id}")
    assert evd_res.status_code == 200
    assert len(evd_res.json()) >= 1
    assert len(evd_res.json()[0]["sha256"]) == 64

    # 14. Export Markdown Report
    rep_md_res = client.get(f"/api/v1/reports/{asm_id}/markdown")
    assert rep_md_res.status_code == 200
    assert "Defensive Security Assessment Report" in rep_md_res.text
    assert fnd_id in rep_md_res.text

    # 15. Export HTML Report
    rep_html_res = client.get(f"/api/v1/reports/{asm_id}/html")
    assert rep_html_res.status_code == 200
    assert "<!DOCTYPE html>" in rep_html_res.text
    assert "Security Assessment Report" in rep_html_res.text
