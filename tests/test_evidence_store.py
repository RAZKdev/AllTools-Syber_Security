import pytest
from app.schemas.evidence import EvidenceType
from evidence.storage import EvidenceStore


@pytest.fixture
def store():
    return EvidenceStore()


def test_evidence_hashing_and_integrity(store):
    payload = {"status": "ok", "target": "https://api.lab.local"}
    ev = store.record_evidence(
        assessment_id="ASM-01",
        evidence_type=EvidenceType.JSON_RESULT,
        source="https://api.lab.local",
        raw_content=payload,
    )
    assert len(ev.sha256) == 64
    assert ev.assessmentId == "ASM-01"
    assert ev.redacted is False


def test_evidence_sensitive_redaction(store):
    raw_headers = {
        "Authorization": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.sensitivePayload12345",
        "Content-Type": "application/json",
        "Set-Cookie": "session_id=SECRET_SESSION_TOKEN_XYZ; Secure; HttpOnly",
    }
    ev = store.record_evidence(
        assessment_id="ASM-01",
        evidence_type=EvidenceType.HTTP_RESPONSE,
        source="https://api.lab.local/login",
        raw_content=raw_headers,
    )
    assert ev.redacted is True
    # Verify retrieved record
    record = store.get_evidence(ev.id)
    assert record is not None
    assert record.sha256 == ev.sha256
