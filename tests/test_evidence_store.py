import pytest
from app.schemas.evidence import EvidenceType
from evidence.storage import EvidenceStore


@pytest.fixture
def store(tmp_path):
    return EvidenceStore(base_dir=tmp_path)


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


def test_evidence_disk_persistence_and_integrity_verification(tmp_path):
    """Verify that evidence artifacts are saved to disk and SHA-256 matches disk bytes."""
    custom_store = EvidenceStore(base_dir=tmp_path)
    payload = {"scan": "complete", "open_ports": [80, 443]}
    ev = custom_store.record_evidence(
        assessment_id="ASM-PERSIST-01",
        evidence_type=EvidenceType.JSON_RESULT,
        source="scanner",
        raw_content=payload,
    )
    assert ev.artifactPath is not None
    # Artifact file exists on disk
    artifact_file = tmp_path / "ASM-PERSIST-01" / f"{ev.id}.json"
    assert artifact_file.is_file()

    # Integrity verification matches
    assert custom_store.verify_evidence_integrity(ev.id) is True

    # Purge removes files
    purged = custom_store.purge_evidence_for_assessment("ASM-PERSIST-01")
    assert purged == 1
    assert not artifact_file.is_file()


def test_evidence_path_traversal_prevention(tmp_path):
    """Verify that path traversal attempts in assessment_id are sanitized."""
    custom_store = EvidenceStore(base_dir=tmp_path)
    ev = custom_store.record_evidence(
        assessment_id="../../etc/shadow",
        evidence_type=EvidenceType.JSON_RESULT,
        source="test",
        raw_content="safe content",
    )
    # Traversal characters must be stripped
    assert ".." not in ev.artifactPath
    assert "shadow" in ev.artifactPath
