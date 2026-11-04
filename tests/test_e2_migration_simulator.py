"""
Tests for Phase E2 Read-Only Evidence Migration Simulator.

Validates inventory loading, physical file integrity checks, relational parent
validation, destination path calculation, collision analysis, volume capacity
calculations, safety guards, and strict read-only guarantees.
"""

import hashlib
import json
import os
import sqlite3
from pathlib import Path
import pytest

from app.services.evidence_migration_models import (
    CollisionStatus,
    DestinationStatus,
    PrimaryDisposition,
    SimulationDecision,
)
from app.services.evidence_migration_simulator import (
    EvidenceMigrationSimulator,
    SimulationSafetyError,
    validate_safe_output_dir,
)


@pytest.fixture
def mock_simulator_env(tmp_path: Path):
    """
    Creates an isolated test environment with source evidence, inventory JSON,
    empty destination data directory, and SQLite test database.
    """
    source_dir = tmp_path / "source_evidence"
    source_dir.mkdir(parents=True)

    dest_data_dir = tmp_path / "app_data"
    dest_data_dir.mkdir(parents=True)

    db_path = dest_data_dir / "test_workbench.db"
    conn = sqlite3.connect(db_path)
    cur = conn.cursor()
    cur.execute("PRAGMA user_version = 0;")
    cur.execute("CREATE TABLE schema_version (version INTEGER PRIMARY KEY);")
    cur.execute("INSERT INTO schema_version VALUES (1);")
    cur.execute("CREATE TABLE engagements (id TEXT PRIMARY KEY, title TEXT);")
    cur.execute("CREATE TABLE assessments (id TEXT PRIMARY KEY, engagement_id TEXT, title TEXT);")
    cur.execute("CREATE TABLE findings (id TEXT PRIMARY KEY, assessment_id TEXT, title TEXT);")
    cur.execute("CREATE TABLE check_executions (id TEXT PRIMARY KEY);")
    cur.execute("CREATE TABLE evidence (id TEXT PRIMARY KEY, assessment_id TEXT);")
    cur.execute("CREATE TABLE quarantine_items (seq INTEGER PRIMARY KEY, event_id TEXT);")
    conn.commit()
    conn.close()

    # Create sample files
    asm01_dir = source_dir / "ASM-01"
    asm01_dir.mkdir()
    f1 = asm01_dir / "EVD-hist01.json"
    c1 = json.dumps({"id": "EVD-hist01", "type": "raw_output", "source": "scanner", "capturedAt": "2026-10-31"}).encode()
    f1.write_bytes(c1)
    sha1 = hashlib.sha256(c1).hexdigest()

    asm001_dir = source_dir / "ASM-001"
    asm001_dir.mkdir()
    f2 = asm001_dir / "EVD-active01.json"
    c2 = json.dumps({"id": "EVD-diff-internal", "assessmentId": "ASM-001", "findingId": "FND-001", "type": "http_response", "source": "web", "capturedAt": "2026-10-31"}).encode()
    f2.write_bytes(c2)
    sha2 = hashlib.sha256(c2).hexdigest()

    persist_dir = source_dir / "ASM-PERSIST-TEST"
    persist_dir.mkdir()
    f3 = persist_dir / "EVD-test01.json"
    c3 = b"test"
    f3.write_bytes(c3)
    sha3 = hashlib.sha256(c3).hexdigest()

    inventory = [
        {
            "rel_path": "ASM-01/EVD-hist01.json",
            "byte_size": len(c1),
            "sha256": sha1,
            "primary_disposition": "HISTORICAL_ARCHIVE",
            "migration_status": "HISTORICAL_ELIGIBLE",
        },
        {
            "rel_path": "ASM-001/EVD-active01.json",
            "byte_size": len(c2),
            "sha256": sha2,
            "assessment_id": "ASM-001",
            "finding_id": "FND-001",
            "primary_disposition": "ACTIVE_MIGRATION_CANDIDATE",
            "migration_status": "BLOCKED_MISSING_PARENT",
        },
        {
            "rel_path": "ASM-PERSIST-TEST/EVD-test01.json",
            "byte_size": len(c3),
            "sha256": sha3,
            "primary_disposition": "MALFORMED_PRESERVE",
            "migration_status": "TEST_ARCHIVE_ELIGIBLE",
        },
    ]

    inv_path = tmp_path / "test_inventory.json"
    inv_path.write_text(json.dumps(inventory, indent=2))

    return {
        "source_dir": source_dir,
        "dest_data_dir": dest_data_dir,
        "db_path": db_path,
        "inv_path": inv_path,
        "expected_count": 3,
        "files": {"f1": (f1, sha1, len(c1)), "f2": (f2, sha2, len(c2)), "f3": (f3, sha3, len(c3))},
    }


# =====================================================================
# A. INVENTORY TESTS
# =====================================================================

def test_inventory_validation_success(mock_simulator_env):
    sim = EvidenceMigrationSimulator(
        source_evidence_dir=mock_simulator_env["source_dir"],
        inventory_file=mock_simulator_env["inv_path"],
        dest_data_dir=mock_simulator_env["dest_data_dir"],
        db_path=mock_simulator_env["db_path"],
        expected_artifact_count=mock_simulator_env["expected_count"],
    )
    records, inv_sha = sim.validate_inventory()
    assert len(records) == 3
    assert len(inv_sha) == 64


def test_inventory_count_mismatch(mock_simulator_env):
    sim = EvidenceMigrationSimulator(
        source_evidence_dir=mock_simulator_env["source_dir"],
        inventory_file=mock_simulator_env["inv_path"],
        dest_data_dir=mock_simulator_env["dest_data_dir"],
        db_path=mock_simulator_env["db_path"],
        expected_artifact_count=174,  # Mismatch with 3
    )
    with pytest.raises(ValueError, match="Inventory count mismatch"):
        sim.validate_inventory()


def test_inventory_duplicate_paths(mock_simulator_env):
    dup_inv = [
        {"rel_path": "ASM-01/EVD-hist01.json", "byte_size": 10, "sha256": "abc", "primary_disposition": "HISTORICAL_ARCHIVE"},
        {"rel_path": "asm-01/evd-hist01.json", "byte_size": 10, "sha256": "abc", "primary_disposition": "HISTORICAL_ARCHIVE"},
    ]
    p = mock_simulator_env["dest_data_dir"] / "dup_inv.json"
    p.write_text(json.dumps(dup_inv))

    sim = EvidenceMigrationSimulator(
        source_evidence_dir=mock_simulator_env["source_dir"],
        inventory_file=p,
        dest_data_dir=mock_simulator_env["dest_data_dir"],
        db_path=mock_simulator_env["db_path"],
        expected_artifact_count=2,
    )
    with pytest.raises(ValueError, match="Duplicate relative path"):
        sim.validate_inventory()


def test_inventory_missing_file_on_disk(mock_simulator_env):
    inv = [
        {"rel_path": "ASM-01/EVD-missing.json", "byte_size": 10, "sha256": "abc", "primary_disposition": "HISTORICAL_ARCHIVE"},
    ]
    p = mock_simulator_env["dest_data_dir"] / "missing_inv.json"
    p.write_text(json.dumps(inv))

    sim = EvidenceMigrationSimulator(
        source_evidence_dir=mock_simulator_env["source_dir"],
        inventory_file=p,
        dest_data_dir=mock_simulator_env["dest_data_dir"],
        db_path=mock_simulator_env["db_path"],
        expected_artifact_count=1,
    )
    report = sim.run_simulation()
    assert report.total_artifacts == 1
    assert report.artifacts[0].decision == SimulationDecision.BLOCKED_PATH_VALIDATION.value
    assert "missing on disk" in report.artifacts[0].reason


# =====================================================================
# B. INTEGRITY TESTS
# =====================================================================

def test_hash_and_size_mismatch_detection(mock_simulator_env):
    bad_inv = [
        {
            "rel_path": "ASM-01/EVD-hist01.json",
            "byte_size": 9999,
            "sha256": "0000000000000000000000000000000000000000000000000000000000000000",
            "primary_disposition": "HISTORICAL_ARCHIVE",
        }
    ]
    p = mock_simulator_env["dest_data_dir"] / "bad_hash_inv.json"
    p.write_text(json.dumps(bad_inv))

    sim = EvidenceMigrationSimulator(
        source_evidence_dir=mock_simulator_env["source_dir"],
        inventory_file=p,
        dest_data_dir=mock_simulator_env["dest_data_dir"],
        db_path=mock_simulator_env["db_path"],
        expected_artifact_count=1,
    )
    report = sim.run_simulation()
    res = report.artifacts[0]
    assert res.decision == SimulationDecision.BLOCKED_SOURCE_INTEGRITY.value
    assert "SHA-256 or size mismatch" in res.reason


def test_malformed_json_and_id_divergence(mock_simulator_env):
    sim = EvidenceMigrationSimulator(
        source_evidence_dir=mock_simulator_env["source_dir"],
        inventory_file=mock_simulator_env["inv_path"],
        dest_data_dir=mock_simulator_env["dest_data_dir"],
        db_path=mock_simulator_env["db_path"],
        expected_artifact_count=mock_simulator_env["expected_count"],
    )
    report = sim.run_simulation()

    # Check active candidate with ID divergence (EVD-active01 vs internal EVD-diff-internal)
    active = next(a for a in report.artifacts if a.source_relative_path == "ASM-001/EVD-active01.json")
    assert active.canonical_filename_id == "EVD-active01"
    assert active.embedded_legacy_id == "EVD-diff-internal"
    assert active.id_discrepancy is True

    # Check malformed file (b"test")
    malformed = next(a for a in report.artifacts if a.source_relative_path == "ASM-PERSIST-TEST/EVD-test01.json")
    assert "MALFORMED_JSON_SCHEMA" in malformed.json_validation_result
    assert malformed.decision == SimulationDecision.WOULD_PRESERVE_AS_TEST_ARCHIVE.value


def test_duplicate_content_groups(mock_simulator_env):
    # Add identical duplicate file
    src = mock_simulator_env["source_dir"]
    dup_file = src / "ASM-01" / "EVD-hist02_dup.json"
    dup_file.write_bytes(mock_simulator_env["files"]["f1"][0].read_bytes())
    sha1 = mock_simulator_env["files"]["f1"][1]

    inv = [
        {"rel_path": "ASM-01/EVD-hist01.json", "byte_size": mock_simulator_env["files"]["f1"][2], "sha256": sha1, "primary_disposition": "HISTORICAL_ARCHIVE"},
        {"rel_path": "ASM-01/EVD-hist02_dup.json", "byte_size": mock_simulator_env["files"]["f1"][2], "sha256": sha1, "primary_disposition": "HISTORICAL_ARCHIVE"},
    ]
    p = mock_simulator_env["dest_data_dir"] / "dup_content_inv.json"
    p.write_text(json.dumps(inv))

    sim = EvidenceMigrationSimulator(
        source_evidence_dir=mock_simulator_env["source_dir"],
        inventory_file=p,
        dest_data_dir=mock_simulator_env["dest_data_dir"],
        db_path=mock_simulator_env["db_path"],
        expected_artifact_count=2,
    )
    report = sim.run_simulation()
    assert len(report.duplicate_content_groups) == 1
    assert report.duplicate_content_groups[0]["count"] == 2
    # Verify no deduplication occurred
    assert len(report.artifacts) == 2


# =====================================================================
# C. RELATIONAL AND DATABASE VALIDATION
# =====================================================================

def test_active_candidate_blocked_when_parents_missing(mock_simulator_env):
    sim = EvidenceMigrationSimulator(
        source_evidence_dir=mock_simulator_env["source_dir"],
        inventory_file=mock_simulator_env["inv_path"],
        dest_data_dir=mock_simulator_env["dest_data_dir"],
        db_path=mock_simulator_env["db_path"],
        expected_artifact_count=mock_simulator_env["expected_count"],
    )
    report = sim.run_simulation()
    active = next(a for a in report.artifacts if a.primary_disposition == PrimaryDisposition.ACTIVE_MIGRATION_CANDIDATE.value)
    assert active.decision == SimulationDecision.BLOCKED_MISSING_PARENT.value
    assert "assessment 'ASM-001' missing" in active.relational_validation_result


def test_active_candidate_verified_when_parents_exist(mock_simulator_env):
    # Insert required parent records
    conn = sqlite3.connect(mock_simulator_env["db_path"])
    cur = conn.cursor()
    cur.execute("INSERT INTO engagements VALUES ('ENG-001', 'Test Eng');")
    cur.execute("INSERT INTO assessments VALUES ('ASM-001', 'ENG-001', 'Test Asm');")
    cur.execute("INSERT INTO findings VALUES ('FND-001', 'ASM-001', 'Test Finding');")
    conn.commit()
    conn.close()

    sim = EvidenceMigrationSimulator(
        source_evidence_dir=mock_simulator_env["source_dir"],
        inventory_file=mock_simulator_env["inv_path"],
        dest_data_dir=mock_simulator_env["dest_data_dir"],
        db_path=mock_simulator_env["db_path"],
        expected_artifact_count=mock_simulator_env["expected_count"],
    )
    report = sim.run_simulation()
    active = next(a for a in report.artifacts if a.primary_disposition == PrimaryDisposition.ACTIVE_MIGRATION_CANDIDATE.value)
    assert active.relational_validation_result == "RELATIONAL_PARENTS_VERIFIED"
    assert active.decision == SimulationDecision.REQUIRES_OPERATOR_REVIEW.value


# =====================================================================
# D. DESTINATION COLLISION TESTS
# =====================================================================

def test_destination_collision_identical_hash(mock_simulator_env):
    dest_dir = mock_simulator_env["dest_data_dir"]
    target = dest_dir / "archive" / "evidence" / "ASM-01" / "EVD-hist01.json"
    target.parent.mkdir(parents=True)
    target.write_bytes(mock_simulator_env["files"]["f1"][0].read_bytes())

    sim = EvidenceMigrationSimulator(
        source_evidence_dir=mock_simulator_env["source_dir"],
        inventory_file=mock_simulator_env["inv_path"],
        dest_data_dir=mock_simulator_env["dest_data_dir"],
        db_path=mock_simulator_env["db_path"],
        expected_artifact_count=mock_simulator_env["expected_count"],
    )
    report = sim.run_simulation()
    hist = next(a for a in report.artifacts if a.source_relative_path == "ASM-01/EVD-hist01.json")
    assert hist.destination_status == DestinationStatus.EXISTING_IDENTICAL_UNOWNED.value
    assert hist.collision_status == CollisionStatus.IDENTICAL_HASH_COLLISION.value
    assert hist.decision == SimulationDecision.BLOCKED_DESTINATION_COLLISION.value


def test_destination_collision_different_hash(mock_simulator_env):
    dest_dir = mock_simulator_env["dest_data_dir"]
    target = dest_dir / "archive" / "evidence" / "ASM-01" / "EVD-hist01.json"
    target.parent.mkdir(parents=True)
    target.write_bytes(b"different content")

    sim = EvidenceMigrationSimulator(
        source_evidence_dir=mock_simulator_env["source_dir"],
        inventory_file=mock_simulator_env["inv_path"],
        dest_data_dir=mock_simulator_env["dest_data_dir"],
        db_path=mock_simulator_env["db_path"],
        expected_artifact_count=mock_simulator_env["expected_count"],
    )
    report = sim.run_simulation()
    hist = next(a for a in report.artifacts if a.source_relative_path == "ASM-01/EVD-hist01.json")
    assert hist.destination_status == DestinationStatus.EXISTING_DIFFERENT_HASH.value
    assert hist.collision_status == CollisionStatus.HASH_MISMATCH_COLLISION.value
    assert hist.decision == SimulationDecision.BLOCKED_DESTINATION_COLLISION.value


# =====================================================================
# E. SAFETY ASSERTONS & OUTPUT VALIDATION
# =====================================================================

def test_safe_output_dir_guard(tmp_path: Path):
    repo_root = tmp_path / "repo"
    repo_root.mkdir()
    source_dir = repo_root / "database" / "evidence"
    source_dir.mkdir(parents=True)
    data_dir = tmp_path / "appdata"
    data_dir.mkdir()
    db_path = data_dir / "workbench.db"
    db_path.touch()

    # Safe external output directory
    safe_out = tmp_path / "safe_reports"
    assert validate_safe_output_dir(safe_out, repo_root, source_dir, data_dir, db_path) == safe_out.resolve()

    # Reject inside repo
    with pytest.raises(SimulationSafetyError, match="repository_root"):
        validate_safe_output_dir(repo_root / "reports", repo_root, source_dir, data_dir, db_path)

    # Reject inside evidence dir
    with pytest.raises(SimulationSafetyError, match="source_evidence_dir"):
        validate_safe_output_dir(source_dir / "out", repo_root, source_dir, data_dir, db_path)

    # Reject inside runtime data dir
    with pytest.raises(SimulationSafetyError, match="runtime_data_dir"):
        validate_safe_output_dir(data_dir / "reports", repo_root, source_dir, data_dir, db_path)


def test_zero_mutation_guarantee(mock_simulator_env):
    source_dir = mock_simulator_env["source_dir"]
    dest_dir = mock_simulator_env["dest_data_dir"]
    db_path = mock_simulator_env["db_path"]

    # Record hashes before
    db_bytes_before = db_path.read_bytes()
    source_bytes_before = {p: p.read_bytes() for p in source_dir.rglob("*.json")}

    sim = EvidenceMigrationSimulator(
        source_evidence_dir=source_dir,
        inventory_file=mock_simulator_env["inv_path"],
        dest_data_dir=dest_dir,
        db_path=db_path,
        expected_artifact_count=mock_simulator_env["expected_count"],
    )
    sim.run_simulation()

    # Verify zero database mutation
    assert db_path.read_bytes() == db_bytes_before

    # Verify zero source file mutation
    for p, b in source_bytes_before.items():
        assert p.read_bytes() == b

    # Verify no archive directory was created in destination
    assert not (dest_dir / "archive").exists()
    assert not (dest_dir / "evidence").exists()
