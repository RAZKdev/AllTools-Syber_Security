"""
Tests for Stable Manifest Identity V2 (Phase E3B Readiness).

Validates:
 1. Same filename ID in different source directories.
 2. Same content hash across different source paths.
 3. Same artifact retried under different operation IDs.
 4. Same identity with changed disposition (fails closed).
 5. Same identity with changed physical SHA-256 (fails closed).
 6. Same identity with changed destination path (fails closed).
 7. Windows case-variant paths (case-insensitive normalization).
 8. Unicode-normalization equivalent paths (NFC).
 9. Path traversal rejection ('..').
10. Absolute path rejection (POSIX leading slash, Windows drive letters).
11. Invalid artifact ID rejection (empty, traversal, path separators).
12. Repeated identity generation produces identical full SHA-256 IDs.
13. All 174 inventory identities remain unique.
"""

import hashlib
import json
import re
import unicodedata
from pathlib import Path
import pytest

from app.core.instance_lock import InstanceLock, MaintenanceSession
from app.services.archive_manager import ArchiveManager
from app.services.migration_models import (
    DEFAULT_IDENTITY_VERSION,
    DEFAULT_SOURCE_NAMESPACE,
    ArchiveManifestEntry,
    MigrationIntegrityError,
    extract_source_relative_path,
    generate_manifest_record_id_v1,
    generate_manifest_record_id_v2,
    normalize_source_relative_path,
    validate_canonical_artifact_id,
)


@pytest.fixture
def identity_sandbox(tmp_path: Path):
    """Provides isolated test directory and acquired MaintenanceSession."""
    data_dir = tmp_path / "sandbox_data"
    data_dir.mkdir(parents=True)

    lock_file = data_dir / "workbench.lock"
    lock = InstanceLock(lock_file)
    lock.acquire()
    session = MaintenanceSession(lock)

    archive_mgr = ArchiveManager(data_dir=data_dir, maintenance_session=session)

    yield {
        "tmp_path": tmp_path,
        "data_dir": data_dir,
        "lock": lock,
        "session": session,
        "archive_mgr": archive_mgr,
    }

    lock.release()


def _create_archive_target(archive_mgr: ArchiveManager, rel_dest: str, content: bytes) -> Path:
    target_p = archive_mgr.data_dir / rel_dest
    target_p.parent.mkdir(parents=True, exist_ok=True)
    target_p.write_bytes(content)
    return target_p


# =====================================================================
# 1. DIFFERENT DIRECTORIES & SAME FILENAME
# =====================================================================

def test_01_same_filename_id_in_different_source_directories():
    """1. Same filename ID in different source directories produces distinct V2 identities."""
    id1 = generate_manifest_record_id_v2("ASM-01/EVD-01.json", "EVD-01")
    id2 = generate_manifest_record_id_v2("ASM-02/EVD-01.json", "EVD-01")
    assert id1 != id2
    assert len(id1) == 64
    assert len(id2) == 64


# =====================================================================
# 2. SAME CONTENT HASH ACROSS DIFFERENT PATHS
# =====================================================================

def test_02_same_content_hash_across_different_source_paths():
    """2. Same content hash across different source paths produces distinct V2 identities."""
    id_a = generate_manifest_record_id_v2("ASM-01/EVD-fileA.json", "EVD-fileA")
    id_b = generate_manifest_record_id_v2("ASM-01/EVD-fileB.json", "EVD-fileB")
    assert id_a != id_b


# =====================================================================
# 3. SAME ARTIFACT RETRIED UNDER DIFFERENT OPERATION IDs
# =====================================================================

def test_03_same_artifact_retried_under_different_operation_ids(identity_sandbox):
    """3. Same artifact retried under different operation IDs retains identical ID and creates no duplicates."""
    archive_mgr = identity_sandbox["archive_mgr"]
    content = b'{"status": "stable_identity"}'
    sha = hashlib.sha256(content).hexdigest()
    target = _create_archive_target(archive_mgr, "archive/evidence/ASM-01/EVD-idem.json", content)

    # First attempt under OP-RUN-1
    e1 = archive_mgr.append_manifest_entry(
        source_path="ASM-01/EVD-idem.json",
        target_path=str(target),
        sha256=sha,
        byte_size=len(content),
        filename="EVD-idem.json",
        classification="HISTORICAL_ARCHIVE",
        operation_id="OP-RUN-1",
        artifact_id="EVD-idem",
    )

    # Second attempt under OP-RUN-2 (different operation_id)
    e2 = archive_mgr.append_manifest_entry(
        source_path="ASM-01/EVD-idem.json",
        target_path=str(target),
        sha256=sha,
        byte_size=len(content),
        filename="EVD-idem.json",
        classification="HISTORICAL_ARCHIVE",
        operation_id="OP-RUN-2",
        artifact_id="EVD-idem",
    )

    # Same manifest_record_id
    assert e1.manifest_record_id == e2.manifest_record_id
    assert len(e1.manifest_record_id) == 64
    assert e1.identity_version == 2
    assert e2.identity_version == 2

    # Exactly 1 physical record line in JSONL file
    records = archive_mgr.read_manifest_entries()
    assert len(records) == 1
    assert records[0].manifest_record_id == e1.manifest_record_id


# =====================================================================
# 4. CHANGED DISPOSITION FAILS CLOSED
# =====================================================================

def test_04_same_identity_with_changed_disposition(identity_sandbox):
    """4. Same identity attempted with changed disposition fails closed requiring reclassification review."""
    archive_mgr = identity_sandbox["archive_mgr"]
    content = b'{"status": "disposition_check"}'
    sha = hashlib.sha256(content).hexdigest()
    target = _create_archive_target(archive_mgr, "archive/evidence/ASM-01/EVD-disp.json", content)

    archive_mgr.append_manifest_entry(
        source_path="ASM-01/EVD-disp.json",
        target_path=str(target),
        sha256=sha,
        byte_size=len(content),
        filename="EVD-disp.json",
        classification="HISTORICAL_ARCHIVE",
        operation_id="OP-DISP-1",
        artifact_id="EVD-disp",
    )

    # Attempt reclassification under same identity
    with pytest.raises(MigrationIntegrityError) as exc_info:
        archive_mgr.append_manifest_entry(
            source_path="ASM-01/EVD-disp.json",
            target_path=str(target),
            sha256=sha,
            byte_size=len(content),
            filename="EVD-disp.json",
            classification="LEGACY_TEST_ARCHIVE",
            operation_id="OP-DISP-2",
            artifact_id="EVD-disp",
        )
    assert "Different disposition for existing identity" in str(exc_info.value)
    assert "reclassification review" in str(exc_info.value)


# =====================================================================
# 5. CHANGED PHYSICAL SHA-256 FAILS CLOSED
# =====================================================================

def test_05_same_identity_with_changed_physical_sha256(identity_sandbox):
    """5. Same identity attempted with changed physical SHA-256 fails closed."""
    archive_mgr = identity_sandbox["archive_mgr"]
    content = b'{"status": "original_content"}'
    sha1 = hashlib.sha256(content).hexdigest()
    target = _create_archive_target(archive_mgr, "archive/evidence/ASM-01/EVD-hash.json", content)

    archive_mgr.append_manifest_entry(
        source_path="ASM-01/EVD-hash.json",
        target_path=str(target),
        sha256=sha1,
        byte_size=len(content),
        filename="EVD-hash.json",
        classification="HISTORICAL_ARCHIVE",
        operation_id="OP-HASH-1",
        artifact_id="EVD-hash",
    )

    # Tamper with physical target file
    tampered_content = b'{"status": "tampered_corrupted_bytes"}'
    target.write_bytes(tampered_content)
    sha2 = hashlib.sha256(tampered_content).hexdigest()

    with pytest.raises(MigrationIntegrityError) as exc_info:
        archive_mgr.append_manifest_entry(
            source_path="ASM-01/EVD-hash.json",
            target_path=str(target),
            sha256=sha2,
            byte_size=len(tampered_content),
            filename="EVD-hash.json",
            classification="HISTORICAL_ARCHIVE",
            operation_id="OP-HASH-2",
            artifact_id="EVD-hash",
        )
    assert "Physical SHA-256 mismatch for existing record" in str(exc_info.value)


# =====================================================================
# 6. CHANGED DESTINATION PATH FAILS CLOSED
# =====================================================================

def test_06_same_identity_with_changed_destination_path(identity_sandbox):
    """6. Same identity attempted with changed destination path fails closed requiring operator review."""
    archive_mgr = identity_sandbox["archive_mgr"]
    content = b'{"status": "dest_check"}'
    sha = hashlib.sha256(content).hexdigest()
    target1 = _create_archive_target(archive_mgr, "archive/evidence/ASM-01/EVD-dest.json", content)
    target2 = _create_archive_target(archive_mgr, "archive/evidence/ASM-01/EVD-dest-ALT.json", content)

    archive_mgr.append_manifest_entry(
        source_path="ASM-01/EVD-dest.json",
        target_path=str(target1),
        sha256=sha,
        byte_size=len(content),
        filename="EVD-dest.json",
        classification="HISTORICAL_ARCHIVE",
        operation_id="OP-DEST-1",
        artifact_id="EVD-dest",
    )

    with pytest.raises(MigrationIntegrityError) as exc_info:
        archive_mgr.append_manifest_entry(
            source_path="ASM-01/EVD-dest.json",
            target_path=str(target2),
            sha256=sha,
            byte_size=len(content),
            filename="EVD-dest-ALT.json",
            classification="HISTORICAL_ARCHIVE",
            operation_id="OP-DEST-2",
            artifact_id="EVD-dest",
        )
    assert "Different destination path for existing identity" in str(exc_info.value)
    assert "operator review" in str(exc_info.value)


# =====================================================================
# 7. WINDOWS CASE-VARIANT PATHS
# =====================================================================

def test_07_windows_case_variant_paths():
    """7. Windows case-variant source paths resolve to identical canonical identity."""
    id1 = generate_manifest_record_id_v2("ASM-01/EVD-01.json", "EVD-01")
    id2 = generate_manifest_record_id_v2("asm-01/evd-01.json", "EVD-01")
    id3 = generate_manifest_record_id_v2("Asm-01/Evd-01.JSON", "EVD-01")
    id4 = generate_manifest_record_id_v2("ASM-01\\EVD-01.json", "EVD-01")
    assert id1 == id2 == id3 == id4


# =====================================================================
# 8. UNICODE NORMALIZATION EQUIVALENT PATHS
# =====================================================================

def test_08_unicode_normalization_equivalent_paths():
    """8. Unicode NFC and NFD equivalent paths resolve to identical canonical identity."""
    # Precomposed é (\u00e9) vs decomposed e + combining acute (\u0301)
    nfc_path = "evidence/\u00e9quipe/evd-01.json"
    nfd_path = "evidence/e\u0301quipe/evd-01.json"

    id_nfc = generate_manifest_record_id_v2(nfc_path, "evd-01")
    id_nfd = generate_manifest_record_id_v2(nfd_path, "evd-01")
    assert id_nfc == id_nfd


# =====================================================================
# 9. PATH TRAVERSAL REJECTION
# =====================================================================

def test_09_path_traversal_rejection():
    """9. Path traversal components ('..') are strictly rejected."""
    traversal_paths = [
        "ASM-01/../escaped.json",
        "../../etc/passwd",
        "ASM-01/sub/../../test.json",
        "..\\traversal.json",
    ]
    for path in traversal_paths:
        with pytest.raises(MigrationIntegrityError) as exc_info:
            normalize_source_relative_path(path)
        assert "Path traversal ('..') is strictly rejected" in str(exc_info.value)


# =====================================================================
# 10. ABSOLUTE PATH REJECTION
# =====================================================================

def test_10_absolute_path_rejection():
    """10. Absolute paths and Windows drive-letter paths are strictly rejected."""
    absolute_paths = [
        "/evidence/ASM-01/EVD-01.json",
        "\\evidence\\ASM-01\\EVD-01.json",
        "C:/Users/Rangga/evidence/EVD-01.json",
        "D:\\PROJECT SAYA\\database\\evidence\\EVD-01.json",
    ]
    for path in absolute_paths:
        with pytest.raises(MigrationIntegrityError) as exc_info:
            normalize_source_relative_path(path)
        assert "Absolute paths are strictly rejected" in str(exc_info.value) or "Drive-letter paths are strictly rejected" in str(exc_info.value)


# =====================================================================
# 11. INVALID ARTIFACT ID REJECTION
# =====================================================================

def test_11_invalid_artifact_id_rejection():
    """11. Invalid artifact IDs (empty, whitespace, traversal, path separators) are rejected."""
    invalid_ids = ["", "   ", "sub/id", "sub\\id", "../id", "..", None]
    for bad_id in invalid_ids:
        with pytest.raises(MigrationIntegrityError):
            validate_canonical_artifact_id(bad_id)


# =====================================================================
# 12. REPEATED IDENTITY GENERATION REPEATABILITY
# =====================================================================

def test_12_repeated_identity_generation_produces_identical_full_sha256():
    """12. Repeated identity generation produces identical full 64-character SHA-256 IDs."""
    source_path = "ASM-01/EVD-repeat.json"
    artifact_id = "EVD-repeat"
    base_id = generate_manifest_record_id_v2(source_path, artifact_id)

    assert len(base_id) == 64
    assert bool(re.match(r"^[0-9a-f]{64}$", base_id))

    for _ in range(500):
        assert generate_manifest_record_id_v2(source_path, artifact_id) == base_id


# =====================================================================
# 13. ALL 174 INVENTORY IDENTITIES REMAIN UNIQUE
# =====================================================================

def test_13_all_174_inventory_identities_remain_unique():
    """13. All 174 inventory artifacts generate unique V2 identities with zero collisions."""
    inv_file = Path(r"C:\Users\Rangga\.gemini\antigravity\brain\72d04d7a-59e5-45ea-b077-8c9e8e67ef4e\legacy-evidence-inventory.json")
    if not inv_file.exists():
        pytest.skip("Authoritative legacy inventory file not found in artifact path.")

    raw = json.loads(inv_file.read_text(encoding="utf-8"))
    artifacts = raw if isinstance(raw, list) else raw.get("artifacts", [])
    assert len(artifacts) == 174

    generated_ids = set()
    for a in artifacts:
        rel_p = a.get("rel_path") or a.get("relative_path")
        fn = a.get("filename") or Path(rel_p).name
        art_id = a.get("artifact_id") or Path(fn).stem

        rec_id = generate_manifest_record_id_v2(
            source_relative_path=rel_p,
            artifact_id=art_id,
        )
        assert len(rec_id) == 64
        assert bool(re.match(r"^[0-9a-f]{64}$", rec_id))
        assert rec_id not in generated_ids, f"Collision detected for record ID '{rec_id}' on '{rel_p}'"
        generated_ids.add(rec_id)

    assert len(generated_ids) == 174
