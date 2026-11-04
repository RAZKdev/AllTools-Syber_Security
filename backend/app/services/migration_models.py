"""
Migration Models & Schema Contracts - Phase E3A.

Defines Pydantic data models, enum states, manifest structures, and exceptions
for the migration engine, SQLite migration journal, archive manager, and audit outbox.
"""

import hashlib
import json
import os
import re
import unicodedata
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field, model_validator


DEFAULT_IDENTITY_VERSION = 2
DEFAULT_SOURCE_NAMESPACE = "alltools-cybersec-legacy-evidence"


class MigrationError(Exception):
    """Base exception for all evidence migration subsystem failures."""
    pass


class MigrationSafetyError(MigrationError):
    """Raised when an operation would violate safety boundaries or target production storage."""
    pass


class InvalidStateTransitionError(MigrationError):
    """Raised when a state machine transition violates approved migration ordering."""
    pass


class MigrationCollisionError(MigrationError):
    """Raised when a target destination already exists (no-clobber invariant)."""
    pass


class MigrationIntegrityError(MigrationError):
    """Raised when artifact SHA-256 or byte-size checks fail."""
    pass


class MigrationRecoveryError(MigrationError):
    """Raised when automatic journal recovery cannot deterministically reconcile an artifact."""
    pass


def extract_source_relative_path(path: Any, parent_folder: Optional[str] = None) -> str:
    """
    Extracts a source relative path from an absolute or relative file path:
    - If already relative, normalizes separators and strips redundant prefix.
    - If absolute, extracts from parent_folder, or evidence root markers.
    """
    p = Path(path)
    clean = str(path).replace("\\", "/")
    if not p.is_absolute() and not clean.startswith(("/", "\\")):
        if clean.startswith("database/evidence/"):
            return clean[len("database/evidence/"):]
        if clean.startswith("evidence/"):
            return clean[len("evidence/"):]
        return clean

    parts = p.parts
    if parent_folder and parent_folder in parts:
        idx = parts.index(parent_folder)
        return "/".join(parts[idx:])

    for marker in ("database/evidence", "evidence", "source_evidence"):
        marker_parts = tuple(marker.split("/"))
        for i in range(len(parts) - len(marker_parts) + 1):
            if tuple(p_part.lower() for p_part in parts[i : i + len(marker_parts)]) == tuple(m.lower() for m in marker_parts):
                return "/".join(parts[i + len(marker_parts) :])

    if len(parts) >= 2:
        return f"{parts[-2]}/{parts[-1]}"
    return parts[-1]


def normalize_source_relative_path(path_str: str) -> str:
    """
    Normalizes a source relative path according to Identity V2 requirements:
    1. Reject empty or whitespace-only paths.
    2. Reject absolute paths (POSIX leading slash or Windows backslash).
    3. Reject Windows drive-letter paths (e.g. C:/).
    4. Normalize Unicode using NFC.
    5. Normalize path separators to forward slash ('/').
    6. Reject traversal components ('..').
    7. Strip leading and trailing slashes and collapse consecutive slashes.
    8. Apply lowercase normalization consistent with Windows filesystem semantics.
    """
    if not path_str or not isinstance(path_str, str) or not path_str.strip():
        raise MigrationIntegrityError("Source relative path cannot be empty or whitespace.")

    clean_raw = path_str.strip()

    # Reject absolute paths
    if os.path.isabs(clean_raw) or clean_raw.startswith(("/", "\\")):
        raise MigrationIntegrityError(f"Absolute paths are strictly rejected in manifest identity: '{path_str}'")

    # Reject drive-letter paths (Windows C:)
    if len(clean_raw) >= 2 and clean_raw[1] == ":" and clean_raw[0].isalpha():
        raise MigrationIntegrityError(f"Drive-letter paths are strictly rejected in manifest identity: '{path_str}'")

    # Unicode NFC normalization
    nfc_str = unicodedata.normalize("NFC", clean_raw)

    # Normalize path separators
    normalized_sep = nfc_str.replace("\\", "/")

    # Split segments, inspect traversal and empty components
    parts = normalized_sep.split("/")
    cleaned_parts: List[str] = []
    for part in parts:
        part_trimmed = part.strip()
        if not part_trimmed or part_trimmed == ".":
            continue
        if part_trimmed == "..":
            raise MigrationIntegrityError(f"Path traversal ('..') is strictly rejected in manifest identity: '{path_str}'")
        cleaned_parts.append(part_trimmed)

    if not cleaned_parts:
        raise MigrationIntegrityError(f"Source relative path resolves to empty path: '{path_str}'")

    # Join with forward slash and apply Windows-consistent case normalization
    canonical_path = "/".join(cleaned_parts).lower()
    return canonical_path


def validate_canonical_artifact_id(artifact_id: str) -> str:
    """
    Validates and canonicalizes artifact identifier:
    - Must be non-empty string without whitespace.
    - Rejects path separators ('/', '\\') and traversal ('..').
    - Applies Unicode NFC normalization.
    """
    if not artifact_id or not isinstance(artifact_id, str) or not artifact_id.strip():
        raise MigrationIntegrityError("Artifact identifier cannot be empty or whitespace.")

    clean_id = unicodedata.normalize("NFC", artifact_id.strip())
    if any(sep in clean_id for sep in ("/", "\\")) or ".." in clean_id:
        raise MigrationIntegrityError(f"Invalid artifact identifier with path separators or traversal: '{artifact_id}'")

    return clean_id


def generate_manifest_record_id_v2(
    source_relative_path: str,
    artifact_id: Optional[str] = None,
    source_namespace: str = DEFAULT_SOURCE_NAMESPACE,
) -> str:
    """
    Generate stable Identity V2 manifest_record_id.
    manifest_record_id = SHA256(canonical deterministic serialization of identity fields)

    Canonical identity fields:
    - identity_version = 2
    - source_namespace = "alltools-cybersec-legacy-evidence"
    - normalized source_relative_path
    - canonical artifact_id derived from filename (or provided)

    Output:
    - Full 64-character lowercase hexadecimal SHA-256 digest.
    - Deterministic key ordering (sorted JSON keys).
    - Deterministic UTF-8 encoding.
    """
    norm_path = normalize_source_relative_path(source_relative_path)

    if artifact_id is None or not str(artifact_id).strip():
        filename = norm_path.split("/")[-1]
        derived_id = Path(filename).stem
        can_art_id = validate_canonical_artifact_id(derived_id)
    else:
        can_art_id = validate_canonical_artifact_id(artifact_id)

    identity_dict = {
        "artifact_id": can_art_id,
        "identity_version": DEFAULT_IDENTITY_VERSION,
        "source_namespace": source_namespace,
        "source_relative_path": norm_path,
    }

    # Deterministic canonical serialization (sorted keys, compact separators)
    canonical_bytes = json.dumps(identity_dict, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(canonical_bytes).hexdigest()


def generate_manifest_record_id_v1(operation_id: str, artifact_id: str, physical_sha256: str) -> str:
    """Legacy Identity V1 generator (truncated hash prefixed with man-{artifact_id}-)."""
    raw_key = f"{operation_id}:{artifact_id}:{physical_sha256}"
    digest = hashlib.sha256(raw_key.encode("utf-8")).hexdigest()[:16]
    return f"man-{artifact_id}-{digest}"


def generate_manifest_record_id(*args: Any, **kwargs: Any) -> str:
    """
    Dispatches to Identity V2 generator by default.
    Supports legacy 3-argument positional V1 signature for backward compatibility:
    generate_manifest_record_id(operation_id, artifact_id, physical_sha256)
    """
    if len(args) == 3 and isinstance(args[0], str) and isinstance(args[1], str) and isinstance(args[2], str):
        # Legacy V1 signature: (operation_id, artifact_id, physical_sha256)
        if args[0].startswith("OP-") or len(args[2]) == 64 or "sha" in args[2]:
            return generate_manifest_record_id_v1(args[0], args[1], args[2])
    if len(args) >= 1:
        source_rel = args[0]
        art_id = args[1] if len(args) > 1 else kwargs.get("artifact_id")
        src_ns = args[2] if len(args) > 2 else kwargs.get("source_namespace", DEFAULT_SOURCE_NAMESPACE)
        return generate_manifest_record_id_v2(source_rel, art_id, src_ns)
    if "source_relative_path" in kwargs:
        return generate_manifest_record_id_v2(
            source_relative_path=kwargs["source_relative_path"],
            artifact_id=kwargs.get("artifact_id"),
            source_namespace=kwargs.get("source_namespace", DEFAULT_SOURCE_NAMESPACE),
        )
    if "operation_id" in kwargs and "artifact_id" in kwargs and "physical_sha256" in kwargs:
        return generate_manifest_record_id_v1(kwargs["operation_id"], kwargs["artifact_id"], kwargs["physical_sha256"])
    raise ValueError("Invalid arguments for generate_manifest_record_id.")


class MigrationState(str, Enum):
    """Approved states for evidence migration state machine."""
    DISCOVERED = "DISCOVERED"
    VALIDATED = "VALIDATED"
    STAGED = "STAGED"
    VERIFIED = "VERIFIED"
    PROMOTION_INTENT_RECORDED = "PROMOTION_INTENT_RECORDED"
    PROMOTED = "PROMOTED"
    COMMITTED = "COMMITTED"
    
    # Terminal / Failure / Blocked states
    BLOCKED_COLLISION = "BLOCKED_COLLISION"
    BLOCKED_MISSING_PARENT = "BLOCKED_MISSING_PARENT"
    FAILED_INTEGRITY = "FAILED_INTEGRITY"
    FAILED_IO = "FAILED_IO"


class MigrationJournalEntry(BaseModel):
    """Represents a durable record in the SQLite migration_journal table."""
    id: Optional[int] = Field(None, description="Auto-incremented primary key")
    operation_id: str = Field(..., description="Batch or execution run identifier")
    artifact_id: str = Field(..., description="Canonical evidence artifact ID")
    parent_folder: str = Field(..., description="Source subfolder (e.g. ASM-01, ASM-001)")
    source_path: str = Field(..., description="Relative source path")
    staged_path: str = Field(..., description="Path to temporary staged file")
    target_path: str = Field(..., description="Final published destination path")
    sha256: str = Field(..., description="Expected/verified SHA-256 digest")
    byte_size: int = Field(..., ge=0, description="Payload byte size")
    state: MigrationState = Field(..., description="Current migration state")
    sequence: int = Field(..., ge=1, description="Monotonic sequence number within operation")
    created_at: str = Field(..., description="ISO-8601 UTC creation timestamp")
    updated_at: str = Field(..., description="ISO-8601 UTC last state update timestamp")
    event_id: str = Field(..., description="Unique stable event identifier for JSONL delivery")
    jsonl_delivered_at: Optional[str] = Field(None, description="Timestamp of durable JSONL outbox flush")
    error_detail: Optional[str] = Field(None, description="Diagnostic error details if failed")


class ArchiveManifestEntry(BaseModel):
    """Represents an entry in the durable archive_manifest.jsonl audit artifact."""
    manifest_record_id: str = Field(..., description="Stable deterministic unique manifest record ID")
    identity_version: int = Field(DEFAULT_IDENTITY_VERSION, description="Identity specification version (1 or 2)")
    source_namespace: str = Field(DEFAULT_SOURCE_NAMESPACE, description="Namespace of source artifacts")
    operation_id: str = Field(..., description="Migration operation identifier")
    artifact_id: str = Field(..., description="Canonical evidence artifact ID")
    source_relative_path: str = Field(..., description="Original legacy source path relative to evidence root")
    destination_relative_path: str = Field(..., description="Final archive destination path relative to data dir")
    physical_sha256: str = Field(..., description="Verified physical SHA-256 digest")
    size_bytes: int = Field(..., ge=0, description="Physical file size in bytes")
    disposition: str = Field(..., description="Archive classification (HISTORICAL_ARCHIVE, LEGACY_TEST_ARCHIVE, MALFORMED_PRESERVE)")
    committed_timestamp: str = Field(..., description="ISO-8601 UTC timestamp of durable commit")
    provenance: Dict[str, Any] = Field(default_factory=dict, description="Metadata preserving historical provenance")

    # Compatibility aliases and secondary fields
    source_path: Optional[str] = Field(None, description="Legacy source path alias")
    target_path: Optional[str] = Field(None, description="Legacy target path alias")
    sha256: Optional[str] = Field(None, description="Legacy sha256 alias")
    byte_size: Optional[int] = Field(None, description="Legacy byte_size alias")
    filename: Optional[str] = Field(None, description="Filename representation")
    classification: Optional[str] = Field(None, description="Legacy classification alias")
    migrated_at: Optional[str] = Field(None, description="Legacy migrated_at alias")

    @model_validator(mode="before")
    @classmethod
    def populate_aliases_and_defaults(cls, data: Any) -> Any:
        if isinstance(data, dict):
            # If legacy fields present, map to canonical fields
            if "source_relative_path" not in data and "source_path" in data:
                data["source_relative_path"] = data["source_path"]
            if "destination_relative_path" not in data and "target_path" in data:
                data["destination_relative_path"] = data["target_path"]
            if "physical_sha256" not in data and "sha256" in data:
                data["physical_sha256"] = data["sha256"]
            if "size_bytes" not in data and "byte_size" in data:
                data["size_bytes"] = data["byte_size"]
            if "disposition" not in data and "classification" in data:
                data["disposition"] = data["classification"]
            if "committed_timestamp" not in data and "migrated_at" in data:
                data["committed_timestamp"] = data["migrated_at"]
            if "artifact_id" not in data:
                src = data.get("source_relative_path") or data.get("source_path") or "artifact"
                data["artifact_id"] = Path(src).stem

            # Explicit identity versioning
            rec_id = data.get("manifest_record_id")
            if rec_id:
                if "identity_version" not in data:
                    if str(rec_id).startswith("man-") and len(str(rec_id)) != 64:
                        data["identity_version"] = 1
                    else:
                        data["identity_version"] = 2
            else:
                data["identity_version"] = 2
                src_rel = data.get("source_relative_path") or data.get("source_path") or "artifact.json"
                art_id = data.get("artifact_id")
                data["manifest_record_id"] = generate_manifest_record_id_v2(
                    source_relative_path=src_rel,
                    artifact_id=art_id,
                )

            data.setdefault("source_namespace", DEFAULT_SOURCE_NAMESPACE)

            # Ensure aliases are populated as well
            data.setdefault("source_path", data.get("source_relative_path"))
            data.setdefault("target_path", data.get("destination_relative_path"))
            data.setdefault("sha256", data.get("physical_sha256"))
            data.setdefault("byte_size", data.get("size_bytes"))
            data.setdefault("classification", data.get("disposition"))
            data.setdefault("migrated_at", data.get("committed_timestamp"))
            if "filename" not in data and "source_relative_path" in data:
                data["filename"] = Path(data["source_relative_path"]).name
        return data


class MigrationBatchPlan(BaseModel):
    """Specification of a migration batch."""
    operation_id: str
    batch_index: int
    target_category: str
    items: List[Dict[str, Any]]
    total_bytes: int


class MigrationBatchResult(BaseModel):
    """Outcome summary for a migration batch execution."""
    operation_id: str
    batch_index: int
    total_items: int
    succeeded_items: int
    blocked_items: int
    failed_items: int
    total_bytes: int
    journal_entries: List[MigrationJournalEntry]
    is_fully_committed: bool
