"""
Evidence Migration Models - Phase E2 Read-Only Simulation.

Defines Pydantic data models for evidence migration discovery, validation,
path simulation, volume capacity analysis, and simulation results.
Strictly read-only; contains no mutation or execution logic.
"""

from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class PrimaryDisposition(str, Enum):
    ACTIVE_MIGRATION_CANDIDATE = "ACTIVE_MIGRATION_CANDIDATE"
    HISTORICAL_ARCHIVE = "HISTORICAL_ARCHIVE"
    LEGACY_TEST_ARCHIVE = "LEGACY_TEST_ARCHIVE"
    MALFORMED_PRESERVE = "MALFORMED_PRESERVE"


class SimulationDecision(str, Enum):
    WOULD_ARCHIVE = "WOULD_ARCHIVE"
    WOULD_PRESERVE_AS_TEST_ARCHIVE = "WOULD_PRESERVE_AS_TEST_ARCHIVE"
    BLOCKED_MISSING_PARENT = "BLOCKED_MISSING_PARENT"
    BLOCKED_SOURCE_INTEGRITY = "BLOCKED_SOURCE_INTEGRITY"
    BLOCKED_DESTINATION_COLLISION = "BLOCKED_DESTINATION_COLLISION"
    BLOCKED_SOURCE_UNSTABLE = "BLOCKED_SOURCE_UNSTABLE"
    BLOCKED_PATH_VALIDATION = "BLOCKED_PATH_VALIDATION"
    REQUIRES_OPERATOR_REVIEW = "REQUIRES_OPERATOR_REVIEW"


class DestinationStatus(str, Enum):
    DESTINATION_ABSENT = "DESTINATION_ABSENT"
    EXISTING_IDENTICAL_UNOWNED = "EXISTING_IDENTICAL_UNOWNED"
    EXISTING_DIFFERENT_HASH = "EXISTING_DIFFERENT_HASH"
    DESTINATION_PATH_CONFLICT = "DESTINATION_PATH_CONFLICT"
    DESTINATION_PATH_UNVERIFIABLE = "DESTINATION_PATH_UNVERIFIABLE"
    BLOCKED_BY_PARENT_PROVENANCE = "BLOCKED_BY_PARENT_PROVENANCE"


class CollisionStatus(str, Enum):
    NO_COLLISION = "NO_COLLISION"
    IDENTICAL_HASH_COLLISION = "IDENTICAL_HASH_COLLISION"
    HASH_MISMATCH_COLLISION = "HASH_MISMATCH_COLLISION"
    CASE_INSENSITIVE_COLLISION = "CASE_INSENSITIVE_COLLISION"


class ArtifactSimulationResult(BaseModel):
    """Artifact-level simulation evaluation for each legacy evidence file."""
    source_relative_path: str = Field(..., description="Relative path from legacy evidence root")
    source_size_bytes: int = Field(..., ge=0, description="Actual physical file size in bytes")
    source_sha256: str = Field(..., description="Actual computed SHA-256 of physical file")
    inventory_sha256: str = Field(..., description="Expected SHA-256 recorded in E0 baseline inventory")
    primary_disposition: str = Field(..., description="Baseline classification disposition")
    migration_status: str = Field(..., description="Baseline migration eligibility/block status")
    canonical_filename_id: Optional[str] = Field(None, description="Identifier derived from filename")
    embedded_legacy_id: Optional[str] = Field(None, description="Identifier extracted from JSON body if present")
    json_validation_result: str = Field(..., description="JSON schema / parse status")
    relational_validation_result: str = Field(..., description="Parent entity foreign key verification status")
    proposed_destination: str = Field(..., description="Simulated destination path in production storage")
    destination_status: str = Field(..., description="Destination presence status")
    collision_status: str = Field(..., description="Collision analysis category")
    source_stability: str = Field(..., description="Pre/post-hash mtime stability status")
    decision: str = Field(..., description="Simulation decision from allowed set")
    reason: str = Field(..., description="Explanatory justification for decision")
    id_discrepancy: bool = Field(False, description="Whether filename ID and internal ID diverge")
    mtime: Optional[str] = Field(None, description="Filesystem modification ISO timestamp")


class VolumeCapacityAnalysis(BaseModel):
    """Volume identity and disk space capacity analysis."""
    source_volume_drive: str
    source_volume_serial: Optional[str] = None
    dest_volume_drive: str
    dest_volume_serial: Optional[str] = None
    cross_volume: bool
    staging_volume_same_as_dest: bool
    dest_free_bytes: int
    dest_total_bytes: int
    total_source_bytes: int
    historical_archive_bytes: int
    legacy_test_archive_bytes: int
    malformed_bytes: int
    blocked_candidate_bytes: int
    estimated_archive_bytes: int
    estimated_staging_bytes: int
    required_safety_buffer_bytes: int
    capacity_sufficient: bool
    margin_ratio: float


class DatabaseValidationResult(BaseModel):
    """Read-only SQLite production database validation summary."""
    db_path: str
    db_size_bytes: int
    db_sha256: str
    user_version: int
    schema_version_count: int
    engagements_count: int
    assessments_count: int
    findings_count: int
    check_executions_count: int
    evidence_count: int
    quarantine_items_count: int
    migration_journal_exists: bool
    active_candidate_parents_exist: bool
    missing_parent_details: Dict[str, Any] = Field(default_factory=dict)


class SimulationSummaryReport(BaseModel):
    """Overall summary report of read-only evidence migration simulation."""
    simulation_timestamp: str
    source_root: str
    dest_data_dir: str
    inventory_file: str
    inventory_sha256: str
    total_artifacts: int
    disposition_counts: Dict[str, int]
    decision_counts: Dict[str, int]
    duplicate_content_groups: List[Dict[str, Any]]
    integrity_verified_count: int
    relational_blocked_count: int
    collisions_count: int
    volume_analysis: VolumeCapacityAnalysis
    database_validation: DatabaseValidationResult
    artifacts: List[ArtifactSimulationResult]
    overall_verdict: str
