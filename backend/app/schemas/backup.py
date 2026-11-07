from datetime import datetime, timezone
from enum import Enum
from typing import List, Optional
from pydantic import BaseModel, Field


class BackupStatus(str, Enum):
    IN_PROGRESS = "IN_PROGRESS"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"


class BackupFileEntry(BaseModel):
    path: str = Field(..., min_length=1, description="Normalized relative path within backup directory")
    byteSize: int = Field(..., ge=0)
    sha256: str = Field(..., pattern=r"^[A-Fa-f0-9]{64}$")


class DatabaseIntegrityInfo(BaseModel):
    quickCheck: str
    pageCount: int
    dataVersion: int
    schemaVersion: int


class BackupManifest(BaseModel):
    generationId: str = Field(..., min_length=1)
    backupFormatVersion: str = Field(default="1.0")
    createdAt: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    schemaVersion: int = Field(..., ge=1)
    coordinationDurationMs: Optional[int] = None
    databaseIntegrity: DatabaseIntegrityInfo
    files: List[BackupFileEntry]
    totalBytes: int = Field(..., ge=0)
    manifestSha256: Optional[str] = None


class BackupSnapshot(BaseModel):
    id: str = Field(..., min_length=1)
    createdAt: datetime
    sqliteDataVersion: int
    evidenceCount: int = Field(..., ge=0)
    quarantineCount: int = Field(..., ge=0)
    manifestSha256: str
    byteSize: int = Field(..., ge=0)
    status: BackupStatus

    model_config = {"extra": "forbid"}
