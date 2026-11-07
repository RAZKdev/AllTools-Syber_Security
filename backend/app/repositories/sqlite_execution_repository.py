import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional, Tuple, Union

from app.core.database import get_db_connection, transaction
from app.repositories.interfaces import IExecutionRepository
from app.schemas.check_execution import CheckExecution
from app.schemas.common import (
    ExecutionStatus,
    ScopeDecision,
    TERMINAL_EXECUTION_STATUSES,
)

TERMINAL_STATUS_VALUES = {s.value for s in TERMINAL_EXECUTION_STATUSES}


class SqliteExecutionRepository(IExecutionRepository):
    """
    SQLite-backed repository for Check Execution records.
    Implements durable write-ahead execution lifecycle, idempotent re-recordings,
    and strict terminal-state immutability.
    """

    def __init__(self, db_path: Optional[Union[str, Path]] = None) -> None:
        self.db_path = db_path

    @staticmethod
    def _row_to_execution(row: sqlite3.Row) -> CheckExecution:
        return CheckExecution(
            id=row["id"],
            assessmentId=row["assessment_id"],
            ruleId=row["rule_id"],
            target=row["target"],
            scopeDecision=ScopeDecision(row["scope_decision"]),
            status=ExecutionStatus(row["status"]),
            ruleVersion=row["rule_version"],
            durationMs=row["duration_ms"],
            errorCode=row["error_code"],
            errorMessage=row["error_message"],
            requestFingerprint=row["request_fingerprint"] if "request_fingerprint" in row.keys() else None,
            executedAt=datetime.fromisoformat(row["executed_at"]) if row["executed_at"] else datetime.now(timezone.utc),
        )

    def reserve_execution(self, data: CheckExecution) -> Tuple[CheckExecution, bool]:
        """
        Atomically reserve check execution in PENDING state using an immediate SQLite write transaction.
        Enforces that concurrent requests with identical execution ID / idempotency key cannot both claim reservation.
        Returns (execution_record, is_newly_reserved).
        - If new: inserts record with status PENDING and returns (inserted_record, True).
        - If existing and matching request fingerprint: returns (existing_record, False).
        - If existing and divergent request fingerprint: raises ValueError for 409 Conflict.
        """
        executed_at = data.executedAt.isoformat() if data.executedAt else datetime.now(timezone.utc).isoformat()
        scope_val = data.scopeDecision.value if hasattr(data.scopeDecision, "value") else str(data.scopeDecision)
        status_val = data.status.value if hasattr(data.status, "value") else str(data.status)

        with transaction(self.db_path) as conn:
            # Foreign key check: assessment must exist
            asm_row = conn.execute(
                "SELECT id FROM assessments WHERE id = ?;",
                (data.assessmentId,),
            ).fetchone()
            if not asm_row:
                raise ValueError(
                    f"Referenced assessment '{data.assessmentId}' does not exist."
                )

            existing = conn.execute(
                "SELECT * FROM check_executions WHERE id = ?;",
                (data.id,),
            ).fetchone()

            if existing:
                existing_fingerprint = existing["request_fingerprint"] if "request_fingerprint" in existing.keys() else None
                # Conflict detection: same ID but different request parameters
                if existing_fingerprint and data.requestFingerprint:
                    if existing_fingerprint != data.requestFingerprint:
                        raise ValueError(
                            f"Conflicting request: Execution '{data.id}' already exists with different request parameters."
                        )
                return self._row_to_execution(existing), False

            # Atomically insert reservation in PENDING state
            conn.execute(
                """
                INSERT INTO check_executions (
                    id, assessment_id, rule_id, target, scope_decision,
                    status, rule_version, duration_ms, error_code, error_message,
                    request_fingerprint, executed_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
                """,
                (
                    data.id,
                    data.assessmentId,
                    data.ruleId,
                    data.target,
                    scope_val,
                    status_val,
                    data.ruleVersion,
                    data.durationMs,
                    data.errorCode,
                    data.errorMessage,
                    data.requestFingerprint,
                    executed_at,
                ),
            )
            inserted = conn.execute("SELECT * FROM check_executions WHERE id = ?;", (data.id,)).fetchone()
            return self._row_to_execution(inserted), True

    def record_execution(self, data: CheckExecution) -> CheckExecution:
        """
        Durable execution recording with idempotency, conflict detection, and immutability:
        - If new: inserts record with foreign key check on assessments.
        - If existing and identical request fingerprint: returns existing record (or updates in-flight state).
        - If existing and conflicting fingerprint: raises ValueError for 409 Conflict.
        - If existing and in terminal state: refuses modifications (immutable terminal record).
        """
        executed_at = data.executedAt.isoformat() if data.executedAt else datetime.now(timezone.utc).isoformat()
        scope_val = data.scopeDecision.value if hasattr(data.scopeDecision, "value") else str(data.scopeDecision)
        status_val = data.status.value if hasattr(data.status, "value") else str(data.status)

        with transaction(self.db_path) as conn:
            # Foreign key check: assessment must exist
            asm_row = conn.execute(
                "SELECT id FROM assessments WHERE id = ?;",
                (data.assessmentId,),
            ).fetchone()
            if not asm_row:
                raise ValueError(
                    f"Referenced assessment '{data.assessmentId}' does not exist."
                )

            # Query existing record
            existing = conn.execute(
                "SELECT * FROM check_executions WHERE id = ?;",
                (data.id,),
            ).fetchone()

            if existing:
                existing_fingerprint = existing["request_fingerprint"] if "request_fingerprint" in existing.keys() else None
                existing_status = existing["status"]

                # Conflict detection: same ID but different request parameters
                if existing_fingerprint and data.requestFingerprint:
                    if existing_fingerprint != data.requestFingerprint:
                        raise ValueError(
                            f"Conflicting request: Execution '{data.id}' already exists with different request parameters."
                        )

                # Terminal state immutability: completed records cannot be overwritten
                if existing_status in TERMINAL_STATUS_VALUES:
                    if status_val != existing_status:
                        raise ValueError(
                            f"Execution record '{data.id}' is in terminal state '{existing_status}' and is immutable."
                        )
                    # Replay of existing terminal record with matching fingerprint
                    return self._row_to_execution(existing)

                # Valid transition from non-terminal state (PENDING -> RUNNING -> terminal)
                conn.execute(
                    """
                    UPDATE check_executions
                    SET status = ?,
                        rule_version = ?,
                        duration_ms = ?,
                        error_code = ?,
                        error_message = ?,
                        request_fingerprint = COALESCE(?, request_fingerprint),
                        executed_at = ?
                    WHERE id = ?;
                    """,
                    (
                        status_val,
                        data.ruleVersion,
                        data.durationMs,
                        data.errorCode,
                        data.errorMessage,
                        data.requestFingerprint,
                        executed_at,
                        data.id,
                    ),
                )
            else:
                # Fresh insert
                conn.execute(
                    """
                    INSERT INTO check_executions (
                        id, assessment_id, rule_id, target, scope_decision,
                        status, rule_version, duration_ms, error_code, error_message,
                        request_fingerprint, executed_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
                    """,
                    (
                        data.id,
                        data.assessmentId,
                        data.ruleId,
                        data.target,
                        scope_val,
                        status_val,
                        data.ruleVersion,
                        data.durationMs,
                        data.errorCode,
                        data.errorMessage,
                        data.requestFingerprint,
                        executed_at,
                    ),
                )

        ret = self.get_execution(data.id)
        if not ret:
            raise RuntimeError(f"Failed to retrieve recorded execution '{data.id}'")
        return ret

    def reconcile_stale_executions(self) -> int:
        """
        On startup, detect in-flight executions left in non-terminal states
        (PENDING or RUNNING) due to unexpected process shutdown.
        Reconciles them to INTERRUPTED state without falsely claiming PASS or FAIL.
        Returns the count of reconciled records.
        """
        with transaction(self.db_path) as conn:
            cursor = conn.execute(
                """
                UPDATE check_executions
                SET status = 'INTERRUPTED',
                    error_code = 'SYSTEM_INTERRUPTED',
                    error_message = 'Process terminated or restarted while execution was in-flight; reconciled on restart without falsified outcome.'
                WHERE status IN ('PENDING', 'RUNNING');
                """
            )
            return cursor.rowcount

    def get_execution(self, execution_id: str) -> Optional[CheckExecution]:
        with get_db_connection(self.db_path) as conn:
            row = conn.execute(
                "SELECT * FROM check_executions WHERE id = ?;",
                (execution_id,),
            ).fetchone()
            if not row:
                return None
            return self._row_to_execution(row)

    def list_executions(self, assessment_id: Optional[str] = None) -> List[CheckExecution]:
        with get_db_connection(self.db_path) as conn:
            if assessment_id:
                rows = conn.execute(
                    """
                    SELECT * FROM check_executions
                    WHERE assessment_id = ?
                    ORDER BY executed_at DESC;
                    """,
                    (assessment_id,),
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT * FROM check_executions ORDER BY executed_at DESC;"
                ).fetchall()
            return [self._row_to_execution(r) for r in rows]
