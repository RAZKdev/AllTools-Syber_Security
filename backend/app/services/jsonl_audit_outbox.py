"""
JSONL Audit Outbox - Phase E3A.

Secondary append-only audit log for evidence migration events.
Implements idempotent at-least-once export, durable fsync before delivery
confirmation, duplicate event_id detection, and non-destructive malformed tail handling.
"""

import hashlib
import json
import logging
import os
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from app.services.migration_models import MigrationJournalEntry

logger = logging.getLogger(__name__)


class JSONLAuditOutbox:
    """
    Manages durable append-only export of migration journal events to JSONL.
    Guarantees:
    - Never silently truncates or rewrites existing bytes.
    - Preserves incomplete or malformed tails non-destructively.
    - Idempotent delivery based on stable event_id.
    - Explicit fsync before confirming delivery.
    """

    def __init__(self, outbox_path: Path) -> None:
        self.outbox_path = Path(outbox_path)
        self.outbox_path.parent.mkdir(parents=True, exist_ok=True)

    def scan_existing_events(self) -> Tuple[Set[str], Optional[Dict[str, Any]]]:
        """
        Scan existing JSONL file non-destructively.
        Returns:
            - Set of stable event_id values already present.
            - Malformed tail diagnostic dict if incomplete/malformed bytes exist at EOF, else None.
        """
        seen_event_ids: Set[str] = set()
        tail_diagnostic: Optional[Dict[str, Any]] = None

        if not self.outbox_path.exists():
            return seen_event_ids, None

        with open(self.outbox_path, "rb") as f:
            raw_data = f.read()

        if not raw_data:
            return seen_event_ids, None

        # Split on newline while preserving exact byte offsets
        lines = raw_data.split(b"\n")
        
        # Check if the file ends with a trailing newline
        ends_with_newline = raw_data.endswith(b"\n")
        
        # All elements except possibly the last if not ending with newline are complete lines
        complete_lines = lines[:-1] if not ends_with_newline else lines
        trailing_fragment = lines[-1] if not ends_with_newline else b""

        for idx, line_bytes in enumerate(complete_lines, 1):
            stripped = line_bytes.strip()
            if not stripped:
                continue
            try:
                rec = json.loads(stripped.decode("utf-8"))
                if isinstance(rec, dict) and "event_id" in rec:
                    seen_event_ids.add(rec["event_id"])
            except Exception as e:
                logger.warning("Invalid JSON at line %d in %s: %s", idx, self.outbox_path, e)

        # Inspect trailing fragment if file did not end with newline
        if trailing_fragment:
            stripped_frag = trailing_fragment.strip()
            is_valid_json = False
            try:
                rec = json.loads(stripped_frag.decode("utf-8"))
                if isinstance(rec, dict) and "event_id" in rec:
                    seen_event_ids.add(rec["event_id"])
                is_valid_json = True
            except Exception:
                pass

            tail_diagnostic = {
                "byte_offset": len(raw_data) - len(trailing_fragment),
                "length": len(trailing_fragment),
                "sha256": hashlib.sha256(trailing_fragment).hexdigest(),
                "is_valid_json_without_newline": is_valid_json,
                "raw_bytes_preview": str(trailing_fragment[:50]),
            }
            logger.info("Non-newline trailing bytes detected in %s: %s", self.outbox_path, tail_diagnostic)

        return seen_event_ids, tail_diagnostic

    def append_event(self, entry: MigrationJournalEntry) -> bool:
        """
        Append a migration journal entry to JSONL with durable fsync.
        If event_id is already present, does not re-append, but ensures log is synced.
        Returns True if appended, False if duplicate detected.
        """
        seen_events, tail_diag = self.scan_existing_events()
        
        if entry.event_id in seen_events:
            logger.info("Event %s already present in outbox %s; skipping duplicate append.", entry.event_id, self.outbox_path)
            # Ensure physical sync even on duplicate
            self.sync_existing_file()
            return False

        # Construct JSON event payload
        event_payload = {
            "event_id": entry.event_id,
            "operation_id": entry.operation_id,
            "artifact_id": entry.artifact_id,
            "sequence": entry.sequence,
            "state": entry.state.value,
            "source_path": entry.source_path,
            "target_path": entry.target_path,
            "sha256": entry.sha256,
            "byte_size": entry.byte_size,
            "created_at": entry.created_at,
            "updated_at": entry.updated_at,
            "payload_hash": hashlib.sha256(f"{entry.artifact_id}:{entry.sha256}:{entry.state.value}".encode()).hexdigest(),
        }
        if entry.error_detail:
            event_payload["error_detail"] = entry.error_detail

        json_bytes = (json.dumps(event_payload, separators=(",", ":")) + "\n").encode("utf-8")

        # Non-destructive handling: if trailing fragment existed without trailing newline,
        # prepend a newline so the existing fragment is preserved on its own line.
        prefix = b""
        if self.outbox_path.exists() and self.outbox_path.stat().st_size > 0:
            with open(self.outbox_path, "rb") as f:
                f.seek(max(0, self.outbox_path.stat().st_size - 1))
                last_char = f.read(1)
                if last_char != b"\n":
                    prefix = b"\n"

        with open(self.outbox_path, "ab") as f:
            if prefix:
                f.write(prefix)
            f.write(json_bytes)
            f.flush()
            os.fsync(f.fileno())

        return True

    def sync_existing_file(self) -> None:
        """Issue durable OS fsync on the outbox file if it exists."""
        if self.outbox_path.exists():
            with open(self.outbox_path, "a+b") as f:
                f.flush()
                os.fsync(f.fileno())
