import hashlib
import json
import os
import re
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from app.schemas.evidence import Evidence, EvidenceCreate, EvidenceType


class EvidenceStore:
    """
    Evidence store abstraction ensuring cryptographic integrity (SHA-256),
    local disk artifact persistence, safe storage paths, size limits,
    and automated redaction of sensitive credentials/tokens.
    """

    MAX_EVIDENCE_BYTES = 5 * 1024 * 1024  # 5 MB per artifact

    # Patterns for sensitive evidence redaction
    SENSITIVE_PATTERNS = [
        (re.compile(r'(?i)(bearer\s+)[A-Za-z0-9_\-\.]{20,}'), r'\1[REDACTED_TOKEN]'),
        (re.compile(r'(?i)(api[_\-]?key\s*[:=]\s*[\'"]?)[A-Za-z0-9_\-]{16,}([\'"]?)'), r'\1[REDACTED_KEY]\2'),
        (re.compile(r'(?i)(password\s*[:=]\s*[\'"]?)[^\'"\s]{6,}([\'"]?)'), r'\1[REDACTED_SECRET]\2'),
        (re.compile(r'(?i)(-----BEGIN [A-Z ]+PRIVATE KEY-----)[\s\S]*?(-----END [A-Z ]+PRIVATE KEY-----)'), r'\1\n[REDACTED_PRIVATE_KEY]\n\2'),
        (re.compile(r'(?i)(set-cookie\s*:\s*[^;\r\n]+session[a-z0-9_\-]*=)[^;\r\n]+'), r'\1[REDACTED_SESSION]'),
    ]

    def __init__(self, base_dir: Optional[Path] = None) -> None:
        default_dir = os.environ.get("EVIDENCE_STORAGE_DIR", "database/evidence")
        self.base_dir = Path(base_dir or default_dir)
        self._evidence_records: Dict[str, Evidence] = {}

    @classmethod
    def redact_text(cls, text: str) -> Tuple[str, bool]:
        """Redact sensitive patterns from text. Returns (redacted_text, was_redacted)."""
        modified = text
        was_redacted = False
        for pattern, replacement in cls.SENSITIVE_PATTERNS:
            new_text = pattern.sub(replacement, modified)
            if new_text != modified:
                was_redacted = True
                modified = new_text
        return modified, was_redacted

    @staticmethod
    def calculate_sha256(content: bytes) -> str:
        """Calculate SHA-256 digest of binary content."""
        return hashlib.sha256(content).hexdigest()

    def _get_safe_artifact_path(self, assessment_id: str, evidence_id: str) -> Path:
        """Construct sanitized path and prevent directory traversal."""
        safe_asm = re.sub(r"[^a-zA-Z0-9_\-]", "", assessment_id) or "default"
        safe_evd = re.sub(r"[^a-zA-Z0-9_\-]", "", evidence_id) or "artifact"
        resolved_base = self.base_dir.resolve()
        target_path = (self.base_dir / safe_asm / f"{safe_evd}.json").resolve()
        if not str(target_path).startswith(str(resolved_base)):
            raise ValueError(f"Path traversal detected: {target_path}")
        return target_path

    def record_evidence(
        self,
        assessment_id: str,
        evidence_type: EvidenceType,
        source: str,
        raw_content: Any,
        finding_id: Optional[str] = None,
        notes: Optional[str] = None,
    ) -> Evidence:
        """
        Record and persist evidence artifact to disk with SHA-256 checksum
        calculated directly from the retained bytes, with sensitive data redacted.
        """
        evidence_id = f"EVD-{uuid.uuid4().hex[:8]}"

        # Serialize if dictionary or object
        if isinstance(raw_content, (dict, list)):
            content_str = json.dumps(raw_content, indent=2, sort_keys=True)
        elif isinstance(raw_content, bytes):
            content_str = raw_content.decode("utf-8", errors="replace")
        else:
            content_str = str(raw_content)

        # Redact sensitive data
        clean_content, was_redacted = self.redact_text(content_str)

        # Enforce size limits
        content_bytes = clean_content.encode("utf-8")
        if len(content_bytes) > self.MAX_EVIDENCE_BYTES:
            clean_content = (
                clean_content[: self.MAX_EVIDENCE_BYTES]
                + "\n...[TRUNCATED: EXCEEDED_5MB_LIMIT]..."
            )
            content_bytes = clean_content.encode("utf-8")

        # Persist artifact to disk
        artifact_path_str: Optional[str] = None
        try:
            target_file = self._get_safe_artifact_path(assessment_id, evidence_id)
            target_file.parent.mkdir(parents=True, exist_ok=True)
            with open(target_file, "wb") as f:
                f.write(content_bytes)
            # Store normalized relative path
            safe_asm = re.sub(r"[^a-zA-Z0-9_\-]", "", assessment_id) or "default"
            safe_evd = re.sub(r"[^a-zA-Z0-9_\-]", "", evidence_id) or "artifact"
            artifact_path_str = str(target_file.relative_to(self.base_dir.parent)).replace("\\", "/") if self.base_dir.parent != self.base_dir else str(target_file).replace("\\", "/")
        except Exception as e:
            # Fallback to in-memory metadata if filesystem error
            artifact_path_str = None

        # Calculate digest from the exact retained artifact bytes
        sha256_digest = self.calculate_sha256(content_bytes)

        evidence = Evidence(
            id=evidence_id,
            assessmentId=assessment_id,
            findingId=finding_id,
            type=evidence_type,
            source=source,
            artifactPath=artifact_path_str,
            capturedAt=datetime.now(timezone.utc),
            sha256=sha256_digest,
            redacted=was_redacted,
            notes=notes or f"Evidence recorded for {source}",
        )
        self._evidence_records[evidence_id] = evidence
        return evidence

    def get_evidence(self, evidence_id: str) -> Optional[Evidence]:
        return self._evidence_records.get(evidence_id)

    def verify_evidence_integrity(self, evidence_id: str) -> bool:
        """Verify that the stored disk artifact matches the recorded SHA-256 digest."""
        ev = self.get_evidence(evidence_id)
        if not ev or not ev.artifactPath:
            return False
        try:
            target_file = Path(ev.artifactPath)
            if not target_file.is_file():
                # Try relative to base_dir
                target_file = self.base_dir / ev.assessmentId / f"{ev.id}.json"
            if not target_file.is_file():
                return False
            data = target_file.read_bytes()
            return self.calculate_sha256(data) == ev.sha256
        except Exception:
            return False

    def list_evidence_for_assessment(self, assessment_id: str) -> List[Evidence]:
        return [e for e in self._evidence_records.values() if e.assessmentId == assessment_id]

    def list_evidence_for_finding(self, finding_id: str) -> List[Evidence]:
        return [e for e in self._evidence_records.values() if e.findingId == finding_id]

    def purge_evidence_for_assessment(self, assessment_id: str) -> int:
        """Purge all evidence files and records for an assessment."""
        removed_count = 0
        to_delete = [
            eid for eid, ev in self._evidence_records.items() if ev.assessmentId == assessment_id
        ]
        for eid in to_delete:
            del self._evidence_records[eid]
            removed_count += 1
        safe_asm = re.sub(r"[^a-zA-Z0-9_\-]", "", assessment_id)
        if safe_asm:
            target_dir = self.base_dir / safe_asm
            if target_dir.is_dir():
                for f in target_dir.glob("*.json"):
                    try:
                        f.unlink()
                    except Exception:
                        pass
                try:
                    target_dir.rmdir()
                except Exception:
                    pass
        return removed_count


evidence_store = EvidenceStore()
