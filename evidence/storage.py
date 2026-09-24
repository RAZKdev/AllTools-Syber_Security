import hashlib
import json
import re
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from app.schemas.evidence import Evidence, EvidenceCreate, EvidenceType


class EvidenceStore:
    """
    Evidence store abstraction ensuring cryptographic integrity (SHA-256)
    and automated redaction of sensitive credentials/tokens.
    """

    # Patterns for sensitive evidence redaction
    SENSITIVE_PATTERNS = [
        (re.compile(r'(?i)(bearer\s+)[A-Za-z0-9_\-\.]{20,}'), r'\1[REDACTED_TOKEN]'),
        (re.compile(r'(?i)(api[_\-]?key\s*[:=]\s*[\'"]?)[A-Za-z0-9_\-]{16,}([\'"]?)'), r'\1[REDACTED_KEY]\2'),
        (re.compile(r'(?i)(password\s*[:=]\s*[\'"]?)[^\'"\s]{6,}([\'"]?)'), r'\1[REDACTED_SECRET]\2'),
        (re.compile(r'(?i)(-----BEGIN [A-Z ]+PRIVATE KEY-----)[\s\S]*?(-----END [A-Z ]+PRIVATE KEY-----)'), r'\1\n[REDACTED_PRIVATE_KEY]\n\2'),
        (re.compile(r'(?i)(set-cookie\s*:\s*[^;\r\n]+session[a-z0-9_\-]*=)[^;\r\n]+'), r'\1[REDACTED_SESSION]'),
    ]

    def __init__(self, base_dir: Optional[Path] = None) -> None:
        self.base_dir = base_dir
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
        Record and store evidence with SHA-256 checksum and redacting if needed.
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
        sha256_digest = self.calculate_sha256(clean_content.encode("utf-8"))

        evidence = Evidence(
            id=evidence_id,
            assessmentId=assessment_id,
            findingId=finding_id,
            type=evidence_type,
            source=source,
            artifactPath=None,
            capturedAt=datetime.now(timezone.utc),
            sha256=sha256_digest,
            redacted=was_redacted,
            notes=notes or f"Evidence recorded for {source}",
        )
        self._evidence_records[evidence_id] = evidence
        return evidence

    def get_evidence(self, evidence_id: str) -> Optional[Evidence]:
        return self._evidence_records.get(evidence_id)

    def list_evidence_for_assessment(self, assessment_id: str) -> List[Evidence]:
        return [e for e in self._evidence_records.values() if e.assessmentId == assessment_id]

    def list_evidence_for_finding(self, finding_id: str) -> List[Evidence]:
        return [e for e in self._evidence_records.values() if e.findingId == finding_id]


evidence_store = EvidenceStore()
