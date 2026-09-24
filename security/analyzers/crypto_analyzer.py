import re
from dataclasses import dataclass
from typing import Any, Dict, List, Optional


@dataclass
class HashAnalysis:
    input_str: str
    detected_algorithm: str
    bit_length: int
    security_status: str  # INSECURE, DEPRECATED, SECURE
    is_salted_or_kdf: bool
    description: str
    cwe: Optional[str]
    recommendation: str


class CryptoHashAnalyzer:
    """Evaluates cryptographic hash algorithm resistance against modern collision attacks."""

    PATTERNS = [
        # Argon2: $argon2id$v=19$m=... or $argon2i$
        (r"^\$argon2(id|i|d)\$v=\d+\$m=\d+,t=\d+,p=\d+\$[A-Za-z0-9+/=]+\$[A-Za-z0-9+/=]+$", "Argon2", 0, "SECURE", True, "Modern memory-hard password hashing function.", None, "Meets current NIST & OWASP password storage standards."),
        # Bcrypt: $2a$, $2b$, $2y$
        (r"^\$2[abxy]\$\d{2}\$[A-Za-z0-9./]{53}$", "bcrypt", 0, "SECURE", True, "Adaptive cryptographic password hash.", None, "Strong, recommended for password hashing."),
        # PBKDF2: $pbkdf2-sha256$ or similar common formats
        (r"^\$pbkdf2(-sha256|-sha512)?\$\d+\$[A-Za-z0-9+/=]+\$[A-Za-z0-9+/=]+$", "PBKDF2", 0, "SECURE", True, "Key derivation function with iteration count.", None, "Acceptable when iteration count is >= 600,000 for SHA-256."),
        # Hex 128 chars = SHA-512
        (r"^[0-9a-fA-F]{128}$", "SHA-512", 512, "SECURE", False, "Secure cryptographic hash function.", None, "Approved for digital signatures and data integrity."),
        # Hex 64 chars = SHA-256
        (r"^[0-9a-fA-F]{64}$", "SHA-256", 256, "SECURE", False, "Standard cryptographic hash function.", None, "Approved for general cryptographic integrity."),
        # Hex 40 chars = SHA-1
        (r"^[0-9a-fA-F]{40}$", "SHA-1", 160, "DEPRECATED", False, "Broken hash function vulnerable to collision attacks (SHAttered).", "CWE-328", "Migrate to SHA-256 or SHA-512 immediately."),
        # Hex 32 chars = MD5
        (r"^[0-9a-fA-F]{32}$", "MD5", 128, "INSECURE", False, "Cryptographically broken algorithm with trivial practical collisions.", "CWE-327", "Never use MD5 for security, signatures, or password storage."),
        # Hex 8 chars = CRC32
        (r"^[0-9a-fA-F]{8}$", "CRC32", 32, "INSECURE", False, "Non-cryptographic error-detection checksum only.", "CWE-328", "Do not use for security purposes."),
    ]

    def analyze(self, hash_string: str) -> HashAnalysis:
        cleaned = hash_string.strip()
        for pattern, algo, bits, status, is_kdf, desc, cwe, rec in self.PATTERNS:
            if re.match(pattern, cleaned):
                return HashAnalysis(
                    input_str=cleaned,
                    detected_algorithm=algo,
                    bit_length=bits,
                    security_status=status,
                    is_salted_or_kdf=is_kdf,
                    description=desc,
                    cwe=cwe,
                    recommendation=rec,
                )

        return HashAnalysis(
            input_str=cleaned,
            detected_algorithm="Unknown",
            bit_length=len(cleaned) * 4 if re.match(r"^[0-9a-fA-F]+$", cleaned) else 0,
            security_status="WARN",
            is_salted_or_kdf=False,
            description="Unrecognized hash or signature format.",
            cwe="CWE-326",
            recommendation="Verify the cryptographic algorithm and ensure it uses at least 256-bit modern standards.",
        )
