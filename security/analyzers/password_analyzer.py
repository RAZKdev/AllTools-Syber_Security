import math
import re
from dataclasses import dataclass, field
from typing import List


@dataclass
class PasswordAuditResult:
    length: int
    entropy_bits: float
    strength: str  # VERY_WEAK, WEAK, FAIR, STRONG, VERY_STRONG
    has_uppercase: bool
    has_lowercase: bool
    has_digits: bool
    has_special: bool
    is_common_pattern: bool
    feedback: List[str] = field(default_factory=list)


class PasswordEntropyAnalyzer:
    """Evaluates password policy compliance and entropy according to NIST SP 800-63B."""

    COMMON_WEAK_PASSWORDS = {
        "password", "123456", "12345678", "admin", "admin123", "root",
        "qwerty", "letmein", "welcome", "password123", "iloveyou", "master"
    }

    def analyze(self, password: str) -> PasswordAuditResult:
        length = len(password)
        has_upper = bool(re.search(r"[A-Z]", password))
        has_lower = bool(re.search(r"[a-z]", password))
        has_digit = bool(re.search(r"[0-9]", password))
        has_special = bool(re.search(r"[^A-Za-z0-9]", password))

        pool_size = 0
        if has_upper:
            pool_size += 26
        if has_lower:
            pool_size += 26
        if has_digit:
            pool_size += 10
        if has_special:
            pool_size += 33

        entropy = length * math.log2(pool_size) if pool_size > 0 and length > 0 else 0.0

        is_common = password.lower().strip() in self.COMMON_WEAK_PASSWORDS
        feedback = []

        if length < 8:
            strength = "VERY_WEAK"
            feedback.append("Length is under 8 characters; highly vulnerable to brute-force.")
        elif is_common:
            strength = "VERY_WEAK"
            feedback.append("Password matches a known top common/breached dictionary word.")
        elif entropy < 36:
            strength = "WEAK"
            feedback.append("Low entropy (<36 bits). Easily cracked with modern GPU rigs.")
        elif entropy < 60:
            strength = "FAIR"
            feedback.append("Moderate entropy. Consider extending length to at least 14-16 characters.")
        elif entropy < 80:
            strength = "STRONG"
            feedback.append("Good entropy. Meets standard defense baseline.")
        else:
            strength = "VERY_STRONG"
            feedback.append("Excellent entropy (>=80 bits). Resistant to offline brute-force attacks.")

        if not has_upper:
            feedback.append("Missing uppercase characters.")
        if not has_lower:
            feedback.append("Missing lowercase characters.")
        if not has_digit:
            feedback.append("Missing numeric digits.")
        if not has_special:
            feedback.append("Missing special symbols.")

        return PasswordAuditResult(
            length=length,
            entropy_bits=round(entropy, 2),
            strength=strength,
            has_uppercase=has_upper,
            has_lowercase=has_lower,
            has_digits=has_digit,
            has_special=has_special,
            is_common_pattern=is_common,
            feedback=feedback,
        )
