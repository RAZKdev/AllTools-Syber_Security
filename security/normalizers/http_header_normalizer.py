from typing import Any, Dict


class HttpHeaderNormalizer:
    """Normalizes HTTP response headers for consistent rule evaluation."""

    @staticmethod
    def normalize(headers: Dict[str, Any]) -> Dict[str, str]:
        """Convert header keys to lowercase and strip values."""
        normalized: Dict[str, str] = {}
        for k, v in headers.items():
            if isinstance(v, (list, tuple)):
                clean_v = ", ".join(str(item).strip() for item in v)
            else:
                clean_v = str(v).strip()
            normalized[k.lower().strip()] = clean_v
        return normalized
