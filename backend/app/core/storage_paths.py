import os
import sys
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Optional


class ConfigurationError(Exception):
    """Raised when application storage path configuration is invalid or inaccessible."""
    pass


@dataclass(frozen=True)
class StoragePaths:
    data_dir: Path
    database_file: Path
    evidence_dir: Path
    quarantine_dir: Path
    backups_dir: Path
    lock_file: Optional[Path] = None

    def __post_init__(self):
        if self.lock_file is None:
            object.__setattr__(self, "lock_file", self.data_dir / "workbench.lock")


def resolve_data_dir(env_override: Optional[str] = None) -> Path:
    """
    Resolve the canonical data directory for AllTools-CyberSec.
    Follows ADR-01 and ADR-04:
    - Evaluates ALLTOOLS_DATA_DIR environment variable (or env_override argument).
    - If defined, validates accessibility and fails closed on invalid/unwritable paths.
    - If undefined, defaults to %LOCALAPPDATA%\\AllTools-CyberSec on Windows
      or ${XDG_DATA_HOME:-~/.local/share}/AllTools-CyberSec on POSIX.
    """
    custom_dir = env_override if env_override is not None else os.environ.get("ALLTOOLS_DATA_DIR")

    if custom_dir:
        candidate = Path(custom_dir).expanduser()
        try:
            candidate = candidate.resolve()
            candidate.mkdir(parents=True, exist_ok=True)
            # Verify write permissions using a per-call probe file so concurrent
            # requests cannot collide on the same path.
            probe_file = candidate / f".probe_write_test_{os.getpid()}_{uuid.uuid4().hex}"
            try:
                probe_file.write_text("ok", encoding="utf-8")
            finally:
                probe_file.unlink(missing_ok=True)
            return candidate
        except Exception as e:
            raise ConfigurationError(
                f"Configured ALLTOOLS_DATA_DIR '{custom_dir}' is invalid or inaccessible: {str(e)}"
            ) from e

    # Default resolution based on OS platform
    if os.name == "nt":
        local_app_data = os.environ.get("LOCALAPPDATA")
        if local_app_data:
            base_dir = Path(local_app_data)
        else:
            base_dir = Path.home() / "AppData" / "Local"
        candidate = (base_dir / "AllTools-CyberSec").resolve()
    else:
        xdg_data = os.environ.get("XDG_DATA_HOME")
        if xdg_data:
            base_dir = Path(xdg_data)
        else:
            base_dir = Path.home() / ".local" / "share"
        candidate = (base_dir / "AllTools-CyberSec").resolve()

    try:
        candidate.mkdir(parents=True, exist_ok=True)
        return candidate
    except Exception as e:
        raise ConfigurationError(
            f"Failed to initialize default storage directory at '{candidate}': {str(e)}"
        ) from e


def get_default_data_dir(platform: Optional[str] = None) -> Path:
    """
    Return the canonical default data directory without creating it.

    The platform defaults match resolve_data_dir():
    - Windows: %LOCALAPPDATA%\\AllTools-CyberSec
    - POSIX: ${XDG_DATA_HOME:-~/.local/share}/AllTools-CyberSec
    """
    effective_platform = platform or os.name

    if effective_platform == "nt":
        local_app_data = os.environ.get("LOCALAPPDATA")
        base_dir = (
            Path(local_app_data)
            if local_app_data
            else Path.home() / "AppData" / "Local"
        )
        return (base_dir / "AllTools-CyberSec").resolve()

    xdg_data = os.environ.get("XDG_DATA_HOME")
    base_dir = Path(xdg_data) if xdg_data else Path.home() / ".local" / "share"
    return (base_dir / "AllTools-CyberSec").resolve()


def get_canonical_data_dir(
    env_override: Optional[str] = None,
    platform: Optional[str] = None,
) -> Path:
    """
    Resolve the configured production data directory without creating it.

    ALLTOOLS_DATA_DIR (or env_override) takes precedence on every platform,
    matching resolve_data_dir() semantics.
    """
    custom_dir = env_override if env_override is not None else os.environ.get("ALLTOOLS_DATA_DIR")
    if custom_dir:
        return Path(custom_dir).expanduser().resolve()
    return get_default_data_dir(platform=platform)


def get_production_data_dirs(
    env_override: Optional[str] = None,
    platform: Optional[str] = None,
) -> set[Path]:
    """
    Return every directory that must be treated as production storage.

    Both the platform default and the configured override are protected so an
    override cannot silently un-guard data left in the default location.
    """
    production_dirs = {get_default_data_dir(platform=platform)}
    custom_dir = env_override if env_override is not None else os.environ.get("ALLTOOLS_DATA_DIR")
    if custom_dir:
        production_dirs.add(Path(custom_dir).expanduser().resolve())
    return production_dirs


def is_production_data_dir(
    target: Path,
    env_override: Optional[str] = None,
    platform: Optional[str] = None,
) -> bool:
    """Return True if target is a production data directory or one of its descendants."""
    resolved_target = Path(target).expanduser().resolve()
    production_dirs = get_production_data_dirs(env_override=env_override, platform=platform)
    return any(
        resolved_target == production_dir or production_dir in resolved_target.parents
        for production_dir in production_dirs
    )


def get_storage_paths(custom_data_dir: Optional[Path] = None) -> StoragePaths:
    """Get the structured storage path configuration."""
    data_dir = custom_data_dir if custom_data_dir is not None else resolve_data_dir()
    return StoragePaths(
        data_dir=data_dir,
        database_file=data_dir / "workbench.db",
        evidence_dir=data_dir / "evidence",
        quarantine_dir=data_dir / "quarantine",
        backups_dir=data_dir / "backups",
        lock_file=data_dir / "workbench.lock",
    )


def ensure_storage_directories(paths: StoragePaths) -> None:
    """Create directory skeleton with appropriate access permissions."""
    paths.data_dir.mkdir(parents=True, exist_ok=True)
    paths.evidence_dir.mkdir(parents=True, exist_ok=True)
    paths.quarantine_dir.mkdir(parents=True, exist_ok=True)
    paths.backups_dir.mkdir(parents=True, exist_ok=True)

    # On POSIX systems, restrict directory permissions to user-only (0700)
    if os.name != "nt":
        for d in (paths.data_dir, paths.evidence_dir, paths.quarantine_dir, paths.backups_dir):
            try:
                os.chmod(d, 0o700)
            except Exception:
                pass
