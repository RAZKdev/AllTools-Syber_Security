"""
Administrative Evidence Migration CLI - Phase E3A.

Command-line entrypoint for evidence migration operations.
Enforces cross-process InstanceLock and strict fail-closed safety guards
against targeting production storage during Phase E3A.
"""

import argparse
import json
import sys
from pathlib import Path
from typing import Optional

# Add backend directory to sys.path
current_dir = Path(__file__).resolve().parent
backend_dir = current_dir.parent.parent
if str(backend_dir) not in sys.path:
    sys.path.insert(0, str(backend_dir))

from app.core.instance_lock import InstanceLock, MaintenanceSession, ProcessLockError
from app.core.storage_paths import (
    StoragePaths,
    get_canonical_data_dir,
    is_production_data_dir,
)
from app.services.migration_authorization import (
    ProductionMigrationAuthorization,
    load_ed25519_public_key,
)
from app.services.migration_engine import MigrationEngine
from app.services.migration_models import (
    MigrationBatchPlan,
    MigrationError,
    MigrationSafetyError,
)
from app.services.migration_recovery_service import MigrationRecoveryService


def get_default_paths():
    repo_root = backend_dir.parent
    source_dir = repo_root / "database" / "evidence"
    brain_dir = Path(r"C:\Users\Rangga\.gemini\antigravity\brain\72d04d7a-59e5-45ea-b077-8c9e8e67ef4e")
    inventory_file = brain_dir / "legacy-evidence-inventory.json"
    
    data_dir = get_canonical_data_dir()
    db_path = data_dir / "workbench.db"

    return repo_root, source_dir, inventory_file, data_dir, db_path


def main():
    parser = argparse.ArgumentParser(
        description="AllTools-CyberSec Phase E3A Evidence Migration Engine CLI."
    )
    repo_root, def_source, def_inv, def_data, def_db = get_default_paths()

    parser.add_argument(
        "--source-dir",
        type=Path,
        default=def_source,
        help="Path to legacy evidence source directory",
    )
    parser.add_argument(
        "--inventory-file",
        type=Path,
        default=def_inv,
        help="Path to baseline inventory JSON",
    )
    parser.add_argument(
        "--data-dir",
        type=Path,
        required=True,
        help="Target data directory (MANDATORY: Must be an isolated test sandbox in Phase E3A)",
    )
    parser.add_argument(
        "--db-path",
        type=Path,
        default=None,
        help="Target SQLite database path (defaults to data-dir / workbench.db)",
    )
    parser.add_argument(
        "--operation-id",
        type=str,
        default=None,
        help="Unique operation identifier",
    )
    parser.add_argument(
        "--recover",
        action="store_true",
        help="Run journal recovery on pending entries",
    )
    parser.add_argument(
        "--authorization-token-file",
        type=Path,
        default=None,
        help="Path to signed/authorized ProductionMigrationAuthorization JSON token",
    )
    parser.add_argument(
        "--authorization-public-key-file",
        type=Path,
        default=None,
        help="Path to the independently pinned Ed25519 public key (PEM, OpenSSH, or raw hex)",
    )

    args = parser.parse_args()

    auth_token: Optional[ProductionMigrationAuthorization] = None
    auth_public_key = None
    if args.authorization_token_file:
        if not args.authorization_token_file.exists():
            print(f"[FATAL ERROR] Authorization token file '{args.authorization_token_file}' not found.", file=sys.stderr)
            sys.exit(2)
        if not args.authorization_public_key_file:
            print(
                "[FATAL ERROR] --authorization-token-file requires --authorization-public-key-file. "
                "Unsigned or self-authored tokens are not accepted.",
                file=sys.stderr,
            )
            sys.exit(2)
        if not args.authorization_public_key_file.exists():
            print(
                f"[FATAL ERROR] Authorization public key file '{args.authorization_public_key_file}' not found.",
                file=sys.stderr,
            )
            sys.exit(2)
        try:
            token_data = json.loads(args.authorization_token_file.read_text(encoding="utf-8"))
            auth_token = ProductionMigrationAuthorization(**token_data)
            auth_public_key = load_ed25519_public_key(args.authorization_public_key_file)
        except Exception as e:
            print(f"[FATAL ERROR] Failed to parse authorization token or public key: {e}", file=sys.stderr)
            sys.exit(2)

    # P0 Safety Guard: Check if data-dir targets production
    resolved_target = args.data_dir.resolve()
    if is_production_data_dir(resolved_target):
        if not auth_token:
            print(
                f"[FATAL ERROR] Production data directory '{resolved_target}' cannot be targeted "
                "without a verified ProductionMigrationAuthorization token (--authorization-token-file) "
                "and pinned public key (--authorization-public-key-file).\n"
                "Direct physical production migration is disabled.",
                file=sys.stderr,
            )
            sys.exit(2)

    db_file = args.db_path or (args.data_dir / "workbench.db")
    paths = StoragePaths(
        data_dir=args.data_dir,
        database_file=db_file,
        evidence_dir=args.data_dir / "evidence",
        quarantine_dir=args.data_dir / "quarantine",
        backups_dir=args.data_dir / "backups",
        lock_file=args.data_dir / "workbench.lock",
    )

    # Acquire exclusive instance lock
    lock = InstanceLock(paths.lock_file)
    try:
        lock.acquire()
    except ProcessLockError as e:
        print(f"[FATAL] Lock acquisition failed: {e}", file=sys.stderr)
        sys.exit(3)

    session = MaintenanceSession(lock)
    try:
        engine = MigrationEngine(
            paths=paths,
            maintenance_session=session,
            authorization=auth_token,
            authorization_public_key=auth_public_key,
        )
        if args.recover:
            print(f"Running Journal Recovery on database at {paths.database_file}...")
            conn = engine.connect_database()
            try:
                rec_svc = MigrationRecoveryService(
                    conn=conn, outbox=engine.outbox, archive_mgr=engine.archive_mgr, maintenance_session=session
                )
                recovered = rec_svc.recover_all_pending(operation_id=args.operation_id)
                print(f"Recovery complete: {len(recovered)} entries reconciled.")
            finally:
                conn.close()
        else:
            print(f"Migration CLI initialized in isolated sandbox: {paths.data_dir}")
    finally:
        lock.release()

    sys.exit(0)


if __name__ == "__main__":
    main()
