"""
Standalone CLI for Phase E2 Read-Only Evidence Migration Simulation.

Performs read-only simulation of legacy evidence migration against baseline
inventory and production SQLite database. Absolutely zero physical mutation
or migration execution capability.
"""

import argparse
import json
import os
import sys
from pathlib import Path

# Add backend directory to path if needed for local execution
current_dir = Path(__file__).resolve().parent
backend_dir = current_dir.parent.parent
if str(backend_dir) not in sys.path:
    sys.path.insert(0, str(backend_dir))

from app.services.evidence_migration_simulator import (
    EvidenceMigrationSimulator,
    SimulationSafetyError,
    validate_safe_output_dir,
)


def get_default_paths():
    repo_root = backend_dir.parent
    source_dir = repo_root / "database" / "evidence"
    
    # Brain artifact directory for baseline inventory
    brain_dir = Path(r"C:\Users\Rangga\.gemini\antigravity\brain\72d04d7a-59e5-45ea-b077-8c9e8e67ef4e")
    inventory_file = brain_dir / "legacy-evidence-inventory.json"
    
    # Default data dir
    local_app_data = os.environ.get("LOCALAPPDATA")
    if local_app_data:
        data_dir = Path(local_app_data) / "AllTools-CyberSec"
    else:
        data_dir = Path.home() / "AppData" / "Local" / "AllTools-CyberSec"
    db_path = data_dir / "workbench.db"

    return repo_root, source_dir, inventory_file, data_dir, db_path


def main():
    parser = argparse.ArgumentParser(
        description="AllTools-CyberSec Phase E2 Read-Only Evidence Migration Simulator."
    )
    repo_root, def_source, def_inv, def_data, def_db = get_default_paths()

    parser.add_argument(
        "--source-dir",
        type=Path,
        default=def_source,
        help="Path to legacy evidence source directory (default: %(default)s)",
    )
    parser.add_argument(
        "--inventory-file",
        type=Path,
        default=def_inv,
        help="Path to baseline inventory JSON (default: %(default)s)",
    )
    parser.add_argument(
        "--data-dir",
        type=Path,
        default=def_data,
        help="Path to runtime data directory (default: %(default)s)",
    )
    parser.add_argument(
        "--db-path",
        type=Path,
        default=def_db,
        help="Path to SQLite workbench database (default: %(default)s)",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=None,
        help="Optional safe output directory for simulation results (must be outside repo and data dirs)",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output raw JSON summary to stdout",
    )

    args = parser.parse_args()

    # Explicit guard: reject any dangerous flags if somehow passed
    for forbidden in ["--execute", "--confirm-execute", "--apply", "--migrate", "--force"]:
        if forbidden in sys.argv:
            print(f"ERROR: Forbidden execution flag '{forbidden}' detected. This simulator is strictly read-only.", file=sys.stderr)
            sys.exit(2)

    try:
        simulator = EvidenceMigrationSimulator(
            source_evidence_dir=args.source_dir,
            inventory_file=args.inventory_file,
            dest_data_dir=args.data_dir,
            db_path=args.db_path,
        )
    except Exception as e:
        print(f"ERROR initializing simulator: {e}", file=sys.stderr)
        sys.exit(1)

    print(f"Running Read-Only Migration Simulation...")
    print(f"  Source Evidence Root: {args.source_dir}")
    print(f"  Inventory File:       {args.inventory_file}")
    print(f"  Destination Data Dir: {args.data_dir}")
    print(f"  Production DB Path:   {args.db_path}")

    report = simulator.run_simulation()

    if args.output_dir:
        try:
            safe_out = validate_safe_output_dir(
                output_dir=args.output_dir,
                repo_root=repo_root,
                source_evidence_dir=args.source_dir,
                data_dir=args.data_dir,
                db_path=args.db_path,
            )
            safe_out.mkdir(parents=True, exist_ok=True)
            out_file = safe_out / "phase-e2-simulation-results.json"
            with open(out_file, "w", encoding="utf-8") as f:
                json.dump(report.model_dump(), f, indent=2)
            print(f"Wrote simulation results to: {out_file}")
        except SimulationSafetyError as se:
            print(f"SAFETY ERROR: {se}", file=sys.stderr)
            sys.exit(3)
        except Exception as e:
            print(f"ERROR writing simulation output: {e}", file=sys.stderr)
            sys.exit(1)

    if args.json:
        print(json.dumps(report.model_dump(), indent=2))
    else:
        print("\n==================================================")
        print("PHASE E2 SIMULATION RESULTS SUMMARY")
        print("==================================================")
        print(f"Overall Verdict:           {report.overall_verdict}")
        print(f"Total Artifacts Evaluated: {report.total_artifacts}")
        print(f"Integrity Verified:        {report.integrity_verified_count} / {report.total_artifacts}")
        print(f"Relational Blocked:        {report.relational_blocked_count}")
        print(f"Collisions Detected:       {report.collisions_count}")
        print("\nPrimary Dispositions:")
        for disp, count in report.disposition_counts.items():
            print(f"  - {disp}: {count}")
        print("\nSimulation Decisions:")
        for dec, count in report.decision_counts.items():
            print(f"  - {dec}: {count}")
        print("\nVolume & Capacity Analysis:")
        va = report.volume_analysis
        print(f"  - Source Volume:         {va.source_volume_drive} ({va.source_volume_serial})")
        print(f"  - Dest Volume:           {va.dest_volume_drive} ({va.dest_volume_serial})")
        print(f"  - Cross Volume:          {va.cross_volume}")
        print(f"  - Total Source Bytes:    {va.total_source_bytes:,} bytes")
        print(f"  - Dest Free Space:       {va.dest_free_bytes:,} bytes ({va.dest_free_bytes / (1024**3):.2f} GB)")
        print(f"  - Required Safety Buffer:{va.required_safety_buffer_bytes:,} bytes ({va.required_safety_buffer_bytes / (1024**2):.2f} MB)")
        print(f"  - Capacity Sufficient:   {va.capacity_sufficient} (Margin: {va.margin_ratio}x)")
        print("\nDatabase Validation:")
        dv = report.database_validation
        print(f"  - SQLite user_version:   {dv.user_version}")
        print(f"  - Active Candidate Valid:{dv.active_candidate_parents_exist}")
        print("==================================================")

    if report.overall_verdict != "SIMULATION_SUCCESS_ALL_GATES_PASSED":
        sys.exit(1)
    sys.exit(0)


if __name__ == "__main__":
    main()
