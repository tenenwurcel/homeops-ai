import argparse
import json
from pathlib import Path

from homeops_ai.build import (
    BuildError,
    cleanup_failed,
    list_builds,
    rebuild,
    rollback,
    validation_report,
    verify_run,
)
from homeops_ai.database import run_smoke_test
from homeops_ai.migration import (
    MigrationError,
    apply_migration,
    plan_migration,
    restore_migration,
    write_report,
)
from homeops_ai.source_contract import discover_sources, export_snapshot


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="HomeOps AI development tools")
    subparsers = parser.add_subparsers(dest="command", required=True)

    smoke = subparsers.add_parser("smoke", help="verify embedded CozoDB")
    smoke.add_argument(
        "--database",
        type=Path,
        help="RocksDB directory; omit to use a disposable in-memory database",
    )

    vault = subparsers.add_parser("vault", help="inspect and migrate a Markdown vault")
    vault_subparsers = vault.add_subparsers(dest="vault_command", required=True)

    inventory = vault_subparsers.add_parser(
        "inventory", help="list sources allowed by the vault contract"
    )
    inventory.add_argument("--vault", type=Path, required=True)
    inventory.add_argument("--include-uppercase-markdown", action="store_true")

    migrate = vault_subparsers.add_parser(
        "migrate", help="plan or apply UUID and lifecycle metadata migration"
    )
    migrate.add_argument("--vault", type=Path, required=True)
    migrate.add_argument("--include-uppercase-markdown", action="store_true")
    mode = migrate.add_mutually_exclusive_group(required=True)
    mode.add_argument("--dry-run", action="store_true")
    mode.add_argument("--apply", action="store_true")
    migrate.add_argument("--output", type=Path)
    migrate.add_argument("--report", type=Path)
    migrate.add_argument("--data-dir", type=Path, default=Path("data"))

    restore = vault_subparsers.add_parser(
        "restore", help="restore exact source bytes from an applied migration"
    )
    restore.add_argument("--vault", type=Path, required=True)
    restore.add_argument("--migration-id", required=True)
    restore.add_argument("--data-dir", type=Path, default=Path("data"))

    validate = vault_subparsers.add_parser(
        "validate", help="validate sources, metadata, categories, and link resolution"
    )
    validate.add_argument("--vault", type=Path, required=True)
    validate.add_argument("--output", type=Path)

    snapshot = vault_subparsers.add_parser(
        "snapshot", help="export approved source bytes and path-only artifact inventory"
    )
    snapshot.add_argument("--vault", type=Path, required=True)
    snapshot.add_argument("--output", type=Path, required=True)

    database = subparsers.add_parser("db", help="build and manage derived Cozo databases")
    database_subparsers = database.add_subparsers(
        dest="database_command", required=True
    )

    rebuild_parser = database_subparsers.add_parser(
        "rebuild", help="build, verify, and promote an immutable candidate"
    )
    rebuild_parser.add_argument("--vault", type=Path, required=True)
    rebuild_parser.add_argument("--data-dir", type=Path, default=Path("data"))
    rebuild_parser.add_argument("--force", action="store_true")
    rebuild_parser.add_argument("--no-promote", action="store_true")

    verify_parser = database_subparsers.add_parser(
        "verify", help="verify an active or selected immutable build"
    )
    verify_parser.add_argument("--data-dir", type=Path, default=Path("data"))
    verify_parser.add_argument("--run-id")

    builds_parser = database_subparsers.add_parser("builds", help="list builds")
    builds_parser.add_argument("--data-dir", type=Path, default=Path("data"))

    rollback_parser = database_subparsers.add_parser(
        "rollback", help="switch active.json to the previous verified build"
    )
    rollback_parser.add_argument("--data-dir", type=Path, default=Path("data"))

    cleanup_parser = database_subparsers.add_parser(
        "cleanup", help="remove database directories for failed builds"
    )
    cleanup_parser.add_argument("--data-dir", type=Path, default=Path("data"))
    cleanup_parser.add_argument("--failed", action="store_true", required=True)

    return parser


def main() -> None:
    args = build_parser().parse_args()

    if args.command == "smoke":
        if args.database is not None:
            args.database.parent.mkdir(parents=True, exist_ok=True)
        rows = run_smoke_test(args.database)
        print(f"CozoDB smoke test passed: {rows}")
        return

    if args.command == "vault" and args.vault_command == "inventory":
        sources = discover_sources(
            args.vault,
            include_uppercase_markdown=args.include_uppercase_markdown,
        )
        print(
            json.dumps(
                {
                    "vault_root": str(args.vault.resolve()),
                    "count": len(sources),
                    "sources": [
                        {"source_path": item.source_path, "kind": item.kind}
                        for item in sources
                    ],
                },
                indent=2,
            )
        )
        return

    if args.command == "vault" and args.vault_command == "migrate":
        try:
            if args.dry_run:
                if args.output is None:
                    raise MigrationError("--output is required with --dry-run")
                report = plan_migration(
                    args.vault,
                    include_uppercase_markdown=args.include_uppercase_markdown,
                )
                write_report(report, args.output)
                print(json.dumps(report.to_dict()["summary"], indent=2))
                if report.errors:
                    raise SystemExit(2)
                return

            if args.report is None:
                raise MigrationError("--report is required with --apply")
            migration_dir = apply_migration(
                args.report, args.vault.resolve(), args.data_dir
            )
            print(f"Migration applied with exact-byte snapshot: {migration_dir}")
            return
        except MigrationError as error:
            raise SystemExit(str(error)) from error

    if args.command == "vault" and args.vault_command == "restore":
        try:
            restore_migration(args.migration_id, args.vault.resolve(), args.data_dir)
            print(f"Migration restored: {args.migration_id}")
            return
        except MigrationError as error:
            raise SystemExit(str(error)) from error

    if args.command == "vault" and args.vault_command == "validate":
        try:
            report = validation_report(args.vault)
            if args.output:
                args.output.parent.mkdir(parents=True, exist_ok=True)
                args.output.write_text(json.dumps(report, indent=2) + "\n")
            print(json.dumps(report, indent=2))
            if report["validation"]["errors"]:
                raise SystemExit(2)
            return
        except (BuildError, OSError, ValueError) as error:
            raise SystemExit(str(error)) from error

    if args.command == "vault" and args.vault_command == "snapshot":
        try:
            print(json.dumps(export_snapshot(args.vault, args.output), indent=2))
            return
        except (OSError, ValueError) as error:
            raise SystemExit(str(error)) from error

    if args.command == "db":
        try:
            if args.database_command == "rebuild":
                result = rebuild(
                    args.vault,
                    args.data_dir,
                    force=args.force,
                    promote=not args.no_promote,
                )
            elif args.database_command == "verify":
                result = verify_run(args.data_dir, args.run_id)
            elif args.database_command == "builds":
                result = {"builds": list_builds(args.data_dir)}
            elif args.database_command == "rollback":
                result = rollback(args.data_dir)
            elif args.database_command == "cleanup":
                result = {"cleaned_failed_builds": cleanup_failed(args.data_dir)}
            else:
                raise BuildError(f"unsupported database command: {args.database_command}")
            print(json.dumps(result, indent=2))
            return
        except (BuildError, OSError, ValueError) as error:
            raise SystemExit(str(error)) from error
