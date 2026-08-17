#!/usr/bin/env -S uv run
# /// script
# requires-python = ">=3.12"
# dependencies = [
#     "hvac==2.2.0",
#     "pandas>=2.3.0,<3.0.0",
#     "requests>=2.32.4,<3.0.0",
#     "structlog>=23.1.0",
#     "tenacity>=8.2.3",
#     "python-json-logger>=2.0.7",
#     "cachetools>=5.3.0",
#     "rich>=13.7.0",
# ]
# ///
import argparse
import importlib.metadata
import os
import sys
import uuid

from src.activity_export.main import run_activity_export
from src.common.config import GlobalConfig
from src.common.exceptions import ConfigurationError, VaultToolsError
from src.common.logging_config import (
    get_structured_logger,
    set_correlation_id,
    setup_logging,
)
from src.common.utils import validate_date_format
from src.common.vault_client import VaultClient
from src.entity_export.main import run_entity_export
from src.namespace_audit.main import NamespaceAuditor

# `uv run main.py` executes this file as a PEP 723 script, so the vault-tools
# distribution is not installed and importlib.metadata cannot be the only
# source. The literal is the fallback for that mode and is pinned to
# pyproject.toml by a test, so the two cannot drift.
_FALLBACK_VERSION = "2.0.1"

try:
    __version__ = importlib.metadata.version("vault-tools")
except importlib.metadata.PackageNotFoundError:
    __version__ = _FALLBACK_VERSION


def create_vault_client(logger) -> VaultClient:
    """Create and validate Vault client from environment variables.

    Args:
        logger: Structured logger instance

    Returns:
        VaultClient: Configured Vault client instance.

    Raises:
        SystemExit: If required environment variables are not set.
    """
    vault_addr = os.environ.get("VAULT_ADDR")
    vault_token = os.environ.get("VAULT_TOKEN")
    # Read here rather than in VaultClient: the client treats it as a plain
    # constructor argument and never consults the environment for it, so
    # passing only addr and token silently left verification on.
    vault_skip_verify = os.environ.get("VAULT_SKIP_VERIFY", "false").lower() == "true"

    if not vault_addr or not vault_token:
        missing_vars = []
        if not vault_addr:
            missing_vars.append("VAULT_ADDR")
        if not vault_token:
            missing_vars.append("VAULT_TOKEN")

        logger.error(
            "missing_required_environment_variables",
            missing_vars=missing_vars,
            vault_addr_set=bool(vault_addr),
            vault_token_set=bool(vault_token),
        )
        sys.exit(1)

    return VaultClient(vault_addr, vault_token, vault_skip_verify=vault_skip_verify)


def validate_dates(start_date: str, end_date: str, logger) -> None:
    """Validate date format and ordering; exit with a clear message on failure.

    Args:
        start_date: Start date string (expected YYYY-MM-DD).
        end_date:   End date string (expected YYYY-MM-DD).
        logger:     Structured logger instance for error reporting.
    """
    for label, value in (("start-date", start_date), ("end-date", end_date)):
        try:
            validate_date_format(value)
        except ValueError as exc:
            logger.error("invalid_date_argument", field=label, value=value, error=str(exc))
            sys.stderr.write(f"Error: {exc}\n")
            sys.exit(1)

    if start_date > end_date:
        msg = f"--start-date ({start_date}) must not be after --end-date ({end_date})"
        logger.error("invalid_date_range", start_date=start_date, end_date=end_date)
        sys.stderr.write(f"Error: {msg}\n")
        sys.exit(1)


def build_parser() -> argparse.ArgumentParser:
    """Construct the CLI argument parser.

    Separate from main() so the parsing rules can be tested without executing
    any command.
    """
    # Global flags live on a shared parent so they are accepted either before or
    # after the subcommand — `main.py namespace-audit --output-dir X` is the
    # order most users reach for, and registering them only on the top-level
    # parser made that an "unrecognized arguments" error.
    # default=SUPPRESS is required, not cosmetic: a shared parent is applied to
    # both the top-level parser and each subparser, and the subparser parses
    # last. With an ordinary default the subparser would overwrite a value given
    # before the subcommand with its own default, silently discarding it.
    # SUPPRESS leaves the attribute unset when the flag is absent, so whichever
    # position supplied it wins. Read them with getattr() in main().
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--debug", action="store_true", default=argparse.SUPPRESS, help="Enable debug logging.")
    common.add_argument("--json-logs", action="store_true", default=argparse.SUPPRESS, help="Output logs in JSON format.")
    common.add_argument(
        "--output-dir",
        type=str,
        default=argparse.SUPPRESS,
        help="Output directory for reports (overrides VAULT_TOOLS_OUTPUT_DIR env var). Accepted before or after the subcommand.",
    )

    parser = argparse.ArgumentParser(description="Vault Tools CLI", parents=[common])
    # Terminal flag, so it stays on the top-level parser rather than the shared
    # parent: the version action prints and exits while the option is consumed,
    # which is what lets `main.py --version` succeed despite the required
    # subcommand below.
    parser.add_argument(
        "--version",
        action="version",
        version=f"vault-tools {__version__}",
        help="Show the version and exit.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # Namespace Audit command
    parser_audit = subparsers.add_parser("namespace-audit", help="Audit Vault namespaces.", parents=[common])
    parser_audit.add_argument("-w", "--workers", type=int, default=4, help="Number of worker threads.")

    # Activity Export command
    parser_activity = subparsers.add_parser("activity-export", help="Export activity data.", parents=[common])
    parser_activity.add_argument("-s", "--start-date", required=True, type=str, help="Start date (YYYY-MM-DD)")
    parser_activity.add_argument("-e", "--end-date", required=True, type=str, help="End date (YYYY-MM-DD)")

    # Entity Export command
    parser_entity = subparsers.add_parser("entity-export", help="Export entity data.", parents=[common])
    parser_entity.add_argument("-s", "--start-date", required=True, type=str, help="Start date (YYYY-MM-DD)")
    parser_entity.add_argument("-e", "--end-date", required=True, type=str, help="End date (YYYY-MM-DD)")

    # All command
    parser_all = subparsers.add_parser("all", help="Run all available commands.", parents=[common])
    parser_all.add_argument(
        "-s",
        "--start-date",
        required=True,
        type=str,
        help="Start date (YYYY-MM-DD) for activity and entity exports.",
    )
    parser_all.add_argument(
        "-e",
        "--end-date",
        required=True,
        type=str,
        help="End date (YYYY-MM-DD) for activity and entity exports.",
    )
    parser_all.add_argument(
        "-w",
        "--workers",
        type=int,
        default=4,
        help="Number of worker threads for namespace audit.",
    )

    return parser


def main() -> None:
    """Main entry point for the Vault Tools CLI application.

    Parses command line arguments and executes the appropriate tool:
    - namespace-audit: Audit Vault namespaces, auth methods, and secret engines
    - activity-export: Export Vault activity logs and usage metrics
    - entity-export: Export Vault entity data
    - all: Run all available tools in sequence
    """
    args = build_parser().parse_args()

    # Global flags use default=SUPPRESS (see above), so the attribute is absent
    # when the flag was not supplied in either position.
    json_logs = getattr(args, "json_logs", False)
    output_dir = getattr(args, "output_dir", None)

    # Load global configuration before logging is configured: it carries
    # VAULT_TOOLS_DEBUG, which has to be known to set the log level. Errors here
    # are reported on stderr because the structured logger is not up yet.
    # The CLI --output-dir flag takes precedence over the environment variable
    # and is passed through the constructor so the directory is created and
    # writability-checked up front. Assigning it afterwards skipped that check,
    # deferring the failure until after a full namespace traversal had run.
    try:
        global_config = GlobalConfig.from_environment(output_dir=output_dir)
    except ConfigurationError as e:
        sys.stderr.write(f"Error: {e}\n")
        sys.exit(1)

    # Either source enables debug; the flag cannot switch it back off.
    debug = getattr(args, "debug", False) or global_config.debug

    # Setup structured logging
    setup_logging(debug=debug, json_logs=json_logs)

    # Generate correlation ID for this execution
    correlation_id = str(uuid.uuid4())
    set_correlation_id(correlation_id)

    # Create structured logger
    logger = get_structured_logger(__name__)

    logger.info(
        "vault_tools_started",
        command=args.command,
        debug=debug,
        json_logs=json_logs,
    )

    if debug:
        logger.debug("debug_logging_enabled", args=vars(args))

    vault_client = create_vault_client(logger)

    try:
        if args.command == "namespace-audit":
            logger.info(
                "command_execution_started",
                command="namespace-audit",
                workers=args.workers,
            )
            auditor = NamespaceAuditor(
                vault_client,
                worker_threads=args.workers,
                output_dir=global_config.output_dir,
            )
            auditor.audit_cluster()
            logger.info("command_execution_completed", command="namespace-audit")

        elif args.command == "activity-export":
            validate_dates(args.start_date, args.end_date, logger)
            logger.info(
                "command_execution_started",
                command="activity-export",
                start_date=args.start_date,
                end_date=args.end_date,
            )
            cluster_name = vault_client.validate_connection()
            run_activity_export(
                vault_client,
                args.start_date,
                args.end_date,
                cluster_name,
                output_dir=global_config.output_dir,
            )
            logger.info("command_execution_completed", command="activity-export")

        elif args.command == "entity-export":
            validate_dates(args.start_date, args.end_date, logger)
            logger.info(
                "command_execution_started",
                command="entity-export",
                start_date=args.start_date,
                end_date=args.end_date,
            )
            cluster_name = vault_client.validate_connection()
            run_entity_export(
                vault_client,
                args.start_date,
                args.end_date,
                cluster_name,
                output_dir=global_config.output_dir,
            )
            logger.info("command_execution_completed", command="entity-export")

        elif args.command == "all":
            validate_dates(args.start_date, args.end_date, logger)
            logger.info(
                "command_execution_started",
                command="all",
                start_date=args.start_date,
                end_date=args.end_date,
                workers=args.workers,
            )
            # Validate connection once and reuse the cluster name for all sub-tools.
            cluster_name = vault_client.validate_connection()

            # Run namespace-audit
            logger.info("subcommand_started", subcommand="namespace-audit")
            auditor = NamespaceAuditor(
                vault_client,
                worker_threads=args.workers,
                output_dir=global_config.output_dir,
            )
            auditor.audit_cluster()
            logger.info("subcommand_completed", subcommand="namespace-audit")

            # Run activity-export (reuses cluster_name from above)
            logger.info("subcommand_started", subcommand="activity-export")
            run_activity_export(
                vault_client,
                args.start_date,
                args.end_date,
                cluster_name,
                output_dir=global_config.output_dir,
            )
            logger.info("subcommand_completed", subcommand="activity-export")

            # Run entity-export (reuses cluster_name from above)
            logger.info("subcommand_started", subcommand="entity-export")
            run_entity_export(
                vault_client,
                args.start_date,
                args.end_date,
                cluster_name,
                output_dir=global_config.output_dir,
            )
            logger.info("subcommand_completed", subcommand="entity-export")

            logger.info("command_execution_completed", command="all")

        logger.info("vault_tools_completed", command=args.command)

    except KeyboardInterrupt:
        # Ctrl-C during a threaded audit otherwise surfaces as stack traces from
        # whichever worker happened to be mid-request.
        logger.warning("vault_tools_interrupted", command=args.command)
        sys.stderr.write("\nInterrupted.\n")
        sys.exit(130)

    except VaultToolsError as e:
        # The project's own exception hierarchy covers the expected operational
        # failures — bad token, sealed cluster, denied path, malformed response.
        # These are not defects, so report the message and exit rather than
        # printing a traceback the user can do nothing with.
        logger.error(
            "vault_tools_failed",
            command=args.command,
            error=str(e),
            error_type=type(e).__name__,
        )
        sys.stderr.write(f"Error: {e}\n")
        sys.exit(1)

    except Exception as e:
        # Anything else is unexpected; keep the traceback, it is a bug report.
        logger.exception(
            "vault_tools_failed",
            command=args.command,
            error=str(e),
            error_type=type(e).__name__,
        )
        raise


if __name__ == "__main__":
    main()
