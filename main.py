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
import os
import sys

from src.activity_export.main import run_activity_export
from src.common.config import GlobalConfig
from src.common.logging_config import (
    get_structured_logger,
    set_correlation_id,
    setup_logging,
)
from src.common.vault_client import VaultClient
from src.entity_export.main import run_entity_export
from src.namespace_audit.main import NamespaceAuditor


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

        if not vault_addr:
            pass
        if not vault_token:
            pass
        sys.exit(1)

    return VaultClient(vault_addr, vault_token)


def main() -> None:
    """Main entry point for the Vault Tools CLI application.

    Parses command line arguments and executes the appropriate tool:
    - namespace-audit: Audit Vault namespaces, auth methods, and secret engines
    - activity-export: Export Vault activity logs and usage metrics
    - entity-export: Export Vault entity data
    - all: Run all available tools in sequence
    """
    parser = argparse.ArgumentParser(description="Vault Tools CLI")
    parser.add_argument("--debug", action="store_true", help="Enable debug logging.")
    parser.add_argument("--json-logs", action="store_true", help="Output logs in JSON format.")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # Namespace Audit command
    parser_audit = subparsers.add_parser("namespace-audit", help="Audit Vault namespaces.")
    parser_audit.add_argument("-n", "--namespace", type=str, default="", help="Namespace path to audit.")
    parser_audit.add_argument("-w", "--workers", type=int, default=4, help="Number of worker threads.")

    # Activity Export command
    parser_activity = subparsers.add_parser("activity-export", help="Export activity data.")
    parser_activity.add_argument("-s", "--start-date", required=True, type=str, help="Start date (YYYY-MM-DD)")
    parser_activity.add_argument("-e", "--end-date", required=True, type=str, help="End date (YYYY-MM-DD)")

    # Entity Export command
    parser_entity = subparsers.add_parser("entity-export", help="Export entity data.")
    parser_entity.add_argument("-s", "--start-date", required=True, type=str, help="Start date (YYYY-MM-DD)")
    parser_entity.add_argument("-e", "--end-date", required=True, type=str, help="End date (YYYY-MM-DD)")

    # All command
    parser_all = subparsers.add_parser("all", help="Run all available commands.")
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
        "-n",
        "--namespace",
        type=str,
        default="",
        help="Namespace path to audit (default: " ") for namespace audit.",
    )
    parser_all.add_argument(
        "-w",
        "--workers",
        type=int,
        default=4,
        help="Number of worker threads for namespace audit.",
    )

    args = parser.parse_args()

    # Setup structured logging
    setup_logging(debug=args.debug, json_logs=args.json_logs)

    # Generate correlation ID for this execution
    import uuid

    correlation_id = str(uuid.uuid4())
    set_correlation_id(correlation_id)

    # Create structured logger
    logger = get_structured_logger(__name__)

    logger.info(
        "vault_tools_started",
        command=args.command,
        debug=args.debug,
        json_logs=args.json_logs,
    )

    if args.debug:
        logger.debug("debug_logging_enabled", args=vars(args))

    # Load global configuration and create vault client
    global_config = GlobalConfig.from_environment()
    vault_client = create_vault_client(logger)

    try:
        if args.command == "namespace-audit":
            logger.info(
                "command_execution_started",
                command="namespace-audit",
                namespace=args.namespace,
                workers=args.workers,
            )
            auditor = NamespaceAuditor(
                vault_client,
                worker_threads=args.workers,
                output_dir=global_config.output_dir,
            )
            auditor.audit_cluster(args.namespace)
            logger.info("command_execution_completed", command="namespace-audit")

        elif args.command == "activity-export":
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
            logger.info(
                "command_execution_started",
                command="all",
                start_date=args.start_date,
                end_date=args.end_date,
                namespace=args.namespace,
                workers=args.workers,
            )
            cluster_name = vault_client.validate_connection()

            # Run namespace-audit
            logger.info("subcommand_started", subcommand="namespace-audit")
            auditor = NamespaceAuditor(
                vault_client,
                worker_threads=args.workers,
                output_dir=global_config.output_dir,
            )
            auditor.audit_cluster(args.namespace)
            logger.info("subcommand_completed", subcommand="namespace-audit")

            # Run activity-export
            logger.info("subcommand_started", subcommand="activity-export")
            run_activity_export(
                vault_client,
                args.start_date,
                args.end_date,
                cluster_name,
                output_dir=global_config.output_dir,
            )
            logger.info("subcommand_completed", subcommand="activity-export")

            # Run entity-export
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

    except Exception as e:
        logger.exception(
            "vault_tools_failed",
            command=args.command,
            error=str(e),
            error_type=type(e).__name__,
        )
        raise


if __name__ == "__main__":
    main()
