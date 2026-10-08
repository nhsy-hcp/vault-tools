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
#     "rich>=13.7.0",
# ]
# ///
import argparse
import importlib.metadata
import os
import sys
import uuid
from collections.abc import Callable
from datetime import date
from typing import Any

from rich.console import Console

from src.activity_export.main import run_activity_export
from src.cluster_audit.main import run_cluster_audit
from src.common.config import GlobalConfig
from src.common.exceptions import ConfigurationError, VaultToolsError
from src.common.findings import EXIT_OK, SEVERITY_ORDER, exit_code_for
from src.common.logging_config import (
    get_structured_logger,
    set_correlation_id,
    setup_logging,
)
from src.common.utils import validate_date_format
from src.common.vault_client import VaultClient
from src.entity_export.main import run_entity_export
from src.findings_diff.main import run_diff
from src.full_audit.main import STEPS as FULL_AUDIT_STEPS
from src.full_audit.main import default_window, run_full_audit
from src.identity_audit.main import run_identity_audit
from src.namespace_audit.main import NamespaceAuditor

# `uv run main.py` executes this file as a PEP 723 script, so the vault-tools
# distribution is not installed and importlib.metadata cannot be the only
# source. The literal is the fallback for that mode and is pinned to
# pyproject.toml by a test, so the two cannot drift.
_FALLBACK_VERSION = "3.1.0"

try:
    __version__ = importlib.metadata.version("vault-tools")
except importlib.metadata.PackageNotFoundError:
    __version__ = _FALLBACK_VERSION

# A run that produced no findings document: the command has already said why.
EXIT_FATAL = 1


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
    # PEM CA bundle to verify the server's certificate against, as the vault CLI
    # reads it. Checked here so a typo fails before any request, not as an
    # opaque TLS error from inside the first read.
    vault_cacert = os.environ.get("VAULT_CACERT") or None
    if vault_cacert and not vault_skip_verify and not os.path.isfile(vault_cacert):
        logger.error("vault_cacert_not_found", vault_cacert=vault_cacert)
        sys.stderr.write(f"Error: VAULT_CACERT file not found: {vault_cacert}\n")
        sys.exit(1)

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

    return VaultClient(vault_addr, vault_token, vault_skip_verify=vault_skip_verify, vault_cacert=vault_cacert)


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


def resolve_window(args: argparse.Namespace, logger) -> tuple[str, str]:
    """Return the ``(start, end)`` activity window from ``-s/-e``, or the default.

    Both or neither: one date alone exits 1. Two dates are validated. Neither
    means the last 12 calendar months, and the resolved window is printed so
    the user sees what was exported.
    """
    start_date, end_date = args.start_date, args.end_date
    if bool(start_date) != bool(end_date):
        logger.error("incomplete_date_window", start_date=start_date, end_date=end_date)
        sys.stderr.write("Error: pass both --start-date and --end-date, or neither for the last 12 months\n")
        sys.exit(1)
    if start_date:
        validate_dates(start_date, end_date, logger)
        return start_date, end_date
    start_date, end_date = default_window(date.today())
    # console.print, not logger.info: INFO is invisible on a default run.
    Console().print(f"Window: {start_date} → {end_date} (default: last 12 calendar months)")
    return start_date, end_date


_SUBCOMMANDS_HELP = """\
Audits:
  full-audit        Every audit and export, plus a combined report (recommended)
  namespace-audit   Namespaces, auth methods, secret engines, ACL and Sentinel policies
  cluster-audit     Seal, HA, replication, raft, audit devices, snapshots, metrics
  identity-audit    Identity entities and aliases

Exports:
  activity-export   Activity data and client usage checks (VT-CLI-*)
  entity-export     Entity data from the activity export

Utilities:
  diff              Compare two findings.json files

Run 'main.py <subcommand> --help' for a subcommand's options.
"""


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

    parser = argparse.ArgumentParser(
        description="Vault Tools CLI",
        parents=[common],
        epilog=_SUBCOMMANDS_HELP,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
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
    # Subparsers take description=, not help=: argparse lists every parser
    # given help= as one flat block, and the grouped epilog replaces that.
    subparsers = parser.add_subparsers(
        dest="command",
        required=True,
        title="subcommands",
        metavar="<subcommand>",
        help="One of the subcommands below; full-audit is the recommended starting point.",
    )

    # CI gating flags, shared by every subcommand that writes a findings.json.
    # Exit 3 beats exit 2 when both apply: a finding is the stronger signal.
    gating = argparse.ArgumentParser(add_help=False)
    gating.add_argument(
        "--fail-on",
        choices=[s.lower() for s in SEVERITY_ORDER],
        default=None,
        help="Exit 3 when any finding is at or above this severity.",
    )
    gating.add_argument(
        "--fail-on-gaps",
        action="store_true",
        help="Exit 2 when coverage is incomplete (a namespace or scope was denied or errored).",
    )

    # Namespace walk, shared by every command that traverses the tree.
    walk_opts = argparse.ArgumentParser(add_help=False)
    walk_opts.add_argument("-w", "--workers", type=int, default=4, help="Number of worker threads.")

    # Policy body collection, shared by namespace-audit and full-audit.
    policy_opts = argparse.ArgumentParser(add_help=False)
    policy_opts.add_argument(
        "--names-only",
        action="store_true",
        help="List policy names without reading ACL or Sentinel bodies, even when the token could. Without it, bodies are read wherever the token's policies allow.",
    )
    policy_opts.add_argument(
        "--no-sentinel",
        action="store_true",
        help="Skip Sentinel EGP/RGP policy collection. Costs one LIST per namespace on Vault Enterprise, plus one read per policy when the token can read bodies; a no-op elsewhere.",
    )

    # Activity window, shared by the exports and full-audit. Both or neither;
    # resolve_window() enforces that and supplies the default.
    window_opts = argparse.ArgumentParser(add_help=False)
    window_opts.add_argument("-s", "--start-date", type=str, default=None, help="Window start (YYYY-MM-DD). Default: the last 12 calendar months.")
    window_opts.add_argument("-e", "--end-date", type=str, default=None, help="Window end (YYYY-MM-DD). Default: today.")

    # Full Audit command: every audit and export, plus one combined report.
    parser_full = subparsers.add_parser(
        "full-audit",
        description="Run every audit and export (cluster, namespace, identity, activity, entity) and write a combined report.",
        parents=[common, gating, walk_opts, policy_opts, window_opts],
    )
    parser_full.add_argument("--list-entities", action="store_true", help="Also write identity entity names, metadata and aliases (confidential).")
    # cluster-audit always runs: it supplies the cluster name and node state.
    step_choice = parser_full.add_mutually_exclusive_group()
    step_choice.add_argument("--skip", action="append", choices=FULL_AUDIT_STEPS[1:], metavar="STEP", help=f"Skip a step; repeatable. One of: {', '.join(FULL_AUDIT_STEPS[1:])}.")
    step_choice.add_argument("--only", action="append", choices=FULL_AUDIT_STEPS[1:], metavar="STEP", help="Run only this step (plus cluster-audit); repeatable.")

    # Namespace Audit command
    subparsers.add_parser("namespace-audit", description="Audit Vault namespaces.", parents=[common, gating, walk_opts, policy_opts])

    # Cluster Audit command
    subparsers.add_parser(
        "cluster-audit",
        description="Audit cluster health: seal, HA, replication, raft, audit devices, snapshots, metrics.",
        parents=[common, gating],
    )

    # Identity Audit command
    parser_identity = subparsers.add_parser(
        "identity-audit",
        description="Audit identity entities: orphans, direct policies, disabled entities, duplicate aliases.",
        parents=[common, gating, walk_opts],
    )
    parser_identity.add_argument(
        "--list",
        "--list-entities",
        dest="list",
        action="store_true",
        help="Also write every entity's name, metadata and aliases to a separate file. Confidential: they can hold emails and role_ids.",
    )

    # Activity Export command
    subparsers.add_parser(
        "activity-export",
        description="Export activity data and check client usage patterns (VT-CLI-*).",
        parents=[common, gating, window_opts],
    )

    # Entity Export command
    subparsers.add_parser("entity-export", description="Export entity data.", parents=[common, window_opts])

    # Diff command: compares two findings.json files, no Vault connection.
    parser_diff = subparsers.add_parser(
        "diff",
        description="Compare two findings.json files (new, resolved, unchanged).",
        parents=[common],
    )
    parser_diff.add_argument("old", nargs="?", default=None, help="Earlier *-findings-*.json. Omit both to compare the two newest full-audit runs.")
    parser_diff.add_argument("new", nargs="?", default=None, help="Later *-findings-*.json")

    return parser


def _gate(document: dict[str, Any] | None, args: argparse.Namespace) -> int:
    """Exit code for a findings document; a missing one is a failed run."""
    # The command has already printed why; a failed audit must not pass a CI
    # gate by exiting 0.
    if document is None:
        return EXIT_FATAL
    return exit_code_for(document, args.fail_on, args.fail_on_gaps)


def _cmd_namespace_audit(args: argparse.Namespace, vault_client: VaultClient, global_config: GlobalConfig, logger) -> int:
    logger.info("command_execution_started", command="namespace-audit", workers=args.workers)
    auditor = NamespaceAuditor(
        vault_client,
        worker_threads=args.workers,
        output_dir=global_config.output_dir,
        collect_sentinel=not args.no_sentinel,
        names_only=args.names_only,
    )
    return _gate(auditor.audit_cluster(), args)


def _cmd_cluster_audit(args: argparse.Namespace, vault_client: VaultClient, global_config: GlobalConfig, logger) -> int:
    logger.info("command_execution_started", command="cluster-audit")
    return _gate(run_cluster_audit(vault_client, global_config.output_dir), args)


def _cmd_identity_audit(args: argparse.Namespace, vault_client: VaultClient, global_config: GlobalConfig, logger) -> int:
    logger.info("command_execution_started", command="identity-audit", workers=args.workers)
    document = run_identity_audit(vault_client, global_config.output_dir, workers=args.workers, include_list=args.list)
    return _gate(document, args)


def _full_audit_skip(args: argparse.Namespace) -> frozenset[str]:
    """The steps to skip, from --skip or the complement of --only."""
    if args.only:
        return frozenset(FULL_AUDIT_STEPS[1:]) - frozenset(args.only)
    return frozenset(args.skip or ())


def _cmd_full_audit(args: argparse.Namespace, vault_client: VaultClient, global_config: GlobalConfig, logger) -> int:
    start_date, end_date = resolve_window(args, logger)
    skip = _full_audit_skip(args)
    logger.info("command_execution_started", command="full-audit", workers=args.workers, skip=sorted(skip))
    document = run_full_audit(
        vault_client,
        global_config.output_dir,
        workers=args.workers,
        collect_sentinel=not args.no_sentinel,
        names_only=args.names_only,
        include_entity_list=args.list_entities,
        start_date=start_date,
        end_date=end_date,
        skip=skip,
    )
    return _gate(document, args)


def _cmd_activity_export(args: argparse.Namespace, vault_client: VaultClient, global_config: GlobalConfig, logger) -> int:
    start_date, end_date = resolve_window(args, logger)
    logger.info("command_execution_started", command="activity-export", start_date=start_date, end_date=end_date)
    info = vault_client.validate_connection()
    result = run_activity_export(
        vault_client,
        start_date,
        end_date,
        info.cluster_name,
        output_dir=global_config.output_dir,
        is_enterprise=info.is_enterprise,
        cluster_id=info.cluster_id,
    )
    return _gate(result.findings_document, args)


def _cmd_entity_export(args: argparse.Namespace, vault_client: VaultClient, global_config: GlobalConfig, logger) -> int:
    start_date, end_date = resolve_window(args, logger)
    logger.info("command_execution_started", command="entity-export", start_date=start_date, end_date=end_date)
    info = vault_client.validate_connection()
    run_entity_export(
        vault_client,
        start_date,
        end_date,
        info.cluster_name,
        output_dir=global_config.output_dir,
        cluster_id=info.cluster_id,
    )
    return EXIT_OK


# Every subcommand that talks to Vault. diff is handled before a client exists.
COMMANDS: dict[str, Callable[[argparse.Namespace, VaultClient, GlobalConfig, Any], int]] = {
    "full-audit": _cmd_full_audit,
    "namespace-audit": _cmd_namespace_audit,
    "cluster-audit": _cmd_cluster_audit,
    "identity-audit": _cmd_identity_audit,
    "activity-export": _cmd_activity_export,
    "entity-export": _cmd_entity_export,
}


def _run_diff_command(args: argparse.Namespace, global_config: GlobalConfig, logger) -> None:
    """Run ``diff``: needs no Vault, so it runs before create_vault_client."""
    if (args.old is None) != (args.new is None):
        logger.error("diff_needs_two_files", old=args.old)
        sys.stderr.write("Error: pass two findings files to diff, or none to compare the two newest full-audit runs\n")
        sys.exit(1)
    try:
        run_diff(args.old, args.new, global_config.output_dir)
    except VaultToolsError as e:
        logger.error("vault_tools_failed", command="diff", error=str(e), error_type=type(e).__name__)
        sys.stderr.write(f"Error: {e}\n")
        sys.exit(1)
    logger.info("vault_tools_completed", command="diff")


def main() -> None:
    """Main entry point for the Vault Tools CLI application.

    Parses command line arguments and executes the appropriate tool:
    - full-audit: Run every audit and export, with a combined report
    - namespace-audit: Audit Vault namespaces, auth methods, and secret engines
    - cluster-audit: Audit cluster health, replication, audit devices and snapshots
    - identity-audit: Audit identity entities and aliases
    - activity-export: Export Vault activity logs and usage metrics
    - entity-export: Export Vault entity data
    - diff: Compare two findings.json files

    Exit codes: 0 ok, 1 fatal, 2 coverage gaps (--fail-on-gaps), 3 findings at
    or above --fail-on.
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

    if args.command == "diff":
        _run_diff_command(args, global_config, logger)
        return

    vault_client = create_vault_client(logger)

    try:
        exit_code = COMMANDS[args.command](args, vault_client, global_config, logger)
        logger.info("command_execution_completed", command=args.command, exit_code=exit_code)
        logger.info("vault_tools_completed", command=args.command)
        if exit_code != EXIT_OK:
            sys.exit(exit_code)

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
