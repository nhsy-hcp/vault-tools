
import argparse
import logging
import os
import sys

from src.common.vault_client import VaultClient
from src.common.config import GlobalConfig
from src.namespace_audit.main import NamespaceAuditor
from src.activity_export.main import run_activity_export
from src.entity_export.main import run_entity_export


def setup_logging(debug: bool = False) -> None:
    """Configure logging for the application.
    
    Args:
        debug: If True, enable DEBUG level logging for all loggers.
               If False, use INFO level logging.
    """
    level = logging.DEBUG if debug else logging.INFO
    logging.basicConfig(
        level=level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    if debug:
        logging.getLogger('hvac').setLevel(logging.DEBUG)
        logging.getLogger('requests').setLevel(logging.DEBUG)
        logging.getLogger('urllib3').setLevel(logging.DEBUG)

def create_vault_client() -> VaultClient:
    """Create and validate Vault client from environment variables.
    
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
        
        print(f"Missing required environment variables: {', '.join(missing_vars)}", file=sys.stderr)
        print("Please set these variables:", file=sys.stderr)
        if not vault_addr:
            print("  export VAULT_ADDR='https://your-vault-server.com'", file=sys.stderr)
        if not vault_token:
            print("  export VAULT_TOKEN='your-vault-token'", file=sys.stderr)
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
    parser_all.add_argument("-s", "--start-date", required=True, type=str, help="Start date (YYYY-MM-DD) for activity and entity exports.")
    parser_all.add_argument("-e", "--end-date", required=True, type=str, help="End date (YYYY-MM-DD) for activity and entity exports.")
    parser_all.add_argument("-n", "--namespace", type=str, help="Namespace path to audit (default: root) for namespace audit.")
    parser_all.add_argument("-w", "--workers", type=int, default=4, help="Number of worker threads for namespace audit.")

    args = parser.parse_args()
    setup_logging(args.debug)
    
    # Load global configuration and create vault client
    global_config = GlobalConfig.from_environment()
    vault_client = create_vault_client()

    if args.command == "namespace-audit":
        auditor = NamespaceAuditor(vault_client, args.workers, output_dir=global_config.output_dir)
        auditor.audit_cluster(args.namespace)
    elif args.command == "activity-export":
        cluster_name = vault_client.validate_connection()
        run_activity_export(vault_client, args.start_date, args.end_date, cluster_name, output_dir=global_config.output_dir)
    elif args.command == "entity-export":
        cluster_name = vault_client.validate_connection()
        run_entity_export(vault_client, args.start_date, args.end_date, cluster_name, output_dir=global_config.output_dir)
    elif args.command == "all":
        cluster_name = vault_client.validate_connection()
        
        # Run namespace-audit
        auditor = NamespaceAuditor(vault_client, args.workers, output_dir=global_config.output_dir)
        auditor.audit_cluster(args.namespace)

        # Run activity-export
        run_activity_export(vault_client, args.start_date, args.end_date, cluster_name, output_dir=global_config.output_dir)

        # Run entity-export
        run_entity_export(vault_client, args.start_date, args.end_date, cluster_name, output_dir=global_config.output_dir)

if __name__ == "__main__":
    main()
