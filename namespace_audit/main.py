#!/usr/bin/env python3
"""
Vault Namespace Audit Tool

A multi-threaded tool for auditing HashiCorp Vault namespaces, auth methods,
and secret engines across an entire cluster.
"""

import argparse
import json
import logging
import os
import queue
import threading
import time
import urllib3
from contextlib import contextmanager
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple

import hvac
import summary


# Constants
class Constants:
    DEFAULT_WORKER_THREADS = 4
    DEFAULT_TIMEOUT = 3
    DEFAULT_BATCH_SIZE = 100
    DEFAULT_SLEEP_SECONDS = 3
    ROOT_NAMESPACE = "/"
    DATE_FORMAT = "%Y%m%d"


@dataclass
class AuditConfig:
    """Configuration for the Vault audit process."""
    vault_addr: str
    vault_token: str
    namespace_path: str = ""
    worker_threads: int = Constants.DEFAULT_WORKER_THREADS
    vault_skip_verify: bool = False
    rate_limit_disable: bool = False
    rate_limit_batch_size: int = Constants.DEFAULT_BATCH_SIZE
    rate_limit_sleep_seconds: int = Constants.DEFAULT_SLEEP_SECONDS
    hvac_timeout: int = Constants.DEFAULT_TIMEOUT
    debug: bool = False

    def __post_init__(self):
        """Validate configuration after initialization."""
        self._validate()

        # Ensure namespace path ends with / if not empty
        if self.namespace_path and not self.namespace_path.endswith("/"):
            self.namespace_path += "/"

    def _validate(self) -> None:
        """Validate configuration parameters."""
        if not self.vault_addr:
            raise ValueError("VAULT_ADDR is required")
        if not self.vault_token:
            raise ValueError("VAULT_TOKEN is required")
        if self.worker_threads <= 0:
            raise ValueError("Worker threads must be positive")
        if self.rate_limit_batch_size <= 0:
            raise ValueError("Rate limit batch size must be positive")
        if self.hvac_timeout <= 0:
            raise ValueError("HVAC timeout must be positive")

    @property
    def vault_tls_verify(self) -> bool:
        """Get TLS verification setting."""
        return not self.vault_skip_verify


@dataclass
class AuditStats:
    """Statistics for the audit process."""
    processed_count: int = 0
    error_count: int = 0
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    _lock: threading.Lock = field(default_factory=threading.Lock)

    def start(self) -> None:
        """Mark audit start time."""
        self.start_time = datetime.now()

    def finish(self) -> None:
        """Mark audit end time."""
        self.end_time = datetime.now()

    @property
    def duration(self) -> Optional[float]:
        """Get audit duration in seconds."""
        if self.start_time and self.end_time:
            return (self.end_time - self.start_time).total_seconds()
        return None

    def increment_processed(self) -> None:
        """Thread-safe increment of processed counter."""
        with self._lock:
            self.processed_count += 1

    def increment_errors(self) -> None:
        """Thread-safe increment of error counter."""
        with self._lock:
            self.error_count += 1


@dataclass
class AuditData:
    """Container for audit results."""
    namespaces: Dict[str, Any] = field(default_factory=dict)
    auth_methods: Dict[str, Any] = field(default_factory=dict)
    secret_engines: Dict[str, Any] = field(default_factory=dict)


class VaultConnectionError(Exception):
    """Custom exception for Vault connection issues."""
    pass


class VaultAuditor:
    """Main class for conducting Vault namespace audits."""

    def __init__(self, config: AuditConfig):
        """Initialize the auditor with configuration."""
        self.config = config
        self.stats = AuditStats()
        self.data = AuditData()
        self.thread_lock = threading.Lock()
        self.logger = self._setup_logging()

        # Configure SSL warnings
        if config.vault_skip_verify:
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    def _setup_logging(self) -> logging.Logger:
        """Configure logging based on debug setting."""
        level = logging.DEBUG if self.config.debug else logging.INFO
        format_str = '%(asctime)s - %(name)s - %(levelname)s - [%(threadName)s] %(message)s'

        logging.basicConfig(
            level=level,
            format=format_str,
            datefmt='%Y-%m-%d %H:%M:%S'
        )

        return logging.getLogger(__name__)

    @contextmanager
    def _vault_client(self, namespace_path: str = ""):
        """Context manager for creating Vault clients."""
        client = hvac.Client(
            url=self.config.vault_addr,
            token=self.config.vault_token,
            namespace=namespace_path,
            verify=self.config.vault_tls_verify,
            timeout=self.config.hvac_timeout
        )
        try:
            yield client
        finally:
            # Cleanup if needed (hvac doesn't require explicit cleanup)
            pass

    def _validate_vault_connection(self) -> str:
        """Validate Vault connection and return cluster name."""
        try:
            with self._vault_client() as client:
                health_status = client.sys.read_health_status(
                    method='GET',
                    sealed_code=200,
                    performance_standby_code=200,
                    uninit_code=200
                )

                if not isinstance(health_status, dict):
                    raise VaultConnectionError(
                        f"Invalid health status response: {health_status}"
                    )

                # Perform additional checks
                if client.sys.is_sealed():
                    raise VaultConnectionError("Vault cluster is sealed")

                if not client.is_authenticated():
                    raise VaultConnectionError("Vault client is not authenticated")

                if not client.sys.is_initialized():
                    raise VaultConnectionError("Vault cluster is not initialized")

                cluster_name = health_status.get('cluster_name', 'unknown')
                self.logger.info(f"Connected to Vault cluster: {cluster_name}")
                return cluster_name

        except hvac.exceptions.VaultError as e:
            raise VaultConnectionError(f"Vault error: {e}") from e
        except Exception as e:
            raise VaultConnectionError(f"Connection error: {e}") from e

    def _fetch_namespace_data(self, namespace_path: str) -> Tuple[
        Optional[Dict[str, Any]],
        Optional[Dict[str, Any]],
        Optional[Dict[str, Any]]
    ]:
        """Fetch auth methods, secret engines, and child namespaces."""
        try:
            with self._vault_client(namespace_path) as client:
                # Fetch auth methods and secret engines
                auth_methods = client.sys.list_auth_methods()
                secret_engines = client.sys.list_mounted_secrets_engines()

                # Fetch child namespaces (may raise InvalidPath if none exist)
                try:
                    namespaces = client.sys.list_namespaces()
                    self.logger.debug(
                        f"Fetched namespaces for {namespace_path}: "
                        f"{list(namespaces.get('data', {}).get('key_info', {}).keys())}"
                    )
                except hvac.exceptions.InvalidPath:
                    namespaces = None

                return auth_methods, secret_engines, namespaces

        except hvac.exceptions.Forbidden as e:
            self.logger.warning(f"Access denied for namespace {namespace_path}: {e}")
            return None, None, None
        except hvac.exceptions.VaultError as e:
            self.logger.error(f"Vault error for namespace {namespace_path}: {e}")
            self.stats.increment_errors()

            return None, None, None
        except Exception as e:
            self.logger.exception(f"Unexpected error for namespace {namespace_path}: {e}")
            return None, None, None

    def _extract_child_namespaces(self, namespaces_response: Optional[Dict[str, Any]]) -> List[str]:
        """Extract child namespace paths from API response."""
        if not namespaces_response:
            return []

        data = namespaces_response.get("data", {})
        key_info = data.get("key_info", {})

        return list(key_info.keys())

    def _traverse_namespace(self, namespace_path: str, path_queue: queue.Queue[str]) -> None:
        """Traverse a single namespace and collect data."""
        display_path = namespace_path if namespace_path else Constants.ROOT_NAMESPACE

        with self.thread_lock:
            self.stats.increment_processed()
            current_count = self.stats.processed_count

        self.logger.info(f"Processing namespace ({current_count}): {display_path}")

        # Fetch namespace data
        auth_methods, secret_engines, namespaces = self._fetch_namespace_data(namespace_path)

        # Store results with thread safety
        key_path = display_path

        with self.thread_lock:
            if auth_methods is not None:
                self.data.auth_methods[key_path] = auth_methods
            if secret_engines is not None:
                self.data.secret_engines[key_path] = secret_engines

        # Process child namespaces
        if namespaces:
            child_namespaces = self._extract_child_namespaces(namespaces)
            if self.logger.isEnabledFor(logging.DEBUG):
                self.logger.debug(
                    f"Found {len(child_namespaces)} child namespaces in {display_path}: "
                    f"{', '.join(child_namespaces) if child_namespaces else 'None'}"
                )
            with self.thread_lock:
                # Store namespace info
                data = namespaces.get("data", {})
                key_info = data.get("key_info", {})

                for child_name in child_namespaces:
                    child_path = f"{namespace_path}{child_name}"
                    path_queue.put(child_path)
                    self.data.namespaces[child_path] = key_info.get(child_name, {})
                    if self.logger.isEnabledFor(logging.DEBUG):
                        self.logger.debug(
                            f"Queued child namespace: {child_path} "
                            f"(total queued: {path_queue.qsize()})"
                        )


    def _should_rate_limit(self) -> bool:
        """Check if rate limiting should be applied."""
        if self.config.rate_limit_disable:
            return False

        return self.stats.processed_count % self.config.rate_limit_batch_size == 0

    def _apply_rate_limit(self) -> None:
        """Apply rate limiting by sleeping."""
        self.logger.info(
            f"Rate limiting - sleeping {self.config.rate_limit_sleep_seconds}s "
            f"(batch size: {self.config.rate_limit_batch_size})"
        )
        time.sleep(self.config.rate_limit_sleep_seconds)

    def _worker(self, path_queue: queue.Queue[str]) -> None:
        """Worker thread function."""
        while True:
            try:
                namespace_path = path_queue.get(timeout=300)
                self.logger.debug(f"Worker received namespace: {namespace_path}")
                if namespace_path is None:  # Shutdown signal
                    break

                # Check rate limiting
                with self.thread_lock:
                    if self._should_rate_limit():
                        self._apply_rate_limit()

                # Process namespace
                self._traverse_namespace(namespace_path, path_queue)

            except queue.Empty:
                continue
            except Exception as e:
                self.logger.exception(f"Worker error: {e}")
                with self.thread_lock:
                    self.stats.increment_errors()
            finally:
                try:
                    path_queue.task_done()
                except ValueError:
                    # task_done() called more times than items in queue
                    pass

    def _write_json_files(self, cluster_name: str) -> None:
        """Write audit results to JSON files."""
        date_str = datetime.now().strftime(Constants.DATE_FORMAT)

        files = {
            f'{cluster_name}-namespaces-{date_str}.json': self.data.namespaces,
            f'{cluster_name}-auth-methods-{date_str}.json': self.data.auth_methods,
            f'{cluster_name}-secrets-engines-{date_str}.json': self.data.secret_engines,
        }

        self.logger.info(f"Writing JSON files: {', '.join(files.keys())}")

        for filename, data in files.items():
            try:
                with open(filename, 'w', encoding='utf-8') as f:
                    json.dump(data, f, indent=2, ensure_ascii=False)
            except IOError as e:
                self.logger.error(f"Failed to write {filename}: {e}")

    def _generate_summary_reports(self, cluster_name: str) -> None:
        """Generate CSV summary reports."""
        date_str = datetime.now().strftime(Constants.DATE_FORMAT)

        files = {
            'namespaces': f"{cluster_name}-summary-namespaces-{date_str}.csv",
            'auth_methods': f"{cluster_name}-summary-auth-methods-{date_str}.csv",
            'secret_engines': f"{cluster_name}-summary-secrets-engines-{date_str}.csv",
        }

        self.logger.info(f"Writing CSV summaries: {', '.join(files.values())}")

        try:
            summary.parse_namespaces(self.data.namespaces, files['namespaces'])
            summary.parse_auth_methods(self.data.auth_methods, files['auth_methods'])
            summary.parse_secret_engines(self.data.secret_engines, files['secret_engines'])
        except Exception as e:
            self.logger.error(f"Failed to generate summary reports: {e}")

    def _log_audit_summary(self) -> None:
        """Log final audit statistics."""
        duration_str = f"{self.stats.duration:.2f}s" if self.stats.duration else "unknown"

        self.logger.info(
            f"Audit complete: "
            f"{self.stats.processed_count} namespaces processed, "
            f"{self.stats.error_count} errors, "
            f"duration: {duration_str}"
        )

        if self.stats.error_count > 0:
            self.logger.warning(f"Audit completed with {self.stats.error_count} errors")

    def audit_cluster(self) -> bool:
        """
        Main method to audit the entire Vault cluster.

        Returns:
            bool: True if audit completed successfully, False otherwise
        """
        try:
            self.logger.info("Starting Vault cluster audit")
            self.stats.start()

            # Validate connection and get cluster name
            cluster_name = self._validate_vault_connection()

            # Create work queue and add initial namespace
            path_queue: queue.Queue[str] = queue.Queue()
            path_queue.put(self.config.namespace_path)

            # Start worker threads
            workers = []
            for i in range(self.config.worker_threads):
                worker_thread = threading.Thread(
                    target=self._worker,
                    args=(path_queue,),
                    name=f"VaultWorker-{i + 1}"
                )
                worker_thread.start()
                workers.append(worker_thread)

            self.logger.info(f"Started {len(workers)} worker threads")

            # Wait for all work to complete
            path_queue.join()

            # Shutdown workers gracefully
            for _ in workers:
                path_queue.put(None)

            for worker in workers:
                worker.join(timeout=5)  # 5 second timeout for cleanup

            self.stats.finish()

            # Generate output files
            self._write_json_files(cluster_name)
            self._generate_summary_reports(cluster_name)

            # Log summary
            self._log_audit_summary()

            return True

        except VaultConnectionError as e:
            self.logger.error(f"Vault connection failed: {e}")
            return False
        except KeyboardInterrupt:
            self.logger.info("Audit interrupted by user")
            return False
        except Exception as e:
            self.logger.exception(f"Unexpected error during audit: {e}")
            return False


def create_config_from_args(args: argparse.Namespace) -> AuditConfig:
    """Create AuditConfig from command line arguments."""
    vault_addr = os.environ.get('VAULT_ADDR')
    vault_token = os.environ.get('VAULT_TOKEN')
    vault_skip_verify = os.environ.get('VAULT_SKIP_VERIFY', 'False').lower() == 'true'

    if not vault_addr:
        raise ValueError("VAULT_ADDR environment variable is required")
    if not vault_token:
        raise ValueError("VAULT_TOKEN environment variable is required")

    return AuditConfig(
        vault_addr=vault_addr,
        vault_token=vault_token,
        namespace_path=args.namespace or "",
        worker_threads=args.workers,
        vault_skip_verify=vault_skip_verify,
        rate_limit_disable=args.fast,
        debug=args.debug
    )


def parse_arguments() -> argparse.Namespace:
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description='Audit HashiCorp Vault cluster namespaces, auth methods, and secret engines',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Environment Variables:
  VAULT_ADDR        Vault server address (required)
  VAULT_TOKEN       Vault authentication token (required)
  VAULT_SKIP_VERIFY Skip TLS certificate verification (default: False)

Examples:
  %(prog)s                           # Audit entire cluster from root
  %(prog)s -n "team-a/"             # Audit specific namespace
  %(prog)s -w 8 --fast              # Use 8 workers with no rate limiting
  %(prog)s -d                       # Enable debug logging
        """
    )

    parser.add_argument(
        '-d', '--debug',
        action='store_true',
        help='Enable debug logging'
    )

    parser.add_argument(
        '--fast',
        action='store_true',
        help='Disable rate limiting for faster execution'
    )

    parser.add_argument(
        '-n', '--namespace',
        type=str,
        help='Namespace path to audit (default: root namespace)'
    )

    parser.add_argument(
        '-w', '--workers',
        type=int,
        default=Constants.DEFAULT_WORKER_THREADS,
        help=f'Number of worker threads (default: {Constants.DEFAULT_WORKER_THREADS})'
    )

    return parser.parse_args()


def main() -> int:
    """Main entry point."""
    try:
        args = parse_arguments()
        config = create_config_from_args(args)

        auditor = VaultAuditor(config)
        success = auditor.audit_cluster()

        return 0 if success else 1

    except ValueError as e:
        print(f"Configuration error: {e}")
        return 1
    except KeyboardInterrupt:
        print("\nAudit interrupted by user")
        return 1
    except Exception as e:
        print(f"Unexpected error: {e}")
        return 1


if __name__ == "__main__":
    exit(main())