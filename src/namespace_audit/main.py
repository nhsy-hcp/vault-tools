import logging
import os
import queue
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

import hvac
import pandas as pd
from rich.console import Console
from rich.panel import Panel
from rich.progress import (
    BarColumn,
    Progress,
    SpinnerColumn,
    TaskProgressColumn,
    TextColumn,
    TimeRemainingColumn,
)
from rich.table import Table

from src.common.audit_logger import get_audit_logger
from src.common.file_utils import write_csv, write_json
from src.common.utils import FILE_DATE_FORMAT
from src.common.vault_client import VaultClient, VaultConnectionError

logger = logging.getLogger(__name__)


class Constants:
    DEFAULT_WORKER_THREADS = 4
    DEFAULT_TIMEOUT = 3
    DEFAULT_BATCH_SIZE = 100
    DEFAULT_SLEEP_SECONDS = 3


@dataclass
class AuditStats:
    """Statistics for the audit process."""

    processed_count: int = 0
    # Namespaces known to exist: the root plus every child discovered so far.
    # Serves as the progress-bar denominator, which grows as traversal uncovers
    # more of the tree and converges on processed_count at completion (N4).
    discovered_count: int = 1
    error_count: int = 0
    forbidden_count: int = 0
    start_time: datetime | None = None
    end_time: datetime | None = None
    _lock: threading.Lock = field(default_factory=threading.Lock)

    def start(self) -> None:
        self.start_time = datetime.now()

    def finish(self) -> None:
        self.end_time = datetime.now()

    @property
    def duration(self) -> float | None:
        if self.start_time and self.end_time:
            return (self.end_time - self.start_time).total_seconds()
        return None

    def increment_processed(self) -> int:
        """Increment the processed counter and return the new value atomically."""
        with self._lock:
            self.processed_count += 1
            return self.processed_count

    def add_discovered(self, count: int) -> int:
        """Record newly discovered child namespaces and return the new total."""
        with self._lock:
            self.discovered_count += count
            return self.discovered_count

    def increment_errors(self) -> None:
        with self._lock:
            self.error_count += 1

    def increment_forbidden(self) -> None:
        """Increment the forbidden (permission-denied) counter atomically."""
        with self._lock:
            self.forbidden_count += 1


@dataclass
class AuditData:
    """Container for audit results."""

    namespaces: dict[str, Any] = field(default_factory=dict)
    auth_methods: dict[str, Any] = field(default_factory=dict)
    secret_engines: dict[str, Any] = field(default_factory=dict)


class NamespaceAuditor:
    def __init__(
        self,
        vault_client: VaultClient,
        worker_threads: int = 4,
        rate_limit_batch_size: int = 100,
        rate_limit_sleep_seconds: int = 3,
        rate_limit_disable: bool = False,
        output_dir: str = "outputs",
        worker_queue_timeout: int = 300,
        queue_depth_warn_threshold: int = 10_000,
    ):
        self.vault_client = vault_client
        self.worker_threads = worker_threads
        self.rate_limit_batch_size = rate_limit_batch_size
        self.rate_limit_sleep_seconds = rate_limit_sleep_seconds
        self.rate_limit_disable = rate_limit_disable
        self.output_dir = output_dir
        self.worker_queue_timeout = worker_queue_timeout
        self.queue_depth_warn_threshold = queue_depth_warn_threshold
        self._queue_depth_warned = False
        self.stats = AuditStats()
        self.data = AuditData()
        self.thread_lock = threading.Lock()
        self.console = Console()
        self.audit_logger = get_audit_logger()
        self.progress_task = None
        self.progress = None

    def audit_cluster(self, namespace_path: str = ""):
        start_time = time.time()
        display_ns = namespace_path if namespace_path else "root"

        # Log audit start
        self.audit_logger.log_tool_execution(
            tool_name="namespace-audit",
            command=f"namespace-audit --namespace {namespace_path}",
            parameters={
                "namespace": namespace_path,
                "worker_threads": self.worker_threads,
                "rate_limit_batch_size": self.rate_limit_batch_size,
                "rate_limit_sleep_seconds": self.rate_limit_sleep_seconds,
                "rate_limit_disable": self.rate_limit_disable,
            },
            result="started",
        )

        self.console.print(
            Panel.fit(
                f"[bold cyan]Vault Namespace Audit[/bold cyan]\n" f"Starting namespace: [yellow]{display_ns}[/yellow]\n" f"Worker threads: [green]{self.worker_threads}[/green]",
                border_style="cyan",
            )
        )

        logger.info("Starting Vault cluster audit")
        logger.debug(f"Initial namespace parameter: '{namespace_path}'")
        self.stats.start()

        try:
            cluster_name = self.vault_client.validate_connection()
            self.console.print(f"[green]✓[/green] Connected to cluster: [bold]{cluster_name}[/bold]")

            # The queue must stay unbounded: worker threads are also the
            # producers (they enqueue child namespaces from _traverse_namespace),
            # so a maxsize would let a worker block on put() waiting for itself.
            # Memory visibility comes from the depth warning instead.
            path_queue: queue.Queue[str] = queue.Queue()
            # Handle None, "/" or empty namespace paths - all should default to root namespace
            initial_namespace = "" if namespace_path is None or namespace_path == "/" or namespace_path == "" else namespace_path
            logger.debug(f"Initial namespace after processing: '{initial_namespace}'")
            path_queue.put(initial_namespace)
            logger.debug(f"Added initial namespace '{initial_namespace}' to queue")

            # Start progress tracking
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TaskProgressColumn(),
                TimeRemainingColumn(),
                console=self.console,
            ) as progress:
                self.progress = progress
                # The total is the number of namespaces discovered so far
                # (starting at 1 for the root) and grows as children are found,
                # so the bar shows real progress and converges rather than
                # spinning indefinitely (N4).
                self.progress_task = progress.add_task(
                    "[cyan]Processing namespaces...",
                    total=self.stats.discovered_count,
                )

                workers = []
                for i in range(self.worker_threads):
                    worker_thread = threading.Thread(
                        target=self._worker,
                        args=(path_queue,),
                        name=f"VaultWorker-{i + 1}",
                    )
                    worker_thread.start()
                    workers.append(worker_thread)

                logger.info(f"Started {len(workers)} worker threads")
                path_queue.join()

                for _ in workers:
                    path_queue.put(None)

                for worker in workers:
                    worker.join(timeout=5)

            self.stats.finish()
            duration = time.time() - start_time

            # Display cache statistics
            cache_stats = self.vault_client.get_cache_stats()
            self.console.print("\n[bold]Cache Performance:[/bold]")
            self.console.print(f"  Hits: [green]{cache_stats['hits']}[/green] | Misses: [yellow]{cache_stats['misses']}[/yellow] | Hit Rate: [cyan]{cache_stats['hit_rate']}[/cyan]")

            self._write_reports(cluster_name)
            self._log_summary()

            # Log successful completion
            self.audit_logger.log_tool_execution(
                tool_name="namespace-audit",
                command=f"namespace-audit --namespace {namespace_path}",
                parameters={
                    "namespace": namespace_path,
                    "worker_threads": self.worker_threads,
                },
                result="success",
                duration_seconds=duration,
                metadata={
                    "cluster_name": cluster_name,
                    "namespaces_processed": self.stats.processed_count,
                    "errors": self.stats.error_count,
                    "forbidden": self.stats.forbidden_count,
                    "cache_stats": cache_stats,
                },
            )

        except VaultConnectionError as e:
            error_msg = str(e)
            logger.error(f"Vault connection failed: {error_msg}")
            self.console.print(f"[red]✗[/red] Connection failed: {error_msg}")

            # Log failure
            self.audit_logger.log_tool_execution(
                tool_name="namespace-audit",
                command=f"namespace-audit --namespace {namespace_path}",
                parameters={"namespace": namespace_path},
                result="failure",
                duration_seconds=time.time() - start_time,
                error=error_msg,
            )
        except Exception as e:
            error_msg = str(e)
            logger.exception(f"An unexpected error occurred during the audit: {error_msg}")
            self.console.print(f"[red]✗[/red] Unexpected error: {error_msg}")

            # Log failure
            self.audit_logger.log_tool_execution(
                tool_name="namespace-audit",
                command=f"namespace-audit --namespace {namespace_path}",
                parameters={"namespace": namespace_path},
                result="failure",
                duration_seconds=time.time() - start_time,
                error=error_msg,
            )

    def _refresh_progress(self) -> None:
        """Push current discovered/processed counts to the progress bar.

        Safe to call from worker threads: rich's Progress.update is internally
        locked, and both counters are read from the lock-protected AuditStats.
        """
        if self.progress is None or self.progress_task is None:
            return
        processed = self.stats.processed_count
        # Clamp so the bar can never render past 100%. Discovery normally runs
        # ahead of processing, but the two counters are incremented at different
        # points by different threads and a display artefact is not worth a lock
        # spanning both.
        total = max(self.stats.discovered_count, processed)
        self.progress.update(self.progress_task, completed=processed, total=total)

    def _warn_on_queue_depth(self, path_queue: queue.Queue[str]) -> None:
        """Warn once when the pending-namespace queue grows unusually deep.

        The queue is intentionally unbounded (see audit_cluster), so this is
        the only backpressure signal available.
        """
        if self._queue_depth_warned:
            return
        depth = path_queue.qsize()
        if depth > self.queue_depth_warn_threshold:
            self._queue_depth_warned = True
            logger.warning(
                f"Namespace queue depth is {depth}, above the warning threshold of {self.queue_depth_warn_threshold}. Memory use will grow with the queue; consider auditing a narrower namespace subtree."
            )

    def _worker(self, path_queue: queue.Queue[str]):
        worker_name = threading.current_thread().name
        logger.debug(f"Worker {worker_name} started")

        while True:
            # The get() is deliberately outside the try block below: task_done()
            # must only ever be called for an item that was actually retrieved,
            # otherwise it corrupts the counter that path_queue.join() depends on.
            try:
                logger.debug(f"Worker {worker_name} waiting for namespace from queue")
                namespace_path = path_queue.get(timeout=self.worker_queue_timeout)
            except queue.Empty:
                # Normal at the tail of a run while peers finish their subtrees.
                logger.debug(f"Worker {worker_name} timed out waiting for queue item after {self.worker_queue_timeout}s")
                continue

            try:
                if namespace_path is None:
                    logger.debug(f"Worker {worker_name} received shutdown signal")
                    break

                logger.debug(f"Worker {worker_name} got namespace: '{namespace_path}'")
                self._traverse_namespace(namespace_path, path_queue)
            except Exception as e:
                logger.exception(f"Error in worker thread: {e}")
                self.stats.increment_errors()
            finally:
                path_queue.task_done()

    def _traverse_namespace(self, namespace_path: str, path_queue: queue.Queue[str]):
        display_path = "root" if namespace_path == "" else namespace_path
        logger.info(f"Processing namespace: {display_path}")
        logger.debug(f"Getting Vault client for namespace: '{namespace_path}'")

        # Rate limiting is driven by the value returned from the increment so
        # that check-and-act is atomic: every count is observed exactly once, by
        # exactly one thread. Reading the counter separately would let two
        # workers both miss (or both hit) a batch boundary.
        processed = self.stats.increment_processed()
        self._refresh_progress()
        if not self.rate_limit_disable and processed % self.rate_limit_batch_size == 0:
            logger.info(f"Rate limiting - sleeping for {self.rate_limit_sleep_seconds} seconds")
            time.sleep(self.rate_limit_sleep_seconds)

        try:
            with self.vault_client.get_client(namespace_path) as client:
                logger.debug(f"Fetching auth methods for namespace: {display_path}")
                auth_methods = client.sys.list_auth_methods()["data"]
                logger.debug(f"Found {len(auth_methods)} auth methods for namespace: {display_path}")

                logger.debug(f"Fetching secrets engines for namespace: {display_path}")
                secret_engines = client.sys.list_mounted_secrets_engines()["data"]
                logger.debug(f"Found {len(secret_engines)} secret engines for namespace: {display_path}")

                with self.thread_lock:
                    # Store namespace_path without trailing slash if not root
                    stored_namespace_path = namespace_path.rstrip("/") if namespace_path != "" else ""
                    logger.debug(f"Storing auth methods for namespace '{stored_namespace_path}': {len(auth_methods)} entries")
                    self.data.auth_methods[stored_namespace_path] = auth_methods
                    logger.debug(f"Storing secrets engines for namespace '{stored_namespace_path}': {len(secret_engines)} entries")
                    self.data.secret_engines[stored_namespace_path] = secret_engines

                # Only traverse child namespaces from root namespace to avoid recursion
                if namespace_path == "":
                    try:
                        logger.debug(f"Attempting to list child namespaces for: {display_path}")
                        raw_namespaces_response = client.sys.list_namespaces()
                        # logger.debug(f"Raw namespaces response for {display_path}: {raw_namespaces_response}")
                        child_namespaces = raw_namespaces_response["data"]["key_info"]

                        if child_namespaces:
                            logger.debug(f"Found {len(child_namespaces)} child namespaces in {display_path}: {list(child_namespaces.keys())}")
                            # Grow the progress denominator before enqueueing so
                            # the bar never reports more done than known (N4).
                            self.stats.add_discovered(len(child_namespaces))
                            self._refresh_progress()
                            for name, info in child_namespaces.items():
                                # Construct child_path: if parent is root (""), child is like "bu01/", else "parent/bu01/"
                                child_path_full = f"{namespace_path}{name}"

                                logger.debug(f"Processing child namespace '{name}' -> constructed path: '{child_path_full}'")
                                logger.debug(f"Adding namespace '{child_path_full}' to processing queue")
                                path_queue.put(child_path_full)  # Put full path with trailing slash for API calls
                                self._warn_on_queue_depth(path_queue)
                                with self.thread_lock:
                                    stored_path = child_path_full.rstrip("/")
                                    self.data.namespaces[stored_path] = info
                                    logger.debug(f"Stored namespace data for '{stored_path}' in data collection")
                        else:
                            logger.debug(f"No child namespaces found for {display_path}")
                    except hvac.exceptions.InvalidPath:
                        logger.debug(f"InvalidPath exception for {display_path} - no child namespaces available")
                else:
                    logger.debug(f"Skipping child namespace discovery for non-root namespace: {display_path}")

        except hvac.exceptions.Forbidden:
            logger.warning(f"Permission denied for namespace: {display_path}")
            self.stats.increment_forbidden()
        except Exception as e:
            logger.error(f"Error processing namespace {display_path}: {e}")
            self.stats.increment_errors()

    def _write_reports(self, cluster_name: str):
        date_str = datetime.now().strftime(FILE_DATE_FORMAT)

        os.makedirs(self.output_dir, exist_ok=True)

        # Convert empty string namespace keys to "/" for JSON output
        def convert_namespace_keys(data_dict):
            """Convert empty string keys to '/' for root namespace representation."""
            converted = {}
            for key, value in data_dict.items():
                new_key = "/" if key == "" else key
                converted[new_key] = value
            return converted

        # Write JSON files
        logger.debug(f"Writing namespaces JSON with {len(self.data.namespaces)} namespaces")
        write_json(
            f"{self.output_dir}/{cluster_name}-namespaces-{date_str}.json",
            convert_namespace_keys(self.data.namespaces),
        )

        logger.debug(f"Writing auth methods JSON with {len(self.data.auth_methods)} namespace entries")
        write_json(
            f"{self.output_dir}/{cluster_name}-auth-methods-{date_str}.json",
            convert_namespace_keys(self.data.auth_methods),
        )

        logger.debug(f"Writing secrets engines JSON with {len(self.data.secret_engines)} namespace entries")
        write_json(
            f"{self.output_dir}/{cluster_name}-secrets-engines-{date_str}.json",
            convert_namespace_keys(self.data.secret_engines),
        )

        # Write CSV summaries
        self._write_namespace_summary(f"{self.output_dir}/{cluster_name}-summary-namespaces-{date_str}.csv")
        self._write_auth_methods_summary(f"{self.output_dir}/{cluster_name}-summary-auth-methods-{date_str}.csv")
        self._write_secrets_engines_summary(f"{self.output_dir}/{cluster_name}-summary-secrets-engines-{date_str}.csv")

    def _write_namespace_summary(self, file_path: str):
        if not self.data.namespaces:
            return
        df = pd.DataFrame.from_dict(self.data.namespaces, orient="index")
        df["path"] = df.index
        df = df[["path", "id", "custom_metadata"]]
        write_csv(file_path, df.to_dict("records"), df.columns.tolist())

    def _write_auth_methods_summary(self, file_path: str):
        self._write_item_summary(file_path, self.data.auth_methods, "auth_methods")

    def _write_secrets_engines_summary(self, file_path: str):
        self._write_item_summary(file_path, self.data.secret_engines, "secrets_engines")

    def _write_item_summary(self, file_path: str, data: dict[str, Any], item_type: str):
        rows = []
        for namespace, items in data.items():
            row = {"namespace": namespace}
            for _item_name, item_data in items.items():
                type_key = item_data.get("type")
                if type_key:
                    row[type_key] = row.get(type_key, 0) + 1
            rows.append(row)

        if not rows:
            return

        df = pd.DataFrame(rows)
        df = df.fillna(0)
        # Convert numeric columns to nullable int to avoid float output in CSV.
        # Int64 (capital I) is pandas' nullable integer type and avoids overflow
        # that the non-nullable int64 can silently produce on very large counts.
        numeric_columns = df.select_dtypes(include=["float64"]).columns
        df[numeric_columns] = df[numeric_columns].astype("Int64")
        write_csv(file_path, df.to_dict("records"), df.columns.tolist())

    def _log_summary(self):
        duration = self.stats.duration

        # Create summary table
        table = Table(title="Audit Summary", show_header=True, header_style="bold cyan")
        table.add_column("Metric", style="cyan", width=30)
        table.add_column("Value", style="green", width=20)

        table.add_row("Namespaces Processed", str(self.stats.processed_count))
        table.add_row(
            "Total Auth Methods",
            str(sum(len(methods) for methods in self.data.auth_methods.values())),
        )
        table.add_row(
            "Total Secret Engines",
            str(sum(len(engines) for engines in self.data.secret_engines.values())),
        )
        table.add_row("Duration", f"{duration:.2f} seconds")
        table.add_row("Worker Threads", str(self.worker_threads))

        if self.stats.error_count > 0:
            table.add_row("Errors", f"[red]{self.stats.error_count}[/red]")
        else:
            table.add_row("Errors", "[green]0[/green]")

        if self.stats.forbidden_count > 0:
            table.add_row("Permission Denied (skipped)", f"[yellow]{self.stats.forbidden_count}[/yellow]")
        else:
            table.add_row("Permission Denied (skipped)", "[green]0[/green]")

        self.console.print("\n")
        self.console.print(table)

        # Log to standard logger as well
        logger.info("Audit finished.")
        logger.info(f"Processed {self.stats.processed_count} namespaces in {duration:.2f} seconds.")
        if self.stats.forbidden_count > 0:
            logger.warning(f"Permission denied for {self.stats.forbidden_count} namespace(s) — skipped.")
        if self.stats.error_count > 0:
            logger.warning(f"Encountered {self.stats.error_count} errors.")
