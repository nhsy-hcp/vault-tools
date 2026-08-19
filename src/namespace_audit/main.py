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
from src.common.file_utils import write_csv, write_json, write_markdown
from src.common.utils import FILE_DATE_FORMAT, normalise_namespace_path
from src.common.vault_client import VaultClient, VaultConnectionError
from src.namespace_audit.report import build_markdown_report

logger = logging.getLogger(__name__)


# The progress bar's resting label. Named because the rate-limit pause swaps it
# out and has to put it back — printing the pause instead would corrupt the bar.
PROGRESS_DESCRIPTION = "[cyan]Processing namespaces..."

# ACL policies Vault provisions in every namespace. Excluded from the inventory
# because they are present everywhere and so say nothing about how a particular
# namespace is configured -- 266 of the 1,499 policies on the reference cluster.
#
# "default-ceiling" is the non-obvious one. It is not documented as a built-in,
# but it appears in every namespace with a byte-identical body granting self-read
# on agent-registry/registration/entity_id/{{identity.entity.id}} -- and
# agent_registry is already treated as a Vault-managed mount in report.py's
# BUILTIN_ENGINE_TYPES.
#
# Matched exactly, never by prefix: a user-defined "default-admin" or
# "default-ceiling-override" is real configuration and must still be listed.
BUILTIN_ACL_POLICIES = frozenset({"default", "root", "default-ceiling"})


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
    # The counters above say how much the audit missed; these say *what*. A
    # denied subtree is a hole in the report, and a bare tally gives the reader
    # no way to find it — so record the path alongside every increment.
    forbidden_namespaces: list[tuple[str, str]] = field(default_factory=list)
    errors: list[tuple[str, str]] = field(default_factory=list)
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

    def increment_errors(self, namespace: str | None = None, message: str = "") -> None:
        """Record an error, optionally naming the namespace it occurred in.

        The arguments are optional so existing bare calls keep working; supply
        them wherever the namespace is known so the report can list it.
        """
        with self._lock:
            self.error_count += 1
            if namespace is not None:
                self.errors.append((namespace, message))

    def increment_forbidden(self, namespace: str | None = None, scope: str = "") -> None:
        """Record a permission denial atomically.

        ``scope`` describes what was refused — the whole namespace, or only the
        listing of its children — because the two lose very different amounts of
        data and the reader needs to tell them apart.
        """
        with self._lock:
            self.forbidden_count += 1
            if namespace is not None:
                self.forbidden_namespaces.append((namespace, scope))


@dataclass
class AuditData:
    """Container for audit results."""

    namespaces: dict[str, Any] = field(default_factory=dict)
    auth_methods: dict[str, Any] = field(default_factory=dict)
    secret_engines: dict[str, Any] = field(default_factory=dict)
    # Sentinel governing policies, keyed the same way as the two collections
    # above: namespace -> {policy name: {enforcement_level, paths, policy}}.
    # EGP entries carry "paths"; RGP entries do not. Both stay empty on any
    # cluster without the Enterprise Governance & Policy module.
    egp_policies: dict[str, Any] = field(default_factory=dict)
    rgp_policies: dict[str, Any] = field(default_factory=dict)
    # ACL policy names per namespace, sorted, with the Vault built-ins removed.
    # Unlike the Sentinel dicts this keeps the key even when the list is empty:
    # "this namespace defines no policies of its own" is a real answer, and on
    # the reference cluster 12 namespaces are in exactly that state.
    acl_policies: dict[str, list[str]] = field(default_factory=dict)


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
        collect_sentinel: bool = True,
    ):
        self.vault_client = vault_client
        self.worker_threads = worker_threads
        self.rate_limit_batch_size = rate_limit_batch_size
        self.rate_limit_sleep_seconds = rate_limit_sleep_seconds
        self.rate_limit_disable = rate_limit_disable
        self.output_dir = output_dir
        self.worker_queue_timeout = worker_queue_timeout
        self.queue_depth_warn_threshold = queue_depth_warn_threshold
        self.collect_sentinel = collect_sentinel
        self._queue_depth_warned = False
        self.stats = AuditStats()
        self.data = AuditData()
        # Namespaces already discovered, keyed without the trailing slash. The
        # tree is finite, but a namespace can be reached only once, so this
        # guards against enqueueing (and billing an API round-trip for) the
        # same path twice if Vault ever reports overlapping children.
        self.visited: set[str] = set()
        self.thread_lock = threading.Lock()
        self.console = Console()
        self.audit_logger = get_audit_logger()
        self.progress_task = None
        self.progress = None
        # Recorded by audit_cluster so the report can state where the walk began;
        # "the audit found no denials" only means something alongside its scope.
        self.start_namespace = ""
        # (default_lease_ttl, max_lease_ttl) for the cluster, or None if the
        # token cannot read it. Calibrates the report's lease findings.
        self.system_lease_ttls: tuple[int, int] | None = None
        # Tri-state, mutated by worker threads under thread_lock. None = never
        # probed (collection disabled, or no namespace reached); True = the
        # endpoint answered at least once; False = the cluster has no Sentinel,
        # which short-circuits every later probe. The report distinguishes all
        # three, because "no policies" and "no Sentinel" are different answers.
        self.sentinel_supported: bool | None = None
        # Basenames of everything _write_reports actually wrote, for the console
        # list printed after the summary table. Held on the instance rather than
        # returned because the integration tests patch _write_reports wholesale:
        # an attribute that stays empty prints nothing, where a return value
        # would hand the printer a Mock to iterate.
        self.output_files: list[str] = []
        # First-denial-per-namespace guard for the per-policy reads, so a
        # namespace holding 40 unreadable policies contributes one access-gap
        # row rather than 40. Keyed by (namespace, kind); guarded by thread_lock.
        self._sentinel_read_denied: set[tuple[str, str]] = set()

    def audit_cluster(self, namespace_path: str = ""):
        start_time = time.time()
        display_ns = namespace_path if namespace_path else "root"
        self.start_namespace = namespace_path

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
                f"[bold cyan]Vault Namespace Audit[/bold cyan]\nVault address: [yellow]{self.vault_client.vault_addr}[/yellow]\nStarting namespace: [yellow]{display_ns}[/yellow]\nWorker threads: [green]{self.worker_threads}[/green]",
                border_style="cyan",
            )
        )

        logger.info("Starting Vault cluster audit")
        logger.debug(f"Initial namespace parameter: '{namespace_path}'")
        self.stats.start()

        try:
            cluster_name = self.vault_client.validate_connection()
            self.console.print(f"[green]✓[/green] Connected to cluster: [bold]{cluster_name}[/bold]")

            self.system_lease_ttls = self._fetch_system_lease_ttls()

            # The queue must stay unbounded: worker threads are also the
            # producers (they enqueue child namespaces from _traverse_namespace),
            # so a maxsize would let a worker block on put() waiting for itself.
            # Memory visibility comes from the depth warning instead.
            path_queue: queue.Queue[str] = queue.Queue()
            # Canonicalise via the shared helper: None, "" and "/" all mean the
            # root namespace, and anything else gains the trailing slash Vault's
            # namespace API expects (C1).
            initial_namespace = normalise_namespace_path(namespace_path)
            logger.debug(f"Initial namespace after processing: '{initial_namespace}'")
            with self.thread_lock:
                self.visited = {initial_namespace.rstrip("/")}
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
                    PROGRESS_DESCRIPTION,
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

            self._write_reports(cluster_name)
            self._log_summary()
            self._print_output_files()

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

    def _fetch_system_lease_ttls(self) -> tuple[int, int] | None:
        """Read the cluster's default and max lease TTLs.

        Optional enrichment, never a failure: the endpoint needs a policy rule
        the audit can otherwise do without, so any error here downgrades the
        report's lease findings to a fixed threshold rather than sinking the run.
        """
        try:
            response = self.vault_client.get("sys/config/state/sanitized")
            payload = response.get("data", response) if isinstance(response, dict) else {}
            default_ttl = payload.get("default_lease_ttl")
            max_ttl = payload.get("max_lease_ttl")
            if isinstance(default_ttl, int) and isinstance(max_ttl, int) and max_ttl > 0:
                logger.debug(f"System lease TTLs: default={default_ttl}s max={max_ttl}s")
                return default_ttl, max_ttl
            logger.debug(f"Unexpected sys/config/state/sanitized payload; lease TTLs unavailable: {payload!r}")
        except Exception as e:
            logger.debug(f"Could not read sys/config/state/sanitized ({e}); lease findings will use the fixed threshold")
        return None

    def _fetch_acl_policies(self, client: Any, display_path: str) -> list[str]:
        """List this namespace's own ACL policy names.

        Names only -- the bodies are deliberately not read. That would need
        `read` on sys/policies/acl/*, which lets the audit token reconstruct the
        cluster's entire access model; listing needs only `list`.

        Simpler than the Sentinel collector: sys/policies/acl exists on every
        Vault edition, so there is no capability to probe for and no tri-state.
        """
        try:
            names = client.sys.list_acl_policies()["data"]["keys"] or []
        except hvac.exceptions.InvalidPath:
            # Vault 404s an empty LIST. Every namespace has at least "default",
            # so this is unlikely in practice, but it is not an error.
            logger.debug(f"No ACL policies in {display_path}")
            return []
        except hvac.exceptions.Forbidden:
            # Debug, not warning -- see the note in _list_and_read: one line per
            # namespace would print straight through the live progress bar.
            logger.debug(f"Permission denied listing ACL policies for: {display_path}")
            self.stats.increment_forbidden(display_path, "ACL policies")
            return []
        except Exception as e:
            logger.error(f"Error listing ACL policies for {display_path}: {e}")
            self.stats.increment_errors(display_path, f"ACL policies: {e}")
            return []

        return sorted(n for n in names if n not in BUILTIN_ACL_POLICIES)

    def _fetch_sentinel_policies(self, client: Any, display_path: str) -> tuple[dict[str, Any], dict[str, Any]]:
        """Collect this namespace's Sentinel EGP and RGP policies.

        Returns ``(egp, rgp)``, each mapping policy name to its full definition.
        Both are empty when Sentinel is unavailable — the endpoints exist only on
        Vault Enterprise with the Governance & Policy module, and the audit must
        run unchanged on Community.
        """
        if not self.collect_sentinel or self.sentinel_supported is False:
            return {}, {}
        egp = self._list_and_read(client, "egp", display_path)
        # Re-check between the two: if the EGP probe just discovered the cluster
        # has no Sentinel, the RGP probe would only 404 the same way. A whole
        # Community run therefore costs a single wasted API call.
        if self.sentinel_supported is False:
            return {}, {}
        return egp, self._list_and_read(client, "rgp", display_path)

    def _mark_sentinel_supported(self) -> None:
        """Record that a Sentinel endpoint answered.

        False is sticky: "unsupported path" is a property of the cluster, not of
        one namespace, so a later success cannot be evidence against it — and
        letting True win a race would restart the probing this flag exists to
        stop.
        """
        with self.thread_lock:
            if self.sentinel_supported is None:
                self.sentinel_supported = True

    def _list_and_read(self, client: Any, kind: str, display_path: str) -> dict[str, Any]:
        """List one Sentinel policy kind in the current namespace and read each body.

        The LIST is where the cluster's capability is decided, and Vault makes
        that awkward: it answers 404 both for "this build has no Sentinel" and
        for "this namespace has zero policies", so only the error body tells them
        apart. Hence the string check below — a heuristic, but one whose failure
        mode is benign: if Vault ever reworks the message the short-circuit stops
        firing and every namespace simply re-probes to an empty result.
        """
        try:
            lister = client.sys.list_egp_policies if kind == "egp" else client.sys.list_rgp_policies
            names = lister()["data"]["keys"] or []
        except hvac.exceptions.InvalidPath as e:
            if "unsupported path" in str(e).lower():
                with self.thread_lock:
                    first = self.sentinel_supported is None
                    self.sentinel_supported = False
                if first:
                    logger.info("Sentinel policy endpoints are unavailable on this cluster; skipping EGP/RGP collection")
                return {}
            # An empty LIST also 404s. Nothing to collect, but the endpoint is there.
            logger.debug(f"No sentinel {kind.upper()} policies in {display_path}")
            self._mark_sentinel_supported()
            return {}
        except hvac.exceptions.Forbidden:
            # Debug, not warning: this fires once per namespace, and a token
            # missing the rule outright produced 268 lines on a 134-namespace
            # cluster — printed straight through the live progress bar. The
            # denial is not lost: increment_forbidden feeds the summary
            # table's count and the report's collapsed Access gaps table.
            logger.debug(f"Permission denied listing sentinel {kind.upper()} policies for: {display_path}")
            self.stats.increment_forbidden(display_path, f"sentinel {kind.upper()} policies")
            return {}
        except Exception as e:
            logger.error(f"Error listing sentinel {kind.upper()} policies for {display_path}: {e}")
            self.stats.increment_errors(display_path, f"sentinel {kind.upper()} policies: {e}")
            return {}

        self._mark_sentinel_supported()

        reader = client.sys.read_egp_policy if kind == "egp" else client.sys.read_rgp_policy
        policies: dict[str, Any] = {}
        for name in names:
            try:
                policies[name] = reader(name)["data"]
            except Exception as e:
                # Keep the name: that a policy exists is worth reporting even when
                # its body is unreadable. One access-gap row per namespace and
                # kind, not one per policy — a namespace with 40 denied reads
                # would otherwise swamp the whole section.
                logger.debug(f"Could not read sentinel {kind.upper()} policy '{name}' in {display_path}: {e}")
                policies[name] = {"name": name, "read_error": str(e)}
                with self.thread_lock:
                    already_recorded = (display_path, kind) in self._sentinel_read_denied
                    self._sentinel_read_denied.add((display_path, kind))
                if not already_recorded:
                    self.stats.increment_forbidden(display_path, f"sentinel {kind.upper()} policy bodies")
        return policies

    def _set_progress_description(self, description: str) -> None:
        """Relabel the progress bar, if one is running.

        Same guard as _refresh_progress: the auditor is driven directly by tests
        and by callers that never enter the Progress context.
        """
        if self.progress is None or self.progress_task is None:
            return
        self.progress.update(self.progress_task, description=description)

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
                self.stats.increment_errors(namespace_path if namespace_path else "root", str(e))
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
            # Say so on the bar rather than printing: a stalled spinner with no
            # explanation reads as a hang, and a print here would tear the bar
            # apart — the very problem this change exists to fix.
            self._set_progress_description(f"[yellow]Rate limiting — sleeping {self.rate_limit_sleep_seconds}s...")
            try:
                time.sleep(self.rate_limit_sleep_seconds)
            finally:
                self._set_progress_description(PROGRESS_DESCRIPTION)

        try:
            with self.vault_client.get_client(namespace_path) as client:
                logger.debug(f"Fetching auth methods for namespace: {display_path}")
                auth_methods = client.sys.list_auth_methods()["data"]
                logger.debug(f"Found {len(auth_methods)} auth methods for namespace: {display_path}")

                logger.debug(f"Fetching secrets engines for namespace: {display_path}")
                secret_engines = client.sys.list_mounted_secrets_engines()["data"]
                logger.debug(f"Found {len(secret_engines)} secret engines for namespace: {display_path}")

                acl_policies = self._fetch_acl_policies(client, display_path)
                egp_policies, rgp_policies = self._fetch_sentinel_policies(client, display_path)

                with self.thread_lock:
                    # Store namespace_path without trailing slash if not root
                    stored_namespace_path = namespace_path.rstrip("/") if namespace_path != "" else ""
                    logger.debug(f"Storing auth methods for namespace '{stored_namespace_path}': {len(auth_methods)} entries")
                    self.data.auth_methods[stored_namespace_path] = auth_methods
                    logger.debug(f"Storing secrets engines for namespace '{stored_namespace_path}': {len(secret_engines)} entries")
                    self.data.secret_engines[stored_namespace_path] = secret_engines
                    # Stored unconditionally, empty list included: a namespace
                    # defining no policies of its own is a real answer.
                    self.data.acl_policies[stored_namespace_path] = acl_policies
                    # Only recorded where present: an entry per namespace on a
                    # Community cluster would put an empty row in every table.
                    if egp_policies:
                        self.data.egp_policies[stored_namespace_path] = egp_policies
                    if rgp_policies:
                        self.data.rgp_policies[stored_namespace_path] = rgp_policies

                # Every namespace is asked for its children, so the queue walks
                # the whole tree rather than stopping one level below the
                # starting point. The visited set below keeps the walk finite.
                try:
                    logger.debug(f"Attempting to list child namespaces for: {display_path}")
                    raw_namespaces_response = client.sys.list_namespaces()
                    child_namespaces = raw_namespaces_response["data"]["key_info"]

                    if child_namespaces:
                        logger.debug(f"Found {len(child_namespaces)} child namespaces in {display_path}: {list(child_namespaces.keys())}")

                        # Claim the unseen children under one lock, then enqueue
                        # outside it: the denominator must count only what this
                        # thread actually put on the queue, or two workers
                        # discovering a shared child would inflate the total.
                        new_children: list[str] = []
                        with self.thread_lock:
                            for name, info in child_namespaces.items():
                                # list_namespaces returns names relative to the current
                                # namespace, so the absolute path is parent + name.
                                child_path_full = f"{namespace_path}{name}"
                                stored_path = child_path_full.rstrip("/")
                                if stored_path in self.visited:
                                    logger.debug(f"Skipping already-visited namespace '{stored_path}'")
                                    continue
                                self.visited.add(stored_path)
                                self.data.namespaces[stored_path] = info
                                new_children.append(child_path_full)
                                logger.debug(f"Stored namespace data for '{stored_path}' in data collection")

                        if new_children:
                            # Grow the progress denominator before enqueueing so
                            # the bar never reports more done than known (N4).
                            self.stats.add_discovered(len(new_children))
                            self._refresh_progress()
                            for child_path_full in new_children:
                                logger.debug(f"Adding namespace '{child_path_full}' to processing queue")
                                path_queue.put(child_path_full)  # Put full path with trailing slash for API calls
                                self._warn_on_queue_depth(path_queue)
                    else:
                        logger.debug(f"No child namespaces found for {display_path}")
                except hvac.exceptions.InvalidPath:
                    logger.debug(f"InvalidPath exception for {display_path} - no child namespaces available")
                except hvac.exceptions.Forbidden:
                    # The auth methods and engines above were already captured;
                    # only the subtree below this namespace is lost, so record
                    # the gap without discarding what this namespace returned.
                    # Per-namespace, so debug — see the note in _list_and_read.
                    logger.debug(f"Permission denied listing child namespaces for: {display_path}")
                    self.stats.increment_forbidden(display_path, "child namespaces (subtree not audited)")

        except hvac.exceptions.Forbidden:
            logger.debug(f"Permission denied for namespace: {display_path}")
            self.stats.increment_forbidden(display_path, "whole namespace (no data collected)")
        except Exception as e:
            logger.error(f"Error processing namespace {display_path}: {e}")
            self.stats.increment_errors(display_path, str(e))

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

        def path_for(kind: str, extension: str) -> str:
            return f"{self.output_dir}/{cluster_name}-{kind}-{date_str}.{extension}"

        # Write JSON files
        logger.debug(f"Writing namespaces JSON with {len(self.data.namespaces)} namespaces")
        write_json(path_for("namespaces", "json"), convert_namespace_keys(self.data.namespaces))

        logger.debug(f"Writing auth methods JSON with {len(self.data.auth_methods)} namespace entries")
        write_json(path_for("auth-methods", "json"), convert_namespace_keys(self.data.auth_methods))

        logger.debug(f"Writing secrets engines JSON with {len(self.data.secret_engines)} namespace entries")
        write_json(path_for("secrets-engines", "json"), convert_namespace_keys(self.data.secret_engines))

        # Unlike the Sentinel dump this is written whenever a namespace was
        # reached: ACL policies exist on every Vault edition, so an empty file
        # means "nothing defined", not "unsupported".
        if self.data.acl_policies:
            logger.debug(f"Writing ACL policies JSON with {len(self.data.acl_policies)} namespace entries")
            write_json(path_for("acl-policies", "json"), convert_namespace_keys(self.data.acl_policies))

        # Sentinel is Enterprise-only, so this file is written only when there is
        # something in it — an empty dump on a Community cluster reads as a
        # collection failure rather than as "this cluster has no Sentinel".
        if self.data.egp_policies or self.data.rgp_policies:
            logger.debug(f"Writing sentinel policies JSON with {len(self.data.egp_policies)} EGP and {len(self.data.rgp_policies)} RGP namespace entries")
            write_json(
                path_for("sentinel-policies", "json"),
                {
                    "egp": convert_namespace_keys(self.data.egp_policies),
                    "rgp": convert_namespace_keys(self.data.rgp_policies),
                },
            )

        # Write CSV summaries
        self._write_namespace_summary(path_for("summary-namespaces", "csv"))
        self._write_auth_methods_summary(path_for("summary-auth-methods", "csv"))
        self._write_secrets_engines_summary(path_for("summary-secrets-engines", "csv"))
        self._write_acl_summary(path_for("summary-acl-policies", "csv"))
        self._write_sentinel_summary(path_for("summary-sentinel-policies", "csv"))

        # Write the human-readable report last so it can index the files above.
        # Existence is checked rather than assumed: the CSV summary writers
        # return early when they have no rows and the Sentinel pair is skipped
        # entirely off Enterprise, so a root-only Community cluster produces five
        # of the eight and listing all eight would send the reader after
        # something that was never written.
        candidates = [
            path_for(kind, extension)
            for kind, extension in (
                ("namespaces", "json"),
                ("auth-methods", "json"),
                ("secrets-engines", "json"),
                ("acl-policies", "json"),
                ("sentinel-policies", "json"),
                ("summary-namespaces", "csv"),
                ("summary-auth-methods", "csv"),
                ("summary-secrets-engines", "csv"),
                ("summary-acl-policies", "csv"),
                ("summary-sentinel-policies", "csv"),
            )
        ]
        sibling_files = [os.path.basename(p) for p in candidates if os.path.exists(p)]
        report_path = path_for("audit-report", "md")
        self._write_markdown_report(report_path, cluster_name, sibling_files)
        # The report indexes its siblings, so it is not in that list itself —
        # but the console list is about what landed on disk, and the report is
        # the file most readers want the path to.
        self.output_files = [*sibling_files, os.path.basename(report_path)] if os.path.exists(report_path) else list(sibling_files)

    def _write_markdown_report(
        self,
        file_path: str,
        cluster_name: str,
        sibling_files: list[str],
    ):
        """Render and write the markdown audit report.

        A rendering failure must not sink a completed audit — the JSON and CSV
        files are already on disk at this point and carry the raw data, so the
        error is reported and swallowed rather than propagated.
        """
        try:
            content = build_markdown_report(
                cluster_name,
                self.data,
                self.stats,
                start_namespace=self.start_namespace,
                vault_addr=self.vault_client.vault_addr,
                worker_threads=self.worker_threads,
                output_files=sibling_files,
                system_lease_ttls=self.system_lease_ttls,
                sentinel_supported=self.sentinel_supported,
            )
            write_markdown(file_path, content)
        except Exception as e:
            logger.exception(f"Failed to write the markdown report: {e}")
            self.console.print(f"[yellow]⚠[/yellow] Markdown report could not be written: {e}")

    def _print_output_files(self) -> None:
        """List what the run wrote, after the summary table.

        The file writers log at INFO, which the console no longer shows — by
        design, since those lines used to interleave with the progress bar. This
        is the user-facing replacement, and it is one block rather than a line
        per writer so the paths stay together and in a predictable order.
        """
        if not self.output_files:
            return
        self.console.print(f"\n[bold]Output files[/bold] → [cyan]{self.output_dir}/[/cyan]")
        for name in self.output_files:
            self.console.print(f"  [green]✓[/green] {name}")

    def _write_namespace_summary(self, file_path: str):
        if not self.data.namespaces:
            return
        df = pd.DataFrame.from_dict(self.data.namespaces, orient="index")
        df["path"] = df.index
        df = df[["path", "id", "custom_metadata"]]
        write_csv(file_path, df.to_dict("records"), df.columns.tolist())

    def _write_acl_summary(self, file_path: str):
        """One row per ACL policy.

        The markdown table groups by namespace for readability; this keeps the
        flat grain so the file can be grepped and pivoted. Namespaces with no
        policies of their own contribute no row -- the report already shows them
        as zero, and a row with an empty policy column would not survive a grep.
        """
        rows = [{"namespace": namespace, "policy": name} for namespace, names in self.data.acl_policies.items() for name in names]

        if not rows:
            return

        write_csv(file_path, rows, ["namespace", "policy"])

    def _write_sentinel_summary(self, file_path: str):
        """One row per Sentinel policy across both kinds.

        Written with write_csv directly rather than through pandas: the rows are
        already uniform, so there is no matrix to reshape the way the auth and
        engine summaries need.
        """
        rows = []
        for kind, collection in (("egp", self.data.egp_policies), ("rgp", self.data.rgp_policies)):
            for namespace, policies in collection.items():
                for name, policy in policies.items():
                    body = policy.get("policy", "") if isinstance(policy, dict) else ""
                    paths = policy.get("paths") if isinstance(policy, dict) else None
                    rows.append(
                        {
                            "namespace": namespace,
                            "kind": kind,
                            "name": name,
                            "enforcement_level": policy.get("enforcement_level", "") if isinstance(policy, dict) else "",
                            "paths": ",".join(paths) if isinstance(paths, list) else "",
                            "policy_lines": len(body.splitlines()) if isinstance(body, str) else 0,
                        }
                    )

        if not rows:
            return

        write_csv(file_path, rows, ["namespace", "kind", "name", "enforcement_level", "paths", "policy_lines"])

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

        self.console.print()
        self.console.print(table)

        # Log to standard logger as well
        logger.info("Audit finished.")
        logger.info(f"Processed {self.stats.processed_count} namespaces in {duration:.2f} seconds.")
        if self.stats.forbidden_count > 0:
            logger.warning(f"Permission denied for {self.stats.forbidden_count} namespace(s) — skipped.")
        if self.stats.error_count > 0:
            logger.warning(f"Encountered {self.stats.error_count} errors.")
