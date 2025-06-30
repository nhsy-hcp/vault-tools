
import logging
import queue
import threading
import time
import os
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, Any, List, Optional, Tuple

import hvac
import pandas as pd

from src.common.file_utils import write_json, write_csv
from src.common.vault_client import VaultClient, VaultConnectionError
from src.common.config import NamespaceAuditConfig

logger = logging.getLogger(__name__)


class Constants:
    DEFAULT_WORKER_THREADS = 4
    DEFAULT_TIMEOUT = 3
    DEFAULT_BATCH_SIZE = 100
    DEFAULT_SLEEP_SECONDS = 3
    DATE_FORMAT = "%Y%m%d"

@dataclass
class AuditStats:
    """Statistics for the audit process."""
    processed_count: int = 0
    error_count: int = 0
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    _lock: threading.Lock = field(default_factory=threading.Lock)

    def start(self) -> None:
        self.start_time = datetime.now()

    def finish(self) -> None:
        self.end_time = datetime.now()

    @property
    def duration(self) -> Optional[float]:
        if self.start_time and self.end_time:
            return (self.end_time - self.start_time).total_seconds()
        return None

    def increment_processed(self) -> None:
        with self._lock:
            self.processed_count += 1

    def increment_errors(self) -> None:
        with self._lock:
            self.error_count += 1

@dataclass
class AuditData:
    """Container for audit results."""
    namespaces: Dict[str, Any] = field(default_factory=dict)
    auth_methods: Dict[str, Any] = field(default_factory=dict)
    secret_engines: Dict[str, Any] = field(default_factory=dict)

class NamespaceAuditor:
    def __init__(self, vault_client: VaultClient, worker_threads: int = 4, rate_limit_batch_size: int = 100, rate_limit_sleep_seconds: int = 3, rate_limit_disable: bool = False, output_dir: str = "outputs"):
        self.vault_client = vault_client
        self.worker_threads = worker_threads
        self.rate_limit_batch_size = rate_limit_batch_size
        self.rate_limit_sleep_seconds = rate_limit_sleep_seconds
        self.rate_limit_disable = rate_limit_disable
        self.output_dir = output_dir
        self.stats = AuditStats()
        self.data = AuditData()
        self.thread_lock = threading.Lock()

    def audit_cluster(self, namespace_path: str = ""):
        logger.info("Starting Vault cluster audit")
        self.stats.start()

        try:
            cluster_name = self.vault_client.validate_connection()

            path_queue: queue.Queue[str] = queue.Queue()
            initial_namespace = namespace_path if namespace_path != "/" else ""
            path_queue.put(initial_namespace)

            workers = []
            for i in range(self.worker_threads):
                worker_thread = threading.Thread(
                    target=self._worker,
                    args=(path_queue,),
                    name=f"VaultWorker-{i + 1}"
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
            self._write_reports(cluster_name)
            self._log_summary()

        except VaultConnectionError as e:
            logger.error(f"Vault connection failed: {e}")
        except Exception as e:
            logger.exception(f"An unexpected error occurred during the audit: {e}")

    def _worker(self, path_queue: queue.Queue[str]):
        while True:
            try:
                namespace_path = path_queue.get(timeout=300)
                if namespace_path is None:
                    break

                if not self.rate_limit_disable and self.stats.processed_count > 0 and self.stats.processed_count % self.rate_limit_batch_size == 0:
                    logger.info(f"Rate limiting - sleeping for {self.rate_limit_sleep_seconds} seconds")
                    time.sleep(self.rate_limit_sleep_seconds)

                self._traverse_namespace(namespace_path, path_queue)

            except queue.Empty:
                continue
            except Exception as e:
                logger.exception(f"Error in worker thread: {e}")
                self.stats.increment_errors()
            finally:
                path_queue.task_done()

    def _traverse_namespace(self, namespace_path: str, path_queue: queue.Queue[str]):
        display_path = "root" if namespace_path == "" else namespace_path
        logger.info(f"Processing namespace: {display_path}")
        self.stats.increment_processed()

        try:
            with self.vault_client.get_client(namespace_path) as client:
                auth_methods = client.sys.list_auth_methods()['data']
                secret_engines = client.sys.list_mounted_secrets_engines()['data']
                
                with self.thread_lock:
                    # Store namespace_path without trailing slash if not root
                    stored_namespace_path = namespace_path.rstrip('/') if namespace_path != "" else ""
                    self.data.auth_methods[stored_namespace_path] = auth_methods
                    self.data.secret_engines[stored_namespace_path] = secret_engines

                try:
                    raw_namespaces_response = client.sys.list_namespaces()
                    logger.debug(f"Raw namespaces response for {display_path}: {raw_namespaces_response}")
                    child_namespaces = raw_namespaces_response['data']['key_info']
                    if child_namespaces:
                        logger.debug(f"Found child namespaces in {display_path}: {list(child_namespaces.keys())}")
                    for name, info in child_namespaces.items():
                        # Construct child_path: if parent is root (""), child is like "bu01/", else "parent/bu01/"
                        child_path_full = f"{namespace_path}{name}"
                        
                        logger.debug(f"Constructed child_path_full: {child_path_full}")
                        path_queue.put(child_path_full) # Put full path with trailing slash for API calls
                        with self.thread_lock:
                            self.data.namespaces[child_path_full.rstrip('/')] = info
                except hvac.exceptions.InvalidPath:
                    pass # No child namespaces
                except hvac.exceptions.InvalidPath:
                    pass # No child namespaces

        except hvac.exceptions.Forbidden:
            logger.warning(f"Permission denied for namespace: {display_path}")
            self.stats.increment_errors()
        except Exception as e:
            logger.error(f"Error processing namespace {display_path}: {e}")
            self.stats.increment_errors()

    def _write_reports(self, cluster_name: str):
        date_str = datetime.now().strftime("%Y%m%d")
        import os
        os.makedirs(self.output_dir, exist_ok=True)

        # Write JSON files
        write_json(f"{self.output_dir}/{cluster_name}-namespaces-{date_str}.json", self.data.namespaces)
        write_json(f"{self.output_dir}/{cluster_name}-auth-methods-{date_str}.json", self.data.auth_methods)
        write_json(f"{self.output_dir}/{cluster_name}-secrets-engines-{date_str}.json", self.data.secret_engines)

        # Write CSV summaries
        self._write_namespace_summary(f"{self.output_dir}/{cluster_name}-summary-namespaces-{date_str}.csv")
        self._write_auth_methods_summary(f"{self.output_dir}/{cluster_name}-summary-auth-methods-{date_str}.csv")
        self._write_secrets_engines_summary(f"{self.output_dir}/{cluster_name}-summary-secrets-engines-{date_str}.csv")

    def _write_namespace_summary(self, file_path: str):
        if not self.data.namespaces:
            return
        df = pd.DataFrame.from_dict(self.data.namespaces, orient='index')
        df['path'] = df.index
        df = df[['path', 'id', 'custom_metadata']]
        write_csv(file_path, df.to_dict('records'), df.columns.tolist())

    def _write_auth_methods_summary(self, file_path: str):
        self._write_item_summary(file_path, self.data.auth_methods, "auth_methods")

    def _write_secrets_engines_summary(self, file_path: str):
        self._write_item_summary(file_path, self.data.secret_engines, "secrets_engines")

    def _write_item_summary(self, file_path: str, data: Dict[str, Any], item_type: str):
        rows = []
        for namespace, items in data.items():
            row = {'namespace': namespace}
            for item_name, item_data in items.items():
                type_key = item_data.get('type')
                if type_key:
                    row[type_key] = row.get(type_key, 0) + 1
            rows.append(row)
        
        if not rows:
            return

        df = pd.DataFrame(rows)
        df = df.fillna(0)
        # Convert numeric columns to int to avoid float output in CSV
        numeric_columns = df.select_dtypes(include=['float64']).columns
        df[numeric_columns] = df[numeric_columns].astype('int64')
        write_csv(file_path, df.to_dict('records'), df.columns.tolist())

    def _log_summary(self):
        duration = self.stats.duration
        logger.info("Audit finished.")
        logger.info(f"Processed {self.stats.processed_count} namespaces in {duration:.2f} seconds.")
        if self.stats.error_count > 0:
            logger.warning(f"Encountered {self.stats.error_count} errors.")




    

    
