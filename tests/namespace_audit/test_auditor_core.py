"""Unit tests for NamespaceAuditor core functionality."""

import logging
import queue
import threading
from unittest.mock import Mock, patch

import pytest

from src.common.vault_client import VaultConnectionError
from src.namespace_audit.main import AuditData, AuditStats, NamespaceAuditor

from .fixtures import mock_file_operations


class TestNamespaceAuditorInitialization:
    """Test NamespaceAuditor initialization and basic properties."""

    def test_auditor_initialization(self, mock_vault_client):
        """Test auditor initialization."""
        auditor = NamespaceAuditor(mock_vault_client)

        assert auditor.vault_client == mock_vault_client
        assert isinstance(auditor.stats, AuditStats)
        assert isinstance(auditor.data, AuditData)
        assert isinstance(auditor.thread_lock, type(threading.Lock()))

    def test_auditor_configuration_defaults(self, mock_vault_client):
        """Test auditor default configuration values."""
        auditor = NamespaceAuditor(mock_vault_client)

        assert auditor.worker_threads == 4
        assert auditor.rate_limit_batch_size == 100
        assert auditor.rate_limit_sleep_seconds == 3
        assert auditor.rate_limit_disable is False

    def test_auditor_custom_configuration(self, mock_vault_client):
        """Test auditor with custom configuration."""
        auditor = NamespaceAuditor(
            mock_vault_client,
            worker_threads=8,
            rate_limit_batch_size=50,
            rate_limit_sleep_seconds=5,
            rate_limit_disable=True,
        )

        assert auditor.worker_threads == 8
        assert auditor.rate_limit_batch_size == 50
        assert auditor.rate_limit_sleep_seconds == 5
        assert auditor.rate_limit_disable is True


class TestVaultConnectionHandling:
    """Test Vault connection validation and error handling."""

    def test_validate_vault_connection_success(self, auditor):
        """Test successful Vault connection validation."""
        auditor.vault_client.validate_connection.return_value = "test-cluster"

        result = auditor.vault_client.validate_connection()

        assert result == "test-cluster"
        auditor.vault_client.validate_connection.assert_called_once()

    def test_validate_vault_connection_sealed(self, auditor):
        """Test Vault connection validation with sealed cluster."""
        auditor.vault_client.validate_connection.side_effect = VaultConnectionError("Vault cluster is sealed")

        with pytest.raises(VaultConnectionError, match="Vault cluster is sealed"):
            auditor.vault_client.validate_connection()

    def test_validate_vault_connection_not_authenticated(self, auditor):
        """Test Vault connection validation with unauthenticated client."""
        auditor.vault_client.validate_connection.side_effect = VaultConnectionError("Vault client is not authenticated")

        with pytest.raises(VaultConnectionError, match="not authenticated"):
            auditor.vault_client.validate_connection()


class TestRateLimiting:
    """Test rate limiting functionality."""

    def test_rate_limit_disabled(self, auditor):
        """Test rate limiting when disabled."""
        auditor.rate_limit_disable = True
        auditor.stats.processed_count = 100

        assert auditor.rate_limit_disable is True

    def test_rate_limit_enabled(self, auditor):
        """Test rate limiting when enabled."""
        auditor.rate_limit_disable = False
        auditor.rate_limit_batch_size = 10

        auditor.stats.processed_count = 10
        assert auditor.rate_limit_disable is False

        auditor.stats.processed_count = 5
        assert auditor.rate_limit_disable is False

    @patch("time.sleep")
    def test_apply_rate_limit(self, mock_sleep, auditor):
        """Rate limiting fires on a batch boundary during traversal."""
        auditor.rate_limit_sleep_seconds = 2
        auditor.rate_limit_disable = False
        auditor.rate_limit_batch_size = 1

        # The rate-limit check runs before any Vault call, so a mock client
        # is enough — get_client failing is caught by _traverse_namespace.
        auditor._traverse_namespace("/test/", queue.Queue())

        mock_sleep.assert_called_with(2)

    @patch("time.sleep")
    def test_rate_limit_uses_incremented_count(self, mock_sleep, auditor):
        """The batch boundary is evaluated against the post-increment count.

        Regression test for the check-then-act race: the count must come from
        increment_processed()'s return value so each boundary is observed
        exactly once, by exactly one thread.
        """
        auditor.rate_limit_disable = False
        auditor.rate_limit_batch_size = 3
        auditor.rate_limit_sleep_seconds = 7
        q = queue.Queue()

        for _ in range(3):
            auditor._traverse_namespace("/test/", q)

        # Counts 1 and 2 must not sleep; count 3 must, exactly once.
        assert auditor.stats.processed_count == 3
        mock_sleep.assert_called_once_with(7)

    @patch("time.sleep")
    def test_rate_limit_disabled_never_sleeps(self, mock_sleep, auditor):
        """No sleep when rate limiting is turned off, even on a boundary."""
        auditor.rate_limit_disable = True
        auditor.rate_limit_batch_size = 1

        auditor._traverse_namespace("/test/", queue.Queue())

        mock_sleep.assert_not_called()


class TestAuditSummaryLogging:
    """Test audit summary and logging functionality."""

    def test_log_audit_summary(self, auditor, caplog):
        """Test audit summary logging."""
        with caplog.at_level(logging.INFO):
            auditor.stats.processed_count = 10
            auditor.stats.error_count = 2
            auditor.stats.start()
            auditor.stats.finish()

            auditor._log_summary()

            assert "Audit finished." in caplog.text
            assert "Processed 10 namespaces" in caplog.text
            assert "Encountered 2 errors." in caplog.text


class TestReportGeneration:
    """Test report generation functionality."""

    def test_write_reports(self, auditor):
        """Test writing JSON and CSV files."""
        # Set up proper data structure that matches what the code expects
        auditor.data.namespaces = {"test/": {"id": "123", "custom_metadata": {}}}
        auditor.data.auth_methods = {"test/": {"userpass/": {"type": "userpass"}}}
        auditor.data.secret_engines = {"test/": {"secret/": {"type": "kv"}}}

        with mock_file_operations() as (mock_write_json, mock_write_csv):
            auditor._write_reports("test-cluster")

            # Verify files were written
            assert mock_write_json.call_count == 3
            assert mock_write_csv.call_count == 3


class TestProgressTracking:
    """N4: the bar must show real progress, not an indeterminate spinner.

    total=None rendered a spinner with no completion signal — and nothing ever
    called Progress.update, so even the spinner never advanced.
    """

    def test_discovered_count_starts_at_root(self, auditor):
        assert auditor.stats.discovered_count == 1

    def test_add_discovered_is_atomic_and_returns_total(self, auditor):
        assert auditor.stats.add_discovered(3) == 4
        assert auditor.stats.add_discovered(2) == 6

    def test_add_discovered_is_thread_safe(self, auditor):
        import threading

        def bump():
            for _ in range(100):
                auditor.stats.add_discovered(1)

        threads = [threading.Thread(target=bump) for _ in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert auditor.stats.discovered_count == 1 + 500

    def test_traversal_updates_progress(self, auditor):
        """_traverse_namespace pushes counts to the bar."""
        auditor.progress = Mock()
        auditor.progress_task = "task-id"

        auditor._traverse_namespace("/test/", queue.Queue())

        auditor.progress.update.assert_called()
        kwargs = auditor.progress.update.call_args.kwargs
        assert kwargs["completed"] == auditor.stats.processed_count
        assert kwargs["total"] >= auditor.stats.discovered_count

    def test_refresh_progress_is_safe_before_bar_exists(self, auditor):
        """Workers may call this before/after the Progress context."""
        auditor.progress = None
        auditor.progress_task = None
        auditor._refresh_progress()  # must not raise

    def test_completed_never_exceeds_total(self, auditor):
        """The bar must never render past 100%.

        Discovery normally runs ahead of processing, but the counters are
        bumped at different points by different threads, so _refresh_progress
        clamps the denominator rather than trusting them to stay ordered.
        """
        auditor.progress = Mock()
        auditor.progress_task = "task-id"

        for _ in range(3):
            auditor._traverse_namespace("/test/", queue.Queue())
            kwargs = auditor.progress.update.call_args.kwargs
            assert kwargs["completed"] <= kwargs["total"]
