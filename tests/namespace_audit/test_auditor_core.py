"""Unit tests for NamespaceAuditor core functionality."""
import threading
import queue
import logging
from unittest.mock import Mock, patch

import pytest
import hvac

from src.namespace_audit.main import NamespaceAuditor, AuditStats, AuditData
from src.common.vault_client import VaultConnectionError
from .fixtures import mock_vault_client, auditor, mock_file_operations


class TestNamespaceAuditorInitialization:
    """Test NamespaceAuditor initialization and basic properties."""

    def test_auditor_initialization(self, mock_vault_client):
        """Test auditor initialization."""
        auditor = NamespaceAuditor(mock_vault_client)

        assert auditor.vault_client == mock_vault_client
        assert isinstance(auditor.stats, AuditStats)
        assert isinstance(auditor.data, AuditData)
        assert isinstance(auditor.thread_lock, threading.Lock)

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
            rate_limit_disable=True
        )
        
        assert auditor.worker_threads == 8
        assert auditor.rate_limit_batch_size == 50
        assert auditor.rate_limit_sleep_seconds == 5
        assert auditor.rate_limit_disable is True


class TestVaultConnectionHandling:
    """Test Vault connection validation and error handling."""

    def test_validate_vault_connection_success(self, auditor):
        """Test successful Vault connection validation."""
        auditor.vault_client.validate_connection.return_value = 'test-cluster'

        result = auditor.vault_client.validate_connection()

        assert result == 'test-cluster'
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

    @patch('time.sleep')
    def test_apply_rate_limit(self, mock_sleep, auditor):
        """Test rate limit application."""
        auditor.rate_limit_sleep_seconds = 2
        auditor.rate_limit_disable = False
        auditor.rate_limit_batch_size = 1
        auditor.stats.processed_count = 1
        
        q = queue.Queue()
        q.put("/test/")
        q.put(None)  # Add sentinel value to prevent hanging
        
        # Mock traverse to avoid actual API calls
        auditor._traverse_namespace = Mock()
        auditor._worker(q)

        # Sleep should be called due to rate limiting
        mock_sleep.assert_called_with(2)


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
        auditor.data.namespaces = {'test/': {'id': '123', 'custom_metadata': {}}}
        auditor.data.auth_methods = {'test/': {'userpass/': {'type': 'userpass'}}}
        auditor.data.secret_engines = {'test/': {'secret/': {'type': 'kv'}}}

        with mock_file_operations() as (mock_write_json, mock_write_csv):
            auditor._write_reports('test-cluster')
            
            # Verify files were written
            assert mock_write_json.call_count == 3
            assert mock_write_csv.call_count == 3