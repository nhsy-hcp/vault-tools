"""Integration tests for NamespaceAuditor."""
import tempfile
from pathlib import Path
from unittest.mock import Mock, patch

import pytest

from src.namespace_audit.main import NamespaceAuditor
from src.common.vault_client import VaultClient, VaultConnectionError
from .fixtures import mock_vault_client, mock_threading


class TestAuditClusterIntegration:
    """Integration tests for the full audit_cluster workflow."""

    def test_audit_cluster_success(self, mock_vault_client, mock_threading):
        """Test successful cluster audit."""
        auditor = NamespaceAuditor(mock_vault_client)
        mock_vault_client.validate_connection.return_value = 'test-cluster'
        mock_thread, mock_queue = mock_threading
        
        with patch.object(auditor, '_write_reports') as mock_write_reports:
            auditor.audit_cluster()

            mock_vault_client.validate_connection.assert_called_once()
            mock_write_reports.assert_called_once_with('test-cluster')

    def test_audit_cluster_connection_failure(self, mock_vault_client):
        """Test cluster audit with connection failure."""
        auditor = NamespaceAuditor(mock_vault_client)
        mock_vault_client.validate_connection.side_effect = VaultConnectionError("Connection failed")

        auditor.audit_cluster()

        # Assert that validate_connection was called
        mock_vault_client.validate_connection.assert_called_once()

    def test_audit_cluster_keyboard_interrupt(self, mock_vault_client):
        """Test cluster audit with keyboard interrupt."""
        auditor = NamespaceAuditor(mock_vault_client)
        mock_vault_client.validate_connection.side_effect = KeyboardInterrupt()

        # KeyboardInterrupt should be allowed to escape audit_cluster
        with pytest.raises(KeyboardInterrupt):
            auditor.audit_cluster()

        # Assert that validate_connection was called
        mock_vault_client.validate_connection.assert_called_once()

    def test_audit_cluster_with_custom_namespace(self, mock_vault_client, mock_threading):
        """Test audit starting from a custom namespace."""
        auditor = NamespaceAuditor(mock_vault_client)
        mock_vault_client.validate_connection.return_value = 'test-cluster'
        mock_thread, mock_queue = mock_threading
        
        with patch.object(auditor, '_write_reports') as mock_write_reports:
            auditor.audit_cluster("custom/namespace/")

            mock_vault_client.validate_connection.assert_called_once()
            mock_write_reports.assert_called_once_with('test-cluster')


class TestEndToEndWorkflow:
    """End-to-end workflow tests."""

    @pytest.fixture
    def temp_dir(self):
        """Provide a temporary directory for file operations."""
        with tempfile.TemporaryDirectory() as tmp_dir:
            yield Path(tmp_dir)

    def test_minimal_audit_workflow(self, mock_vault_client, temp_dir, mock_threading):
        """Test a minimal audit workflow."""
        auditor = NamespaceAuditor(mock_vault_client, worker_threads=1)
        mock_vault_client.validate_connection.return_value = 'test-cluster'
        mock_thread, mock_queue = mock_threading
        
        # Set up minimal test data
        auditor.data.namespaces = {'test/': {'id': '123', 'custom_metadata': {}}}
        auditor.data.auth_methods = {'test/': {'userpass/': {'type': 'userpass'}}}
        auditor.data.secret_engines = {'test/': {'secret/': {'type': 'kv'}}}
        
        # Mock file operations to write to temp directory
        with patch('src.namespace_audit.main.write_json') as mock_write_json, \
             patch('src.namespace_audit.main.write_csv') as mock_write_csv, \
             patch('os.makedirs'):
            
            auditor.audit_cluster()
            
            # Verify the workflow completed
            mock_vault_client.validate_connection.assert_called_once()
            assert mock_write_json.call_count == 3
            assert mock_write_csv.call_count == 3

    def test_error_recovery_workflow(self, mock_vault_client, mock_threading):
        """Test that the auditor handles and recovers from errors."""
        auditor = NamespaceAuditor(mock_vault_client)
        mock_thread, mock_queue = mock_threading
        
        # Simulate various error conditions
        mock_vault_client.validate_connection.return_value = 'test-cluster'
        
        # Test error handling during report writing
        with patch.object(auditor, '_write_reports', side_effect=Exception("Write failed")):
            # Should not raise exception despite write failure
            auditor.audit_cluster()
            
            mock_vault_client.validate_connection.assert_called_once()


class TestConfigurationVariations:
    """Test different configuration variations."""

    def test_single_threaded_audit(self, mock_vault_client, mock_threading):
        """Test audit with single worker thread."""
        auditor = NamespaceAuditor(mock_vault_client, worker_threads=1)
        assert auditor.worker_threads == 1
        mock_thread, mock_queue = mock_threading
        
        # Should work with single thread
        mock_vault_client.validate_connection.return_value = 'test-cluster'
        with patch.object(auditor, '_write_reports'):
            auditor.audit_cluster()
            # Should create exactly one worker thread
            assert mock_thread.call_count == 1

    def test_multi_threaded_audit(self, mock_vault_client, mock_threading):
        """Test audit with multiple worker threads."""
        auditor = NamespaceAuditor(mock_vault_client, worker_threads=4)
        assert auditor.worker_threads == 4
        mock_thread, mock_queue = mock_threading
        
        mock_vault_client.validate_connection.return_value = 'test-cluster'
        with patch.object(auditor, '_write_reports'):
            auditor.audit_cluster()
            # Should create exactly four worker threads
            assert mock_thread.call_count == 4

    def test_rate_limiting_configuration(self, mock_vault_client):
        """Test different rate limiting configurations."""
        # Test with rate limiting disabled
        auditor_no_limit = NamespaceAuditor(mock_vault_client, rate_limit_disable=True)
        assert auditor_no_limit.rate_limit_disable is True
        
        # Test with custom rate limiting
        auditor_custom = NamespaceAuditor(
            mock_vault_client,
            rate_limit_disable=False,
            rate_limit_batch_size=50,
            rate_limit_sleep_seconds=2
        )
        assert auditor_custom.rate_limit_disable is False
        assert auditor_custom.rate_limit_batch_size == 50
        assert auditor_custom.rate_limit_sleep_seconds == 2


@pytest.mark.slow
class TestPerformanceCharacteristics:
    """Performance and stress tests."""

    def test_statistics_tracking_accuracy(self, mock_vault_client):
        """Test that statistics are tracked accurately."""
        auditor = NamespaceAuditor(mock_vault_client)
        
        # Simulate processing and errors
        auditor.stats.start()
        
        for _ in range(10):
            auditor.stats.increment_processed()
            
        for _ in range(3):
            auditor.stats.increment_errors()
            
        auditor.stats.finish()
        
        assert auditor.stats.processed_count == 10
        assert auditor.stats.error_count == 3
        assert auditor.stats.duration is not None
        assert auditor.stats.duration > 0

    def test_large_data_handling(self, mock_vault_client):
        """Test handling of large amounts of audit data."""
        auditor = NamespaceAuditor(mock_vault_client)
        
        # Simulate large dataset
        for i in range(1000):
            namespace = f"namespace-{i}/"
            auditor.data.namespaces[namespace] = {'id': str(i), 'custom_metadata': {}}
            auditor.data.auth_methods[namespace] = {'userpass/': {'type': 'userpass'}}
            auditor.data.secret_engines[namespace] = {'secret/': {'type': 'kv'}}
        
        # Should handle large datasets without issues
        assert len(auditor.data.namespaces) == 1000
        assert len(auditor.data.auth_methods) == 1000
        assert len(auditor.data.secret_engines) == 1000
        
        # Test report generation with large dataset
        with patch('src.namespace_audit.main.write_json'), \
             patch('src.namespace_audit.main.write_csv'), \
             patch('os.makedirs'):
            
            # Should not raise exceptions with large dataset
            auditor._write_reports('large-cluster')