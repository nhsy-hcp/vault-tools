"""Simple integration tests for NamespaceAuditor."""
from unittest.mock import Mock, patch

import pytest

from src.namespace_audit.main import NamespaceAuditor
from src.common.vault_client import VaultConnectionError
from .fixtures import mock_vault_client


class TestBasicIntegration:
    """Basic integration tests that don't involve complex threading."""

    def test_basic_audit_workflow_components(self, mock_vault_client):
        """Test that all basic components work together."""
        auditor = NamespaceAuditor(mock_vault_client)
        
        # Test initialization
        assert auditor.vault_client == mock_vault_client
        assert auditor.stats.processed_count == 0
        assert auditor.stats.error_count == 0
        
        # Test basic statistics
        auditor.stats.start()
        auditor.stats.increment_processed()
        auditor.stats.increment_errors()
        auditor.stats.finish()
        
        assert auditor.stats.processed_count == 1
        assert auditor.stats.error_count == 1
        assert auditor.stats.duration is not None

    def test_data_collection_workflow(self, mock_vault_client):
        """Test the data collection and storage workflow."""
        auditor = NamespaceAuditor(mock_vault_client)
        
        # Simulate data collection with proper structure
        auditor.data.namespaces['test/'] = {'id': '123', 'custom_metadata': {}}
        auditor.data.auth_methods['test/'] = {'userpass/': {'type': 'userpass'}}
        auditor.data.secret_engines['test/'] = {'secret/': {'type': 'kv'}}
        
        # Verify data storage
        assert len(auditor.data.namespaces) == 1
        assert len(auditor.data.auth_methods) == 1
        assert len(auditor.data.secret_engines) == 1
        
        # Test report generation
        with patch('src.namespace_audit.main.write_json'), \
             patch('src.namespace_audit.main.write_csv'), \
             patch('os.makedirs'):
            # Should not raise exceptions
            auditor._write_reports('test-cluster')

    def test_error_handling_integration(self, mock_vault_client):
        """Test error handling across components."""
        auditor = NamespaceAuditor(mock_vault_client)
        
        # Test connection error handling
        mock_vault_client.validate_connection.side_effect = VaultConnectionError("Test error")
        
        # Should handle error gracefully
        auditor.audit_cluster()
        mock_vault_client.validate_connection.assert_called_once()

    def test_configuration_integration(self, mock_vault_client):
        """Test different configuration combinations work together."""
        # Test with custom configuration
        auditor = NamespaceAuditor(
            mock_vault_client,
            worker_threads=1,
            rate_limit_disable=True,
            rate_limit_batch_size=50,
            rate_limit_sleep_seconds=1
        )
        
        assert auditor.worker_threads == 1
        assert auditor.rate_limit_disable is True
        assert auditor.rate_limit_batch_size == 50
        assert auditor.rate_limit_sleep_seconds == 1
        
        # Verify all components still work
        auditor.stats.start()
        auditor.stats.finish()
        assert auditor.stats.duration is not None


@pytest.mark.unit
class TestComponentInteractions:
    """Test interactions between different components."""

    def test_stats_and_data_interaction(self, mock_vault_client):
        """Test that stats and data collection work together."""
        auditor = NamespaceAuditor(mock_vault_client)
        
        # Simulate processing multiple namespaces
        namespaces = ['ns1/', 'ns2/', 'ns3/']
        
        auditor.stats.start()
        for ns in namespaces:
            auditor.stats.increment_processed()
            auditor.data.namespaces[ns] = {'id': f'id-{ns}'}
            auditor.data.auth_methods[ns] = {'token/': {'type': 'token'}}
            auditor.data.secret_engines[ns] = {'kv/': {'type': 'kv'}}
        
        auditor.stats.finish()
        
        # Verify consistency
        assert auditor.stats.processed_count == len(namespaces)
        assert len(auditor.data.namespaces) == len(namespaces)
        assert len(auditor.data.auth_methods) == len(namespaces)
        assert len(auditor.data.secret_engines) == len(namespaces)

    def test_thread_safety_components(self, mock_vault_client):
        """Test that thread-safe components work correctly."""
        auditor = NamespaceAuditor(mock_vault_client)
        
        # Test thread lock exists
        assert auditor.thread_lock is not None
        
        # Test stats thread safety
        with auditor.thread_lock:
            auditor.stats.increment_processed()
            auditor.data.namespaces['test/'] = {'id': '123'}
        
        assert auditor.stats.processed_count == 1
        assert 'test/' in auditor.data.namespaces

    def test_vault_client_integration(self, mock_vault_client):
        """Test VaultClient integration with auditor."""
        auditor = NamespaceAuditor(mock_vault_client)
        
        # Test client configuration
        assert auditor.vault_client == mock_vault_client
        
        # Test client method calls
        mock_vault_client.validate_connection.return_value = 'test-cluster'
        result = auditor.vault_client.validate_connection()
        assert result == 'test-cluster'
        
        # Test client context manager
        assert auditor.vault_client.get_client is not None