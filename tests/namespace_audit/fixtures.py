"""Improved fixtures for namespace audit tests."""
import pytest
from unittest.mock import Mock, MagicMock
from contextlib import contextmanager

from src.namespace_audit.main import NamespaceAuditor, AuditStats, AuditData
from src.common.vault_client import VaultClient


@pytest.fixture
def mock_vault_client():
    """Create a properly configured mock VaultClient."""
    client = Mock(spec=VaultClient)
    
    # Mock validate_connection method
    client.validate_connection.return_value = 'test-cluster'
    
    # Create a mock context manager for get_client
    mock_context_manager = MagicMock()
    mock_hvac_client = Mock()
    
    # Set up default hvac client responses
    mock_hvac_client.sys.list_auth_methods.return_value = {
        'data': {'userpass/': {'type': 'userpass'}}
    }
    mock_hvac_client.sys.list_mounted_secrets_engines.return_value = {
        'data': {'secret/': {'type': 'kv'}}
    }
    mock_hvac_client.sys.list_namespaces.return_value = {
        'data': {'key_info': {'team-a/': {'id': '123'}}}
    }
    
    mock_context_manager.__enter__.return_value = mock_hvac_client
    mock_context_manager.__exit__.return_value = None
    client.get_client.return_value = mock_context_manager
    
    return client


@pytest.fixture
def auditor(mock_vault_client):
    """Create a NamespaceAuditor instance with mocked dependencies."""
    return NamespaceAuditor(mock_vault_client)


@pytest.fixture
def sample_audit_data():
    """Provide sample audit data for testing."""
    return {
        'namespaces': {'test/': {'id': '123', 'custom_metadata': {}}},
        'auth_methods': {'test/': {'userpass/': {'type': 'userpass'}}},
        'secret_engines': {'test/': {'secret/': {'type': 'kv'}}}
    }


@pytest.fixture
def populated_auditor(auditor, sample_audit_data):
    """Create an auditor with populated test data."""
    auditor.data.namespaces = sample_audit_data['namespaces']
    auditor.data.auth_methods = sample_audit_data['auth_methods'] 
    auditor.data.secret_engines = sample_audit_data['secret_engines']
    return auditor


@contextmanager
def mock_file_operations():
    """Context manager to mock file operations."""
    from unittest.mock import patch
    with patch('src.namespace_audit.main.write_json') as mock_write_json, \
         patch('src.namespace_audit.main.write_csv') as mock_write_csv, \
         patch('os.makedirs'):
        yield mock_write_json, mock_write_csv


@pytest.fixture
def mock_threading():
    """Mock threading operations to prevent hanging tests."""
    from unittest.mock import patch, Mock
    
    with patch('threading.Thread') as mock_thread, \
         patch('queue.Queue') as mock_queue_class:
        
        # Mock Thread class
        mock_thread_instance = Mock()
        mock_thread.return_value = mock_thread_instance
        mock_thread_instance.start.return_value = None
        mock_thread_instance.join.return_value = None
        
        # Mock Queue class
        mock_queue_instance = Mock()
        mock_queue_class.return_value = mock_queue_instance
        mock_queue_instance.put.return_value = None
        mock_queue_instance.get.return_value = None
        mock_queue_instance.join.return_value = None
        mock_queue_instance.task_done.return_value = None
        
        yield mock_thread, mock_queue_instance