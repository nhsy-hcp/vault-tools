"""Shared test fixtures and configuration."""
import sys
import os
import pytest
from unittest.mock import Mock

# Add the parent directory to Python path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

@pytest.fixture
def mock_vault_client():
    """Mock Vault client for testing."""
    client = Mock()
    # Configure mock client with common responses
    client.sys.read_health_status.return_value = {
        'cluster_name': 'test-cluster',
        'sealed': False,
        'initialized': True
    }
    client.sys.is_sealed.return_value = False
    client.is_authenticated.return_value = True
    client.sys.is_initialized.return_value = True
    
    # Mock auth methods response
    client.sys.list_auth_methods.return_value = {
        'userpass/': {'type': 'userpass'},
        'token/': {'type': 'token'}
    }
    
    # Mock secret engines response
    client.sys.list_mounted_secrets_engines.return_value = {
        'secret/': {'type': 'kv'},
        'pki/': {'type': 'pki'}
    }
    
    # Mock namespaces response
    client.sys.list_namespaces.return_value = {
        'data': {
            'key_info': {
                'team-a/': {'id': '123'},
                'team-b/': {'id': '456'}
            }
        }
    }
    
    return client

@pytest.fixture
def sample_config():
    """Sample audit configuration for testing."""
    from main import AuditConfig
    return AuditConfig(
        vault_addr="https://vault.example.com",
        vault_token="test-token"
    )

@pytest.fixture
def mock_vault_responses():
    """Mock Vault API responses for testing."""
    return {
        'health': {
            'cluster_name': 'test-cluster',
            'sealed': False,
            'initialized': True
        },
        'auth_methods': {
            'userpass/': {'type': 'userpass'},
            'token/': {'type': 'token'}
        },
        'secret_engines': {
            'secret/': {'type': 'kv'},
            'pki/': {'type': 'pki'}
        },
        'namespaces': {
            'data': {
                'key_info': {
                    'team-a/': {'id': '123'},
                    'team-b/': {'id': '456'}
                }
            }
        }
    }