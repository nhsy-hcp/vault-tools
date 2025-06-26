"""Shared test fixtures and configuration."""
import sys
import os
import pytest

# Add the parent directory to Python path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Import fixtures from the new fixtures module
from .fixtures import mock_vault_client, auditor, sample_audit_data, populated_auditor, mock_threading

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

@pytest.fixture
def temp_dir():
    """Provide a temporary directory for file operations."""
    import tempfile
    from pathlib import Path
    with tempfile.TemporaryDirectory() as tmp_dir:
        yield Path(tmp_dir)