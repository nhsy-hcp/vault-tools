"""Centralized fixtures for activity_export tests."""
import pytest
from unittest.mock import Mock, MagicMock
from src.common.vault_client import VaultClient


@pytest.fixture
def mock_vault_client():
    """Create a properly configured mock VaultClient."""
    client = Mock(spec=VaultClient)
    
    # Create a mock context manager for get_client
    mock_context_manager = MagicMock()
    mock_hvac_client = Mock()
    
    mock_context_manager.__enter__.return_value = mock_hvac_client
    mock_context_manager.__exit__.return_value = None
    client.get_client.return_value = mock_context_manager
    
    # Mock the get method for activity data
    client.get = Mock(return_value={})
    
    return client


@pytest.fixture
def sample_activity_data():
    """Sample activity data for testing."""
    return {
        "by_namespace": [
            {
                "namespace_id": "root",
                "namespace_path": "",
                "counts": {"clients": 5, "entity_clients": 4, "non_entity_clients": 1},
                "mounts": [
                    {
                        "mount_path": "auth/token/",
                        "counts": {"clients": 3, "entity_clients": 2, "non_entity_clients": 1}
                    }
                ]
            }
        ],
        "total": {"clients": 5, "entity_clients": 4, "non_entity_clients": 1},
        "start_time": "2024-01-01T00:00:00Z"
    }


@pytest.fixture
def sample_namespace_csv_data():
    """Sample namespace CSV data for testing."""
    return [
        ['namespace_id', 'namespace_path', 'mounts', 'clients', 'entity_clients', 'non_entity_clients'],
        ['root', '', '1', '5', '4', '1']
    ]


@pytest.fixture
def sample_mounts_csv_data():
    """Sample mounts CSV data for testing."""
    return [
        ['namespace_id', 'namespace_path', 'mount_path', 'clients', 'entity_clients', 'non_entity_clients'],
        ['root', '', 'auth/token/', '3', '2', '1']
    ]
