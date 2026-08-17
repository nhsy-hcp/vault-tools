"""Pytest configuration and fixtures for namespace_audit tests."""

import os
import sys

# Add the parent directory to Python path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Import all fixtures from the fixtures module
import pytest

from tests.namespace_audit.fixtures import (
    auditor,
    mock_file_operations,
    mock_threading,
    mock_vault_client,
    populated_auditor,
    sample_audit_data,
)
from tests.namespace_audit.report_fixtures import (
    clean_data,
    denied_stats,
    finished_stats,
    flagged_data,
)


@pytest.fixture
def mock_vault_responses():
    """Mock Vault API responses for testing."""
    return {
        "health": {
            "cluster_name": "test-cluster",
            "sealed": False,
            "initialized": True,
        },
        "auth_methods": {
            "userpass/": {"type": "userpass"},
            "token/": {"type": "token"},
        },
        "secret_engines": {"secret/": {"type": "kv"}, "pki/": {"type": "pki"}},
        "namespaces": {"data": {"key_info": {"team-a/": {"id": "123"}, "team-b/": {"id": "456"}}}},
    }


@pytest.fixture
def temp_dir():
    """Provide a temporary directory for file operations."""
    import tempfile
    from pathlib import Path

    with tempfile.TemporaryDirectory() as tmp_dir:
        yield Path(tmp_dir)


__all__ = [
    "auditor",
    "clean_data",
    "denied_stats",
    "finished_stats",
    "flagged_data",
    "mock_file_operations",
    "mock_threading",
    "mock_vault_client",
    "mock_vault_responses",
    "populated_auditor",
    "sample_audit_data",
    "temp_dir",
]
