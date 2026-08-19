"""Improved fixtures for namespace audit tests."""

from contextlib import contextmanager
from unittest.mock import MagicMock, Mock

import pytest

from src.common.vault_client import VaultClient
from src.namespace_audit.main import NamespaceAuditor


def make_hvac_client(**overrides):
    """Build a mock hvac client with every endpoint the traversal calls stubbed.

    Use this rather than a bare ``Mock()``: an unstubbed ``list_egp_policies()``
    returns a Mock, and ``Mock`` has no ``__getitem__``, so the collector's
    ``[...]["keys"]`` raises TypeError and the traversal records a spurious
    error. Stubbing centrally means adding a collector does not break every test
    in this package.

    Pass ``sys.``-prefixed names as keyword arguments to override one endpoint,
    e.g. ``make_hvac_client(list_namespaces={"data": {"key_info": {}}})``.
    """
    client = Mock()
    defaults = {
        "list_auth_methods": {"data": {}},
        "list_mounted_secrets_engines": {"data": {}},
        "list_namespaces": {"data": {"key_info": {}}},
        "list_egp_policies": {"data": {"keys": []}},
        "list_rgp_policies": {"data": {"keys": []}},
        "read_egp_policy": {"data": {}},
        "read_rgp_policy": {"data": {}},
    }
    for name, value in {**defaults, **overrides}.items():
        getattr(client.sys, name).return_value = value
    return client


def as_context_manager(hvac_client):
    """Wrap a mock hvac client the way VaultClient.get_client yields it."""
    manager = MagicMock()
    manager.__enter__.return_value = hvac_client
    manager.__exit__.return_value = None
    return manager


@pytest.fixture
def mock_vault_client():
    """Create a properly configured mock VaultClient."""
    client = Mock(spec=VaultClient)

    # Mock validate_connection method
    client.validate_connection.return_value = "test-cluster"

    # Mock cache statistics
    client.get_cache_stats = Mock(
        return_value={
            "hits": 0,
            "misses": 0,
            "total": 0,
            "hit_rate": "0.00%",
            "cache_size": 0,
            "cache_maxsize": 1000,
        }
    )

    # Create a mock context manager for get_client
    mock_context_manager = MagicMock()
    mock_hvac_client = Mock()

    # Set up default hvac client responses
    mock_hvac_client.sys.list_auth_methods.return_value = {"data": {"userpass/": {"type": "userpass"}}}
    mock_hvac_client.sys.list_mounted_secrets_engines.return_value = {"data": {"secret/": {"type": "kv"}}}
    mock_hvac_client.sys.list_namespaces.return_value = {"data": {"key_info": {"team-a/": {"id": "123"}}}}
    # Sentinel defaults are not optional: mock_hvac_client is a bare Mock, so an
    # unstubbed list_egp_policies() returns a Mock whose ["data"]["keys"] is
    # another Mock, which then fails to iterate — breaking every traversal test
    # rather than just the Sentinel ones. Empty keys is the common case anyway.
    mock_hvac_client.sys.list_egp_policies.return_value = {"data": {"keys": []}}
    mock_hvac_client.sys.list_rgp_policies.return_value = {"data": {"keys": []}}
    mock_hvac_client.sys.read_egp_policy.return_value = {"data": {}}
    mock_hvac_client.sys.read_rgp_policy.return_value = {"data": {}}

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
        "namespaces": {"test/": {"id": "123", "custom_metadata": {}}},
        "auth_methods": {"test/": {"userpass/": {"type": "userpass"}}},
        "secret_engines": {"test/": {"secret/": {"type": "kv"}}},
    }


@pytest.fixture
def populated_auditor(auditor, sample_audit_data):
    """Create an auditor with populated test data."""
    auditor.data.namespaces = sample_audit_data["namespaces"]
    auditor.data.auth_methods = sample_audit_data["auth_methods"]
    auditor.data.secret_engines = sample_audit_data["secret_engines"]
    return auditor


@contextmanager
def mock_file_operations():
    """Context manager to mock file operations.

    write_markdown is patched too — without it _write_reports would put a real
    report file on disk during unit tests. It is not yielded, so existing
    two-value unpacking at the call sites keeps working; assert on it by
    patching directly where a test needs to.
    """
    from unittest.mock import patch

    with (
        patch("src.namespace_audit.main.write_json") as mock_write_json,
        patch("src.namespace_audit.main.write_csv") as mock_write_csv,
        patch("src.namespace_audit.main.write_markdown"),
        patch("os.makedirs"),
    ):
        yield mock_write_json, mock_write_csv


@pytest.fixture
def mock_threading():
    """Mock threading operations to prevent hanging tests."""
    from unittest.mock import Mock, patch

    with patch("threading.Thread") as mock_thread, patch("queue.Queue") as mock_queue_class:
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
