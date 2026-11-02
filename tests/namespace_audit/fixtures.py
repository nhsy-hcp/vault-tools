"""Improved fixtures for namespace audit tests."""

import urllib.parse
from contextlib import contextmanager
from unittest.mock import MagicMock, Mock

import pytest

from src.common import vault_http
from src.common.vault_client import ConnectionInfo, VaultClient
from src.namespace_audit.main import NamespaceAuditor

# Every endpoint the namespace walk reads, keyed by (operation, path). A path
# ending in "/*" takes the last segment as its one argument: a policy name.
DEFAULT_ROUTES = {
    ("read", "sys/auth"): {"data": {}},
    ("read", "sys/mounts"): {"data": {}},
    ("list", "sys/namespaces"): {"data": {"key_info": {}}},
    ("list", "sys/policies/acl"): {"data": {"keys": []}},
    ("list", "sys/policies/egp"): {"data": {"keys": []}},
    ("list", "sys/policies/rgp"): {"data": {"keys": []}},
    ("read", "sys/policies/acl/*"): {"data": {"name": "", "policy": ""}},
    ("read", "sys/policies/egp/*"): {"data": {}},
    ("read", "sys/policies/rgp/*"): {"data": {}},
}


class FakeVault:
    """Stands in for NamespacedClient: ``read``/``list`` route by path to one Mock per endpoint.

    Configure or inspect an endpoint through ``at(op, path)``, e.g.
    ``client.at("list", "sys/policies/egp").side_effect = vault_http.Forbidden()``
    or ``client.at("read", "sys/policies/acl/*").call_count``. Any path without a
    route raises InvalidPath: that keeps the cluster health collector's reads
    inert ("not applicable"), so no health finding fires in unrelated tests.
    """

    def __init__(self, routes):
        self.endpoints = {}
        for key, value in routes.items():
            endpoint = Mock()
            endpoint.return_value = value
            self.endpoints[key] = endpoint
        self.read = Mock(side_effect=lambda path, params=None: self._call("read", path))
        self.list = Mock(side_effect=lambda path: self._call("list", path))

    def at(self, op, path):
        return self.endpoints[(op, path)]

    def _call(self, op, path):
        if (op, path) in self.endpoints:
            return self.endpoints[(op, path)]()
        prefix, _, name = path.rpartition("/")
        if (op, f"{prefix}/*") in self.endpoints:
            return self.endpoints[(op, f"{prefix}/*")](urllib.parse.unquote(name))
        raise vault_http.InvalidPath()


def make_vault_client_mock(routes=None):
    """A FakeVault with every endpoint the traversal reads stubbed.

    Use this rather than a bare ``Mock()``: an unstubbed read returns a Mock,
    and ``Mock`` has no ``__getitem__``, so the collector's ``[...]["keys"]``
    raises TypeError and the traversal records a spurious error. Stubbing
    centrally means adding a collector does not break every test in this
    package, so add every new collector endpoint to DEFAULT_ROUTES.

    ``routes`` overrides endpoints by (op, path), e.g.
    ``make_vault_client_mock({("list", "sys/namespaces"): {"data": {"key_info": {}}}})``.
    """
    return FakeVault({**DEFAULT_ROUTES, **(routes or {})})


def as_context_manager(client):
    """Wrap a fake client the way VaultClient.get_client yields it."""
    manager = MagicMock()
    manager.__enter__.return_value = client
    manager.__exit__.return_value = None
    return manager


@pytest.fixture
def mock_vault_client():
    """Create a properly configured mock VaultClient."""
    client = Mock(spec=VaultClient)

    # Set explicitly: vault_addr is assigned in VaultClient.__init__, so a
    # spec'd Mock does not carry it and every read raises AttributeError.
    client.vault_addr = "https://vault.example.com:8200"

    # Mock validate_connection method
    client.validate_connection.return_value = ConnectionInfo("test-cluster", "1.17.0+ent", True, "d33099d9-206e-53c2-4e50-44fb62ac69a6")

    fake = make_vault_client_mock(
        {
            ("read", "sys/auth"): {"data": {"userpass/": {"type": "userpass"}}},
            ("read", "sys/mounts"): {"data": {"secret/": {"type": "kv"}}},
            ("list", "sys/namespaces"): {"data": {"key_info": {"team-a/": {"id": "123"}}}},
        }
    )
    client.get_client.return_value = as_context_manager(fake)

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
