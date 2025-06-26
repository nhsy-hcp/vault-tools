"""Tests for namespace traversal functionality."""
import queue
from unittest.mock import Mock, MagicMock

import pytest
import hvac

from .fixtures import mock_vault_client, auditor


class TestNamespaceDataFetching:
    """Test fetching data from individual namespaces."""

    def test_fetch_namespace_data_success(self, auditor):
        """Test successful namespace data fetch."""
        # Create a proper context manager mock
        mock_hvac_client = Mock()
        mock_hvac_client.sys.list_auth_methods.return_value = {'data': {'userpass/': {'type': 'userpass'}}}
        mock_hvac_client.sys.list_mounted_secrets_engines.return_value = {'data': {'secret/': {'type': 'kv'}}}
        mock_hvac_client.sys.list_namespaces.return_value = {'data': {'key_info': {'team-a/': {'id': '123'}}}}
        
        # Mock the context manager properly using MagicMock to support magic methods
        mock_context_manager = MagicMock()
        mock_context_manager.__enter__.return_value = mock_hvac_client
        mock_context_manager.__exit__.return_value = None
        auditor.vault_client.get_client.return_value = mock_context_manager

        path_queue = queue.Queue()
        auditor._traverse_namespace("test/", path_queue)

        assert "test" in auditor.data.auth_methods
        assert "test" in auditor.data.secret_engines
        assert "test/team-a" in auditor.data.namespaces

    def test_fetch_namespace_data_invalid_path(self, auditor):
        """Test namespace data fetch with invalid path."""
        mock_hvac_client = Mock()
        mock_hvac_client.sys.list_auth_methods.return_value = {'data': {}}
        mock_hvac_client.sys.list_mounted_secrets_engines.return_value = {'data': {}}
        mock_hvac_client.sys.list_namespaces.side_effect = hvac.exceptions.InvalidPath()
        
        # Mock the context manager properly using MagicMock to support magic methods
        mock_context_manager = MagicMock()
        mock_context_manager.__enter__.return_value = mock_hvac_client
        mock_context_manager.__exit__.return_value = None
        auditor.vault_client.get_client.return_value = mock_context_manager

        path_queue = queue.Queue()
        auditor._traverse_namespace("test/", path_queue)

        assert "test" in auditor.data.auth_methods
        assert "test" in auditor.data.secret_engines
        assert path_queue.empty()  # Should be empty since no child namespaces were found

    def test_fetch_namespace_data_forbidden(self, auditor):
        """Test namespace data fetch with forbidden access."""
        mock_hvac_client = Mock()
        mock_hvac_client.sys.list_auth_methods.side_effect = hvac.exceptions.Forbidden()
        
        # Mock the context manager properly using MagicMock to support magic methods
        mock_context_manager = MagicMock()
        mock_context_manager.__enter__.return_value = mock_hvac_client
        mock_context_manager.__exit__.return_value = None
        auditor.vault_client.get_client.return_value = mock_context_manager

        path_queue = queue.Queue()
        auditor._traverse_namespace("test/", path_queue)

        assert "test/" not in auditor.data.auth_methods
        assert "test/" not in auditor.data.secret_engines
        assert auditor.stats.error_count == 1

    def test_traverse_namespace_error_handling(self, auditor):
        """Test error handling during namespace traversal."""
        # Mock an unexpected exception
        mock_hvac_client = Mock()
        mock_hvac_client.sys.list_auth_methods.side_effect = Exception("Unexpected error")
        
        mock_context_manager = MagicMock()
        mock_context_manager.__enter__.return_value = mock_hvac_client
        mock_context_manager.__exit__.return_value = None
        auditor.vault_client.get_client.return_value = mock_context_manager

        path_queue = queue.Queue()
        auditor._traverse_namespace("test/", path_queue)

        # Should increment error count for unexpected errors
        assert auditor.stats.error_count == 1
        assert "test/" not in auditor.data.auth_methods


class TestNamespacePathProcessing:
    """Test namespace path processing and child discovery."""

    def test_root_namespace_processing(self, auditor):
        """Test processing the root namespace."""
        mock_hvac_client = Mock()
        mock_hvac_client.sys.list_auth_methods.return_value = {'data': {'token/': {'type': 'token'}}}
        mock_hvac_client.sys.list_mounted_secrets_engines.return_value = {'data': {'sys/': {'type': 'system'}}}
        mock_hvac_client.sys.list_namespaces.return_value = {'data': {'key_info': {'prod/': {'id': '456'}}}}
        
        mock_context_manager = MagicMock()
        mock_context_manager.__enter__.return_value = mock_hvac_client
        mock_context_manager.__exit__.return_value = None
        auditor.vault_client.get_client.return_value = mock_context_manager

        path_queue = queue.Queue()
        auditor._traverse_namespace("/", path_queue)

        assert "" in auditor.data.auth_methods
        assert "" in auditor.data.secret_engines
        assert "/prod" in auditor.data.namespaces

    def test_nested_namespace_processing(self, auditor):
        """Test processing nested namespaces."""
        mock_hvac_client = Mock()
        mock_hvac_client.sys.list_auth_methods.return_value = {'data': {'ldap/': {'type': 'ldap'}}}
        mock_hvac_client.sys.list_mounted_secrets_engines.return_value = {'data': {'database/': {'type': 'database'}}}
        mock_hvac_client.sys.list_namespaces.return_value = {'data': {'key_info': {'dev/': {'id': '789'}}}}
        
        mock_context_manager = MagicMock()
        mock_context_manager.__enter__.return_value = mock_hvac_client
        mock_context_manager.__exit__.return_value = None
        auditor.vault_client.get_client.return_value = mock_context_manager

        path_queue = queue.Queue()
        auditor._traverse_namespace("prod/team-a/", path_queue)

        assert "prod/team-a" in auditor.data.auth_methods
        assert "prod/team-a" in auditor.data.secret_engines
        assert "prod/team-a/dev" in auditor.data.namespaces

    def test_empty_namespace_processing(self, auditor):
        """Test processing namespace with no auth methods or secret engines."""
        mock_hvac_client = Mock()
        mock_hvac_client.sys.list_auth_methods.return_value = {'data': {}}
        mock_hvac_client.sys.list_mounted_secrets_engines.return_value = {'data': {}}
        mock_hvac_client.sys.list_namespaces.side_effect = hvac.exceptions.InvalidPath()
        
        mock_context_manager = MagicMock()
        mock_context_manager.__enter__.return_value = mock_hvac_client
        mock_context_manager.__exit__.return_value = None
        auditor.vault_client.get_client.return_value = mock_context_manager

        path_queue = queue.Queue()
        auditor._traverse_namespace("empty/", path_queue)

        assert "empty" in auditor.data.auth_methods
        assert "empty" in auditor.data.secret_engines
        assert auditor.data.auth_methods["empty"] == {}
        assert auditor.data.secret_engines["empty"] == {}