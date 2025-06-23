#!/usr/bin/env python3
"""
Comprehensive test suite for the Vault Audit Script.

This module contains unit tests, integration tests, and mock tests
for all components of the vault audit system.
"""
# from namespace_audit.summary import *
import json
import logging
import os
import queue
import tempfile
import threading
import time
from datetime import datetime
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock, mock_open
from contextlib import contextmanager

import pytest
import hvac

# Import the main module
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    from main import (
        AuditConfig, AuditStats, AuditData, VaultAuditor,
        VaultConnectionError, Constants, create_config_from_args,
        parse_arguments, main
    )
except ImportError:
    # Alternative import path for PyCharm or other IDEs
    parent_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    sys.path.insert(0, parent_dir)
    from main import (
        AuditConfig, AuditStats, AuditData, VaultAuditor,
        VaultConnectionError, Constants, create_config_from_args,
        parse_arguments, main
    )


class TestConstants:
    """Test the Constants class."""

    def test_constants_values(self):
        """Test that constants have expected values."""
        assert Constants.DEFAULT_WORKER_THREADS == 4
        assert Constants.DEFAULT_TIMEOUT == 3
        assert Constants.DEFAULT_BATCH_SIZE == 100
        assert Constants.DEFAULT_SLEEP_SECONDS == 3
        assert Constants.ROOT_NAMESPACE == "/"
        assert Constants.DATE_FORMAT == "%Y%m%d"


class TestAuditConfig:
    """Test the AuditConfig dataclass."""

    def test_valid_config_creation(self):
        """Test creating a valid configuration."""
        config = AuditConfig(
            vault_addr="https://vault.example.com",
            vault_token="test-token"
        )

        assert config.vault_addr == "https://vault.example.com"
        assert config.vault_token == "test-token"
        assert config.namespace_path == ""
        assert config.worker_threads == Constants.DEFAULT_WORKER_THREADS
        assert not config.vault_skip_verify
        assert not config.rate_limit_disable

    def test_namespace_path_normalization(self):
        """Test that namespace paths are normalized with trailing slash."""
        config = AuditConfig(
            vault_addr="https://vault.example.com",
            vault_token="test-token",
            namespace_path="team-a"
        )

        assert config.namespace_path == "team-a/"

    def test_empty_namespace_path(self):
        """Test that empty namespace path remains empty."""
        config = AuditConfig(
            vault_addr="https://vault.example.com",
            vault_token="test-token",
            namespace_path=""
        )

        assert config.namespace_path == ""

    def test_vault_tls_verify_property(self):
        """Test the vault_tls_verify property."""
        config_verify = AuditConfig(
            vault_addr="https://vault.example.com",
            vault_token="test-token",
            vault_skip_verify=False
        )
        assert config_verify.vault_tls_verify is True

        config_no_verify = AuditConfig(
            vault_addr="https://vault.example.com",
            vault_token="test-token",
            vault_skip_verify=True
        )
        assert config_no_verify.vault_tls_verify is False

    def test_invalid_config_missing_vault_addr(self):
        """Test validation fails when vault_addr is missing."""
        with pytest.raises(ValueError, match="VAULT_ADDR is required"):
            AuditConfig(vault_addr="", vault_token="test-token")

    def test_invalid_config_missing_vault_token(self):
        """Test validation fails when vault_token is missing."""
        with pytest.raises(ValueError, match="VAULT_TOKEN is required"):
            AuditConfig(vault_addr="https://vault.example.com", vault_token="")

    def test_invalid_config_negative_workers(self):
        """Test validation fails with negative worker threads."""
        with pytest.raises(ValueError, match="Worker threads must be positive"):
            AuditConfig(
                vault_addr="https://vault.example.com",
                vault_token="test-token",
                worker_threads=-1
            )

    def test_invalid_config_invalid_batch_size(self):
        """Test validation fails with invalid batch size."""
        with pytest.raises(ValueError, match="Rate limit batch size must be positive"):
            AuditConfig(
                vault_addr="https://vault.example.com",
                vault_token="test-token",
                rate_limit_batch_size=0
            )

    def test_invalid_config_invalid_timeout(self):
        """Test validation fails with invalid timeout."""
        with pytest.raises(ValueError, match="HVAC timeout must be positive"):
            AuditConfig(
                vault_addr="https://vault.example.com",
                vault_token="test-token",
                hvac_timeout=0
            )


class TestAuditStats:
    """Test the AuditStats dataclass."""

    def test_initial_stats(self):
        """Test initial statistics values."""
        stats = AuditStats()

        assert stats.processed_count == 0
        assert stats.error_count == 0
        assert stats.start_time is None
        assert stats.end_time is None
        assert stats.duration is None

    def test_start_and_finish_timing(self):
        """Test timing functionality."""
        stats = AuditStats()

        stats.start()
        assert stats.start_time is not None
        assert isinstance(stats.start_time, datetime)

        time.sleep(0.1)  # Small delay to ensure measurable duration

        stats.finish()
        assert stats.end_time is not None
        assert stats.duration is not None
        assert stats.duration > 0

    def test_increment_counters(self):
        """Test counter increment methods."""
        stats = AuditStats()

        stats.increment_processed()
        assert stats.processed_count == 1

        stats.increment_errors()
        assert stats.error_count == 1

        # Test multiple increments
        for _ in range(5):
            stats.increment_processed()
            stats.increment_errors()

        assert stats.processed_count == 6
        assert stats.error_count == 6


class TestAuditData:
    """Test the AuditData dataclass."""

    def test_initial_data(self):
        """Test initial data structure."""
        data = AuditData()

        assert isinstance(data.namespaces, dict)
        assert isinstance(data.auth_methods, dict)
        assert isinstance(data.secret_engines, dict)
        assert len(data.namespaces) == 0
        assert len(data.auth_methods) == 0
        assert len(data.secret_engines) == 0


class TestVaultAuditor:
    """Test the VaultAuditor class."""

    @pytest.fixture
    def valid_config(self):
        """Provide a valid configuration for testing."""
        return AuditConfig(
            vault_addr="https://vault.example.com",
            vault_token="test-token"
        )

    @pytest.fixture
    def auditor(self, valid_config):
        """Provide a VaultAuditor instance for testing."""
        return VaultAuditor(valid_config)

    def test_auditor_initialization(self, valid_config):
        """Test auditor initialization."""
        auditor = VaultAuditor(valid_config)

        assert auditor.config == valid_config
        assert isinstance(auditor.stats, AuditStats)
        assert isinstance(auditor.data, AuditData)
        assert isinstance(auditor.thread_lock, threading.Lock)
        assert auditor.logger is not None

    @patch('urllib3.disable_warnings')
    def test_ssl_warning_disabled_when_skip_verify(self, mock_disable_warnings, valid_config):
        """Test SSL warnings are disabled when skip_verify is True."""
        valid_config.vault_skip_verify = True
        VaultAuditor(valid_config)
        mock_disable_warnings.assert_called_once()

    def test_extract_child_namespaces_empty_response(self, auditor):
        """Test extracting child namespaces from empty response."""
        result = auditor._extract_child_namespaces(None)
        assert result == []

        result = auditor._extract_child_namespaces({})
        assert result == []

    def test_extract_child_namespaces_valid_response(self, auditor):
        """Test extracting child namespaces from valid response."""
        response = {
            "data": {
                "key_info": {
                    "team-a/": {"id": "123"},
                    "team-b/": {"id": "456"}
                }
            }
        }

        result = auditor._extract_child_namespaces(response)
        assert set(result) == {"team-a/", "team-b/"}

    def test_should_rate_limit_disabled(self, auditor):
        """Test rate limiting when disabled."""
        auditor.config.rate_limit_disable = True
        auditor.stats.processed_count = 100

        assert not auditor._should_rate_limit()

    def test_should_rate_limit_enabled(self, auditor):
        """Test rate limiting when enabled."""
        auditor.config.rate_limit_disable = False
        auditor.config.rate_limit_batch_size = 10

        auditor.stats.processed_count = 10
        assert auditor._should_rate_limit()

        auditor.stats.processed_count = 5
        assert not auditor._should_rate_limit()

    @patch('time.sleep')
    def test_apply_rate_limit(self, mock_sleep, auditor):
        """Test rate limit application."""
        auditor.config.rate_limit_sleep_seconds = 2
        auditor._apply_rate_limit()

        mock_sleep.assert_called_once_with(2)

    @patch('hvac.Client')
    def test_validate_vault_connection_success(self, mock_hvac_client, auditor):
        """Test successful Vault connection validation."""
        # Setup mock client
        mock_client = Mock()
        mock_client.sys.read_health_status.return_value = {
            'cluster_name': 'test-cluster',
            'sealed': False
        }
        mock_client.sys.is_sealed.return_value = False
        mock_client.is_authenticated.return_value = True
        mock_client.sys.is_initialized.return_value = True

        mock_hvac_client.return_value = mock_client

        result = auditor._validate_vault_connection()

        assert result == 'test-cluster'
        mock_client.sys.read_health_status.assert_called_once()

    @patch('hvac.Client')
    def test_validate_vault_connection_sealed(self, mock_hvac_client, auditor):
        """Test Vault connection validation with sealed cluster."""
        mock_client = Mock()
        mock_client.sys.read_health_status.return_value = {'cluster_name': 'test'}
        mock_client.sys.is_sealed.return_value = True

        mock_hvac_client.return_value = mock_client

        with pytest.raises(VaultConnectionError, match="Vault cluster is sealed"):
            auditor._validate_vault_connection()

    @patch('hvac.Client')
    def test_validate_vault_connection_not_authenticated(self, mock_hvac_client, auditor):
        """Test Vault connection validation with unauthenticated client."""
        mock_client = Mock()
        mock_client.sys.read_health_status.return_value = {'cluster_name': 'test'}
        mock_client.sys.is_sealed.return_value = False
        mock_client.is_authenticated.return_value = False

        mock_hvac_client.return_value = mock_client

        with pytest.raises(VaultConnectionError, match="not authenticated"):
            auditor._validate_vault_connection()

    @patch('hvac.Client')
    def test_fetch_namespace_data_success(self, mock_hvac_client, auditor):
        """Test successful namespace data fetch."""
        mock_client = Mock()
        mock_client.sys.list_auth_methods.return_value = {'auth_methods': 'data'}
        mock_client.sys.list_mounted_secrets_engines.return_value = {'secret_engines': 'data'}
        mock_client.sys.list_namespaces.return_value = {'namespaces': 'data'}

        mock_hvac_client.return_value = mock_client

        auth, secrets, namespaces = auditor._fetch_namespace_data("test/")

        assert auth == {'auth_methods': 'data'}
        assert secrets == {'secret_engines': 'data'}
        assert namespaces == {'namespaces': 'data'}

    @patch('hvac.Client')
    def test_fetch_namespace_data_invalid_path(self, mock_hvac_client, auditor):
        """Test namespace data fetch with invalid path."""
        mock_client = Mock()
        mock_client.sys.list_auth_methods.return_value = {'auth_methods': 'data'}
        mock_client.sys.list_mounted_secrets_engines.return_value = {'secret_engines': 'data'}
        mock_client.sys.list_namespaces.side_effect = hvac.exceptions.InvalidPath()

        mock_hvac_client.return_value = mock_client

        auth, secrets, namespaces = auditor._fetch_namespace_data("test/")

        assert auth == {'auth_methods': 'data'}
        assert secrets == {'secret_engines': 'data'}
        assert namespaces is None

    @patch('hvac.Client')
    def test_fetch_namespace_data_forbidden(self, mock_hvac_client, auditor):
        """Test namespace data fetch with forbidden access."""
        mock_client = Mock()
        mock_client.sys.list_auth_methods.side_effect = hvac.exceptions.Forbidden()

        mock_hvac_client.return_value = mock_client

        auth, secrets, namespaces = auditor._fetch_namespace_data("test/")

        assert auth is None
        assert secrets is None
        assert namespaces is None

    @patch('builtins.open', new_callable=mock_open)
    @patch('json.dump')
    def test_write_json_files(self, mock_json_dump, mock_file_open, auditor):
        """Test writing JSON files."""
        auditor.data.namespaces = {'test': 'namespace'}
        auditor.data.auth_methods = {'test': 'auth'}
        auditor.data.secret_engines = {'test': 'secret'}

        auditor._write_json_files('test-cluster')

        # Should open 3 files
        assert mock_file_open.call_count == 3
        assert mock_json_dump.call_count == 3

    @patch('summary.parse_namespaces')
    @patch('summary.parse_auth_methods')
    @patch('summary.parse_secret_engines')
    def test_generate_summary_reports(self, mock_parse_secrets, mock_parse_auth,
                                      mock_parse_namespaces, auditor):
        """Test generating summary reports."""
        auditor._generate_summary_reports('test-cluster')

        mock_parse_namespaces.assert_called_once()
        mock_parse_auth.assert_called_once()
        mock_parse_secrets.assert_called_once()

    def test_log_audit_summary(self, auditor, caplog):
        """Test audit summary logging."""
        with caplog.at_level(logging.INFO):
            auditor.stats.processed_count = 10
            auditor.stats.error_count = 2
            auditor.stats.start()
            time.sleep(0.01)
            auditor.stats.finish()

            auditor._log_audit_summary()

            assert "Audit complete" in caplog.text
            assert "10 namespaces processed" in caplog.text
            assert "2 errors" in caplog.text

    @patch.object(VaultAuditor, '_validate_vault_connection')
    @patch.object(VaultAuditor, '_write_json_files')
    @patch.object(VaultAuditor, '_generate_summary_reports')
    @patch.object(VaultAuditor, '_worker')
    def test_audit_cluster_success(self, mock_worker, mock_summary, mock_write,
                                   mock_validate, auditor):
        """Test successful cluster audit."""
        mock_validate.return_value = 'test-cluster'

        # Mock worker to not actually process anything
        def mock_worker_func(path_queue):
            try:
                while True:
                    item = path_queue.get(timeout=0.1)
                    if item is None:
                        break
                    path_queue.task_done()
            except queue.Empty:
                pass

        mock_worker.side_effect = mock_worker_func

        result = auditor.audit_cluster()

        assert result is True
        mock_validate.assert_called_once()
        mock_write.assert_called_once_with('test-cluster')
        mock_summary.assert_called_once_with('test-cluster')

    @patch.object(VaultAuditor, '_validate_vault_connection')
    def test_audit_cluster_connection_failure(self, mock_validate, auditor):
        """Test cluster audit with connection failure."""
        mock_validate.side_effect = VaultConnectionError("Connection failed")

        result = auditor.audit_cluster()

        assert result is False

    @patch.object(VaultAuditor, '_validate_vault_connection')
    def test_audit_cluster_keyboard_interrupt(self, mock_validate, auditor):
        """Test cluster audit with keyboard interrupt."""
        mock_validate.side_effect = KeyboardInterrupt()

        result = auditor.audit_cluster()

        assert result is False


class TestWorkerThreads:
    """Test worker thread functionality."""

    @pytest.fixture
    def auditor_with_mock_traverse(self):
        """Create auditor with mocked traverse method."""
        config = AuditConfig(
            vault_addr="https://vault.example.com",
            vault_token="test-token"
        )
        auditor = VaultAuditor(config)

        # Mock the traverse method to avoid actual Vault calls
        # The method takes (namespace_path, path_queue) parameters
        auditor._traverse_namespace = Mock(return_value=None)
        
        # Mock rate limiting methods to avoid delays
        auditor._should_rate_limit = Mock(return_value=False)
        auditor._apply_rate_limit = Mock()
        
        return auditor

    def test_worker_processes_queue_items(self, auditor_with_mock_traverse):
        """Test that worker processes queue items correctly."""
        test_queue = queue.Queue()
        test_queue.put("namespace1/")
        test_queue.put("namespace2/")
        test_queue.put(None)  # Shutdown signal

        # Start worker in a separate thread
        worker_thread = threading.Thread(
            target=auditor_with_mock_traverse._worker,
            args=(test_queue,)
        )
        worker_thread.start()
        worker_thread.join(timeout=2)  # Give more time for processing

        # Verify traverse was called for each namespace
        assert auditor_with_mock_traverse._traverse_namespace.call_count == 2

    def test_worker_handles_empty_queue(self, auditor_with_mock_traverse):
        """Test worker handles empty queue gracefully."""
        test_queue = queue.Queue()
        test_queue.put(None)  # Immediate shutdown

        worker_thread = threading.Thread(
            target=auditor_with_mock_traverse._worker,
            args=(test_queue,)
        )
        worker_thread.start()
        worker_thread.join(timeout=1)

        # Should not call traverse for empty queue
        auditor_with_mock_traverse._traverse_namespace.assert_not_called()


class TestConfigCreation:
    """Test configuration creation from arguments."""

    def test_create_config_from_args_success(self):
        """Test successful config creation from arguments."""
        with patch.dict(os.environ, {
            'VAULT_ADDR': 'https://vault.example.com',
            'VAULT_TOKEN': 'test-token'
        }):
            args = Mock()
            args.namespace = 'team-a'
            args.workers = 8
            args.fast = True
            args.debug = True

            config = create_config_from_args(args)

            assert config.vault_addr == 'https://vault.example.com'
            assert config.vault_token == 'test-token'
            assert config.namespace_path == 'team-a/'
            assert config.worker_threads == 8
            assert config.rate_limit_disable is True
            assert config.debug is True

    def test_create_config_missing_vault_addr(self):
        """Test config creation fails without VAULT_ADDR."""
        with patch.dict(os.environ, {}, clear=True):
            args = Mock()
            args.namespace = None
            args.workers = 4
            args.fast = False
            args.debug = False

            with pytest.raises(ValueError, match="VAULT_ADDR environment variable is required"):
                create_config_from_args(args)

    def test_create_config_missing_vault_token(self):
        """Test config creation fails without VAULT_TOKEN."""
        with patch.dict(os.environ, {'VAULT_ADDR': 'https://vault.example.com'}, clear=True):
            args = Mock()
            args.namespace = None
            args.workers = 4
            args.fast = False
            args.debug = False

            with pytest.raises(ValueError, match="VAULT_TOKEN environment variable is required"):
                create_config_from_args(args)


class TestArgumentParsing:
    """Test command line argument parsing."""

    def test_parse_arguments_defaults(self):
        """Test argument parsing with default values."""
        with patch('sys.argv', ['main.py']):
            args = parse_arguments()

            assert args.debug is False
            assert args.fast is False
            assert args.namespace is None
            assert args.workers == Constants.DEFAULT_WORKER_THREADS

    def test_parse_arguments_all_options(self):
        """Test argument parsing with all options."""
        test_args = [
            'main.py',
            '--debug',
            '--fast',
            '--namespace', 'team-a/',
            '--workers', '8'
        ]

        with patch('sys.argv', test_args):
            args = parse_arguments()

            assert args.debug is True
            assert args.fast is True
            assert args.namespace == 'team-a/'
            assert args.workers == 8


class TestMainFunction:
    """Test the main function."""

    @patch('main.VaultAuditor')
    @patch('main.create_config_from_args')
    @patch('main.parse_arguments')
    def test_main_success(self, mock_parse_args, mock_create_config, mock_auditor_class):
        """Test successful main function execution."""
        # Setup mocks
        mock_args = Mock()
        mock_parse_args.return_value = mock_args

        mock_config = Mock()
        mock_create_config.return_value = mock_config

        mock_auditor = Mock()
        mock_auditor.audit_cluster.return_value = True
        mock_auditor_class.return_value = mock_auditor

        result = main()

        assert result == 0
        mock_parse_args.assert_called_once()
        mock_create_config.assert_called_once_with(mock_args)
        mock_auditor_class.assert_called_once_with(mock_config)
        mock_auditor.audit_cluster.assert_called_once()

    @patch('main.create_config_from_args')
    @patch('main.parse_arguments')
    def test_main_config_error(self, mock_parse_args, mock_create_config):
        """Test main function with configuration error."""
        mock_parse_args.return_value = Mock()
        mock_create_config.side_effect = ValueError("Config error")

        result = main()

        assert result == 1

    @patch('main.VaultAuditor')
    @patch('main.create_config_from_args')
    @patch('main.parse_arguments')
    def test_main_audit_failure(self, mock_parse_args, mock_create_config, mock_auditor_class):
        """Test main function with audit failure."""
        mock_parse_args.return_value = Mock()
        mock_create_config.return_value = Mock()

        mock_auditor = Mock()
        mock_auditor.audit_cluster.return_value = False
        mock_auditor_class.return_value = mock_auditor

        result = main()

        assert result == 1


# Integration test fixtures and utilities
@pytest.fixture
def temp_dir():
    """Provide a temporary directory for file operations."""
    with tempfile.TemporaryDirectory() as tmp_dir:
        yield Path(tmp_dir)


@pytest.fixture
def mock_vault_responses():
    """Provide mock Vault API responses."""
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


class TestIntegration:
    """Integration tests using mocked Vault responses."""

    @patch('hvac.Client')
    def test_full_audit_workflow(self, mock_hvac_client, mock_vault_responses, temp_dir):
        """Test complete audit workflow with mocked Vault."""
        # Setup mock client with proper return values
        mock_client = Mock()
        mock_client.sys.read_health_status.return_value = mock_vault_responses['health']
        mock_client.sys.is_sealed.return_value = False
        mock_client.is_authenticated.return_value = True
        mock_client.sys.is_initialized.return_value = True
        mock_client.sys.list_auth_methods.return_value = mock_vault_responses['auth_methods']
        mock_client.sys.list_mounted_secrets_engines.return_value = mock_vault_responses['secret_engines']
        
        # Mock namespaces to return empty for child namespaces to prevent infinite recursion
        mock_client.sys.list_namespaces.side_effect = [
            mock_vault_responses['namespaces'],  # First call (root) returns namespaces
            None,  # Subsequent calls return None to prevent infinite recursion
            None,
            None
        ]

        mock_hvac_client.return_value = mock_client

        # Create config with minimal settings to prevent hanging
        config = AuditConfig(
            vault_addr="https://vault.example.com",
            vault_token="test-token",
            worker_threads=1,  # Use single thread for predictable testing
            rate_limit_disable=True,  # Disable rate limiting to speed up test
            hvac_timeout=1  # Short timeout
        )

        # Change to temp directory for file output
        original_cwd = os.getcwd()
        try:
            os.chdir(temp_dir)

            # Run audit with additional mocking to prevent hanging
            auditor = VaultAuditor(config)
            
            # Mock the traverse method to control execution and prevent infinite loops
            call_count = 0
            
            def limited_traverse(namespace_path, path_queue):
                nonlocal call_count
                call_count += 1
                # Only process the first few calls to prevent infinite recursion
                if call_count <= 3:
                    # Store basic data without recursive namespace discovery
                    display_path = namespace_path if namespace_path else "/"
                    with auditor.thread_lock:
                        auditor.stats.increment_processed()
                        auditor.data.auth_methods[display_path] = mock_vault_responses['auth_methods']
                        auditor.data.secret_engines[display_path] = mock_vault_responses['secret_engines']
                        # Don't add child namespaces to prevent infinite loops
                        # Note: path_queue parameter required for interface compatibility
                return
            
            auditor._traverse_namespace = limited_traverse

            with patch('summary.parse_namespaces'), \
                    patch('summary.parse_auth_methods'), \
                    patch('summary.parse_secret_engines'):
                result = auditor.audit_cluster()

            assert result is True

            # Verify data was collected
            assert len(auditor.data.auth_methods) > 0
            assert len(auditor.data.secret_engines) > 0

            # Verify statistics
            assert auditor.stats.processed_count > 0
            assert auditor.stats.duration is not None

        finally:
            os.chdir(original_cwd)

    def test_simple_audit_workflow(self):
        """Test a simplified audit workflow without full integration complexity."""
        config = AuditConfig(
            vault_addr="https://vault.example.com",
            vault_token="test-token",
            worker_threads=1,
            rate_limit_disable=True
        )
        
        auditor = VaultAuditor(config)
        
        # Test that the auditor can be created and basic methods work
        assert auditor.config == config
        assert isinstance(auditor.stats, AuditStats)
        assert isinstance(auditor.data, AuditData)
        
        # Test extract child namespaces method
        mock_response = {
            'data': {
                'key_info': {
                    'test-ns/': {'id': '123'}
                }
            }
        }
        
        result = auditor._extract_child_namespaces(mock_response)
        assert result == ['test-ns/']
        
        # Test rate limiting logic
        auditor.config.rate_limit_disable = False
        auditor.config.rate_limit_batch_size = 5
        auditor.stats.processed_count = 5
        assert auditor._should_rate_limit() is True
        
        auditor.stats.processed_count = 3
        assert auditor._should_rate_limit() is False


# Performance and stress tests
class TestPerformance:
    """Performance and stress tests."""

    def test_large_namespace_tree_simulation(self):
        """Test handling of large namespace trees."""
        config = AuditConfig(
            vault_addr="https://vault.example.com",
            vault_token="test-token",
            worker_threads=2
        )

        auditor = VaultAuditor(config)

        # Simulate large namespace response
        large_response = {
            'data': {
                'key_info': {f'namespace-{i}/': {'id': str(i)} for i in range(100)}
            }
        }

        result = auditor._extract_child_namespaces(large_response)

        assert len(result) == 100
        assert all(ns.startswith('namespace-') for ns in result)

    def test_concurrent_statistics_updates(self):
        """Test thread-safe statistics updates under load."""
        stats = AuditStats()
        threads = []

        def update_stats():
            for _ in range(100):
                stats.increment_processed()
                stats.increment_errors()

        # Start multiple threads updating stats
        for _ in range(10):
            thread = threading.Thread(target=update_stats)
            threads.append(thread)
            thread.start()

        # Wait for completion
        for thread in threads:
            thread.join()

        # Verify final counts
        assert stats.processed_count == 1000
        assert stats.error_count == 1000


if __name__ == "__main__":
    pytest.main([__file__, "-v"])