"""Tests for VaultConfig class and related functionality."""
import os
import pytest
from unittest.mock import patch, mock_open
from pathlib import Path

import sys
sys.path.insert(0, f"{os.path.dirname(__file__)}/../")

from main import VaultConfig


class TestVaultConfig:
    """Test cases for VaultConfig class."""
    
    def test_vault_config_initialization(self):
        """Test VaultConfig initialization with environment variables."""
        with patch.dict(os.environ, {'VAULT_ADDR': 'https://vault.example.com', 'VAULT_TOKEN': 'test-token'}):
            config = VaultConfig()
            assert config.vault_addr == 'https://vault.example.com'
            assert config.vault_token == 'test-token'
            assert isinstance(config.date_str, str)
            assert len(config.date_str) == 8  # YYYYMMDD format
    
    def test_vault_config_missing_env_vars(self):
        """Test VaultConfig with missing environment variables."""
        with patch.dict(os.environ, {}, clear=True):
            config = VaultConfig()
            assert config.vault_addr is None
            assert config.vault_token is None
    
    def test_activity_json_filename_property(self):
        """Test activity JSON filename generation."""
        config = VaultConfig()
        filename = config.activity_json_filename
        assert filename.startswith('activity-')
        assert filename.endswith('.json')
        assert len(filename) == 22  # activity-YYYYMMDD.json
    
    def test_activity_namespaces_filename_property(self):
        """Test activity namespaces CSV filename generation."""
        config = VaultConfig()
        filename = config.activity_namespaces_filename
        assert filename.startswith('activity-namespaces-')
        assert filename.endswith('.csv')
    
    def test_activity_mounts_filename_property(self):
        """Test activity mounts CSV filename generation."""
        config = VaultConfig()
        filename = config.activity_mounts_filename
        assert filename.startswith('activity-mounts-')
        assert filename.endswith('.csv')
    
    def test_validate_environment_success(self):
        """Test successful environment validation."""
        with patch.dict(os.environ, {'VAULT_ADDR': 'https://vault.example.com', 'VAULT_TOKEN': 'test-token'}):  
            config = VaultConfig()
            # Should not raise an exception
            config.validate_environment()
    
    def test_validate_environment_missing_token(self):
        """Test environment validation with missing token."""
        with patch.dict(os.environ, {'VAULT_ADDR': 'https://vault.example.com'}, clear=True):
            config = VaultConfig()
            with pytest.raises(EnvironmentError, match="VAULT_TOKEN environment variable not set"):
                config.validate_environment()
    
    def test_validate_environment_missing_addr(self):
        """Test environment validation with missing address."""
        with patch.dict(os.environ, {'VAULT_TOKEN': 'test-token'}, clear=True):
            config = VaultConfig()
            with pytest.raises(EnvironmentError, match="VAULT_ADDR environment variable not set"):
                config.validate_environment()
    
    def test_validate_environment_missing_both(self):
        """Test environment validation with both variables missing."""
        with patch.dict(os.environ, {}, clear=True):
            config = VaultConfig()
            with pytest.raises(EnvironmentError, match="VAULT_TOKEN environment variable not set"):
                config.validate_environment()