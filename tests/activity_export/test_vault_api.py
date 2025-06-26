"""Tests for Vault API interaction functions."""
import pytest
from unittest.mock import patch, Mock

from src.common.vault_client import VaultClient, VaultAPIError
from src.activity_export.main import get_activity_data
from src.common.file_utils import write_csv
from .fixtures import mock_vault_client, sample_activity_data, sample_namespace_csv_data, sample_mounts_csv_data


class FileProcessingError(Exception):
    """Mock exception for file processing errors."""
    pass


class TestFetchDataFromVault:
    """Test cases for fetching data from Vault API."""

    def test_successful_api_request(self, mock_vault_client, sample_activity_data):
        """Test successful API request to Vault."""
        mock_vault_client.get.return_value = {"data": sample_activity_data}

        result = get_activity_data(mock_vault_client, "2024-01-01", "2024-01-31")

        assert result == sample_activity_data
        mock_vault_client.get.assert_called_once()

    def test_api_request_failure(self, mock_vault_client):
        """Test API request failure scenarios."""
        mock_vault_client.get.side_effect = VaultAPIError("API error")

        with pytest.raises(VaultAPIError, match="API error"):
            get_activity_data(mock_vault_client, "2024-01-01", "2024-01-31")


class TestDataProcessing:
    """Test cases for data processing functionality."""

    def test_process_activity_data_creates_csv_data(self, sample_activity_data):
        """Test that process_activity_data creates correct CSV data structure."""
        from src.activity_export.main import process_activity_data
        
        with patch('src.activity_export.main.write_csv') as mock_write_csv:
            with patch('src.activity_export.main.write_json') as mock_write_json:
                namespaces_data, mounts_data = process_activity_data(sample_activity_data, "test-cluster")
                
                # Verify the data structure
                assert len(namespaces_data) == 1
                assert len(mounts_data) == 1
                assert namespaces_data[0]['namespace_id'] == "root"  # namespace_id
                assert mounts_data[0]['mount_path'] == "auth/token/"  # mount_path

    def test_process_empty_activity_data(self):
        """Test processing empty activity data."""
        from src.activity_export.main import process_activity_data
        
        empty_data = {"by_namespace": []}
        
        with patch('src.activity_export.main.write_csv') as mock_write_csv:
            with patch('src.activity_export.main.write_json') as mock_write_json:
                namespaces_data, mounts_data = process_activity_data(empty_data, "test-cluster")
                
                assert len(namespaces_data) == 0
                assert len(mounts_data) == 0


