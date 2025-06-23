"""Tests for Vault API interaction functions."""
import json
import os
import sys
import pytest
from unittest.mock import patch, Mock, mock_open

sys.path.insert(0, f"{os.path.dirname(__file__)}/../")

from main import (
    VaultConfig, 
    fetch_data_from_vault, 
    write_csv_reports, 
    read_activity_report,
    VaultAPIError,
    FileProcessingError
)


class TestFetchDataFromVault:
    """Test cases for fetching data from Vault API."""
    
    def test_successful_api_request(self):
        """Test successful API request to Vault."""
        mock_response_data = {
            "data": {
                "by_namespace": [{"namespace_id": "root"}],
                "total": {"clients": 5, "entity_clients": 4, "non_entity_clients": 1},
                "start_time": "2024-01-01T00:00:00Z"
            }
        }
        
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = mock_response_data
        
        config = VaultConfig()
        config.vault_addr = "https://vault.example.com"
        config.vault_token = "test-token"
        
        with patch('requests.get', return_value=mock_response):
            with patch('builtins.open', mock_open()):
                result = fetch_data_from_vault(config, "2024-01-01", "2024-01-31")
                
                assert result == mock_response_data["data"]
    
    def test_api_request_failure(self):
        """Test API request failure scenarios."""
        mock_response = Mock()
        mock_response.status_code = 403
        mock_response.text = "Forbidden"
        
        config = VaultConfig()
        config.vault_addr = "https://vault.example.com"
        config.vault_token = "invalid-token"
        
        with patch('requests.get', return_value=mock_response):
            with pytest.raises(VaultAPIError, match="Vault API request failed with status 403"):
                fetch_data_from_vault(config, "2024-01-01", "2024-01-31")
    
    def test_api_connection_error(self):
        """Test API connection error."""
        import requests
        
        config = VaultConfig()
        config.vault_addr = "https://vault.example.com"
        config.vault_token = "test-token"
        
        with patch('requests.get', side_effect=requests.ConnectionError("Connection failed")):
            with pytest.raises(VaultAPIError, match="Failed to connect to Vault"):
                fetch_data_from_vault(config, "2024-01-01", "2024-01-31")
    
    def test_api_timeout_error(self):
        """Test API timeout error."""
        import requests
        
        config = VaultConfig()
        config.vault_addr = "https://vault.example.com"
        config.vault_token = "test-token"
        
        with patch('requests.get', side_effect=requests.Timeout("Request timed out")):
            with pytest.raises(VaultAPIError, match="Failed to connect to Vault"):
                fetch_data_from_vault(config, "2024-01-01", "2024-01-31")
    
    def test_json_save_error_handling(self):
        """Test handling of JSON file save errors."""
        mock_response_data = {
            "data": {
                "by_namespace": [],
                "total": {"clients": 0},
                "start_time": "2024-01-01T00:00:00Z"
            }
        }
        
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = mock_response_data
        
        config = VaultConfig()
        config.vault_addr = "https://vault.example.com"
        config.vault_token = "test-token"
        
        with patch('requests.get', return_value=mock_response):
            with patch('builtins.open', mock_open()) as mock_file:
                mock_file.side_effect = OSError("Permission denied")
                # Should not raise exception, just print warning
                result = fetch_data_from_vault(config, "2024-01-01", "2024-01-31")
                assert result == mock_response_data["data"]


class TestWriteCSVReports:
    """Test cases for writing CSV reports."""
    
    def test_successful_csv_write(self):
        """Test successful CSV file writing."""
        config = VaultConfig()
        namespaces_data = [
            ['namespace_id', 'namespace_path', 'mounts', 'clients', 'entity_clients', 'non_entity_clients'],
            ['root', '', '2', '5', '4', '1']
        ]
        mounts_data = [
            ['namespace_id', 'namespace_path', 'mount_path', 'clients', 'entity_clients', 'non_entity_clients'],
            ['root', '', 'auth/token/', '3', '2', '1']
        ]
        
        with patch('builtins.open', mock_open()) as mock_file:
            write_csv_reports(config, namespaces_data, mounts_data)
            # Verify files were opened for writing
            assert mock_file.call_count == 2
    
    def test_csv_write_error(self):
        """Test CSV writing error handling."""
        config = VaultConfig()
        namespaces_data = [['header']]
        mounts_data = [['header']]
        
        with patch('builtins.open', side_effect=OSError("Permission denied")):
            with pytest.raises(FileProcessingError, match="Error writing CSV files"):
                write_csv_reports(config, namespaces_data, mounts_data)


class TestReadActivityReport:
    """Test cases for reading activity reports."""
    
    def test_successful_report_reading(self):
        """Test successful reading of CSV reports."""
        config = VaultConfig()
        
        # Mock CSV file content
        csv_content = "namespace_id,namespace_path,mounts,clients\nroot,,2,5\n"
        
        with patch('builtins.open', mock_open(read_data=csv_content)):
            # Should not raise exception
            read_activity_report(config)
    
    def test_report_reading_file_error(self):
        """Test reading CSV reports with file error."""
        config = VaultConfig()
        
        with patch('builtins.open', side_effect=OSError("File not found")):
            with pytest.raises(FileProcessingError, match="Error reading CSV files"):
                read_activity_report(config)