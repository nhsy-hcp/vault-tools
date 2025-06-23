"""Integration tests for the main functionality."""
import json
import os
import sys
import tempfile
import pytest
from unittest.mock import patch, Mock, mock_open

sys.path.insert(0, f"{os.path.dirname(__file__)}/../")

from main import create_activity_report, VaultConfig, main


class TestCreateActivityReportIntegration:
    """Integration tests for create_activity_report function."""
    
    def test_create_report_from_json_file(self):
        """Test creating report from JSON file end-to-end."""
        test_data = {
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
            ]
        }
        
        config = VaultConfig()
        
        with patch("builtins.open", mock_open(read_data=json.dumps(test_data))):
            with patch("pathlib.Path.exists", return_value=True):
                with patch('main.write_csv_reports') as mock_write:
                    create_activity_report(config, json_file_name="test.json")
                    mock_write.assert_called_once()
    
    def test_create_report_from_vault_api(self):
        """Test creating report from Vault API end-to-end."""
        mock_response_data = {
            "data": {
                "by_namespace": [
                    {
                        "namespace_id": "root",
                        "namespace_path": "",
                        "counts": {"clients": 5, "entity_clients": 4, "non_entity_clients": 1},
                        "mounts": []
                    }
                ],
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
                with patch('main.write_csv_reports') as mock_write:
                    create_activity_report(config, "2024-01-01", "2024-01-31")
                    mock_write.assert_called_once()
    
    def test_create_report_missing_dates(self):
        """Test creating report with missing date parameters."""
        config = VaultConfig()
        
        with pytest.raises(ValueError, match="start_date and end_date must be provided"):
            create_activity_report(config)
    
    def test_create_report_invalid_date_format(self):
        """Test creating report with invalid date format."""
        config = VaultConfig()
        
        with pytest.raises(ValueError, match="Invalid date format"):
            create_activity_report(config, "2024/01/01", "2024/01/31")


class TestMainFunctionIntegration:
    """Integration tests for main function."""
    
    def test_main_with_json_file(self):
        """Test main function with JSON file argument."""
        test_args = ['main.py', '-f', 'test.json']
        test_data = {"by_namespace": []}
        
        with patch('sys.argv', test_args):
            with patch("builtins.open", mock_open(read_data=json.dumps(test_data))):
                with patch("pathlib.Path.exists", return_value=True):
                    with patch('main.write_csv_reports'):
                        # Should not raise exception
                        main()
    
    def test_main_with_date_range(self):
        """Test main function with date range arguments."""
        test_args = ['main.py', '-s', '2024-01-01', '-e', '2024-01-31']
        
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
        
        with patch('sys.argv', test_args):
            with patch.dict(os.environ, {'VAULT_ADDR': 'https://vault.example.com', 'VAULT_TOKEN': 'test-token'}):
                with patch('requests.get', return_value=mock_response):
                    with patch('builtins.open', mock_open()):
                        with patch('main.write_csv_reports'):
                            # Should not raise exception
                            main()
    
    def test_main_with_print_option(self):
        """Test main function with print option."""
        test_args = ['main.py', '-f', 'test.json', '-p']
        test_data = {"by_namespace": []}
        
        with patch('sys.argv', test_args):
            with patch("builtins.open", mock_open(read_data=json.dumps(test_data))):
                with patch("pathlib.Path.exists", return_value=True):
                    with patch('main.write_csv_reports'):
                        with patch('main.read_activity_report') as mock_read:
                            main()
                            mock_read.assert_called_once()
    
    def test_main_error_handling(self):
        """Test main function error handling."""
        test_args = ['main.py', '-f', 'nonexistent.json']
        
        with patch('sys.argv', test_args):
            with patch("pathlib.Path.exists", return_value=False):
                with pytest.raises(SystemExit):
                    main()
    
    def test_main_keyboard_interrupt(self):
        """Test main function keyboard interrupt handling."""
        test_args = ['main.py', '-f', 'test.json']
        
        with patch('sys.argv', test_args):
            with patch('main.create_activity_report', side_effect=KeyboardInterrupt()):
                with pytest.raises(SystemExit):
                    main()
    
    def test_main_unexpected_error(self):
        """Test main function unexpected error handling."""
        test_args = ['main.py', '-f', 'test.json']
        
        with patch('sys.argv', test_args):
            with patch('main.create_activity_report', side_effect=RuntimeError("Unexpected error")):
                with pytest.raises(SystemExit):
                    main()