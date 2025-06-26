import os
import pytest
from unittest.mock import patch, Mock
from src.common.vault_client import VaultClient
from src.activity_export.main import run_activity_export
from main import main
from .fixtures import mock_vault_client, sample_activity_data


class TestCreateActivityReportIntegration:
    """Integration tests for create_activity_report function."""

    def test_create_report_from_json_file(self, mock_vault_client, sample_activity_data):
        """Test creating report from JSON file end-to-end."""
        with patch('src.activity_export.main.write_csv') as mock_write:
            run_activity_export(mock_vault_client, "2024-01-01", "2024-01-31", "test-cluster", data=sample_activity_data)
            assert mock_write.call_count == 2

    def test_create_report_from_vault_api(self, mock_vault_client, sample_activity_data):
        """Test creating report from Vault API end-to-end."""
        mock_vault_client.get.return_value = {"data": sample_activity_data}

        with patch('src.activity_export.main.write_csv') as mock_write:
            run_activity_export(mock_vault_client, "2024-01-01", "2024-01-31", "test-cluster")
            assert mock_write.call_count == 2


class TestMainFunctionIntegration:
    """Integration tests for main function."""

    def test_run_activity_export_with_client(self, mock_vault_client, sample_activity_data):
        """Test run_activity_export function directly."""
        mock_vault_client.get.return_value = {"data": sample_activity_data}
        
        with patch('src.activity_export.main.write_csv') as mock_write_csv:
            with patch('src.activity_export.main.write_json') as mock_write_json:
                result = run_activity_export(mock_vault_client, "2024-01-01", "2024-01-31", "test-cluster")
                
                # Verify function completed successfully
                assert result is not None
                namespaces_data, mounts_data = result
                assert len(namespaces_data) == 1
                assert len(mounts_data) == 1