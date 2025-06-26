import json
import pandas as pd
import pytest
from unittest.mock import Mock, patch, mock_open
from src.common.vault_client import VaultClient, VaultAPIError
from src.entity_export.main import (
    get_entity_export_data as fetch_entity_export_from_vault,
    process_entity_export_data,
    run_entity_export as create_entity_export_report
)
from src.common.file_utils import FileProcessingError, read_json as load_entity_export_from_file




@pytest.fixture
def mock_vault_client():
    client = Mock(spec=VaultClient)
    client.get = Mock(return_value=[])
    return client

class TestEntityExportFunctionality:
    """Test cases for entity export functionality.""" 

    @pytest.fixture
    def sample_entity_data(self):
        """Sample entity export data for testing."""
        return [
            {"client_id": "client-1", "namespace_id": "root", "timestamp": "2024-01-01T10:00:00Z", "mount_accessor": "accessor-1", "client_type": "entity"},
            {"client_id": "client-2", "namespace_id": "ns1", "timestamp": "2024-01-01T11:00:00Z", "mount_accessor": "accessor-2", "client_type": "non_entity"},
            {"client_id": "client-3", "namespace_id": "root", "timestamp": "2024-01-02T09:00:00Z", "mount_accessor": "accessor-1", "client_type": "entity"}
        ]


    def test_fetch_entity_export_success(self, mock_vault_client, sample_entity_data):
        """Test successful entity export fetch from Vault API."""
        mock_vault_client.get.return_value = sample_entity_data
        result = fetch_entity_export_from_vault(mock_vault_client, "2024-01-01", "2024-01-31")
        
        mock_vault_client.get.assert_called_once()
        assert result == sample_entity_data

    def test_fetch_entity_export_api_error(self, mock_vault_client):
        """Test entity export fetch with API error."""
        mock_vault_client.get.side_effect = VaultAPIError("API error")
        with pytest.raises(VaultAPIError, match="API error"):
            fetch_entity_export_from_vault(mock_vault_client, "2024-01-01", "2024-01-31")

    @patch('src.common.file_utils.write_csv')
    @patch('src.common.file_utils.write_json')
    def test_process_entity_export_data_success(self, mock_write_json, mock_write_csv, sample_entity_data):
        """Test successful processing of entity export data."""
        df = process_entity_export_data(sample_entity_data, "test-cluster")
        
        assert isinstance(df, pd.DataFrame)
        assert len(df) == 3
        assert 'entity_type' in df.columns

    def test_process_entity_export_data_empty(self):
        """Test processing empty entity export data."""
        df = process_entity_export_data([], "test-cluster")
        assert df is None

    def test_process_entity_export_data_missing_columns(self):
        """Test processing entity data with missing columns."""
        incomplete_data = [{"client_id": "client-1"}]
        df = process_entity_export_data(incomplete_data, "test-cluster")
        assert df is None

    def test_load_entity_export_from_file_success(self, sample_entity_data):
        """Test successful loading of entity export from file."""
        json_content = json.dumps(sample_entity_data)
        with patch('builtins.open', mock_open(read_data=json_content)):
            result = load_entity_export_from_file("test.json")
        assert result == sample_entity_data

    def test_load_entity_export_from_file_not_found(self):
        """Test loading entity export from non-existent file."""
        with pytest.raises(FileProcessingError, match="Failed to read or parse"):
            with patch('builtins.open', side_effect=FileNotFoundError):
                load_entity_export_from_file("nonexistent.json")

    @patch('src.entity_export.main.get_entity_export_data')
    @patch('src.entity_export.main.process_entity_export_data')
    def test_create_entity_export_report_from_api(self, mock_process, mock_fetch, mock_vault_client, sample_entity_data):
        """Test creating entity export report from Vault API."""
        mock_fetch.return_value = sample_entity_data
        create_entity_export_report(mock_vault_client, "2024-01-01", "2024-01-31", "test-cluster")
        
        mock_fetch.assert_called_once_with(mock_vault_client, "2024-01-01", "2024-01-31")
        mock_process.assert_called_once_with(sample_entity_data, "test-cluster", "outputs")