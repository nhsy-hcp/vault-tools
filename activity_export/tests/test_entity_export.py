import json
import pandas as pd
import pytest
from pathlib import Path
from unittest.mock import Mock, patch, mock_open

from main import (
    VaultConfig, 
    fetch_entity_export_from_vault, 
    process_entity_export_data, 
    write_entities_csv_report,
    load_entity_export_from_file,
    create_entity_export_report,
    VaultAPIError,
    FileProcessingError
)


class TestEntityExportFunctionality:
    """Test cases for entity export functionality."""

    @pytest.fixture
    def mock_config(self):
        """Create a mock VaultConfig for testing."""
        config = VaultConfig()
        config.vault_addr = "https://vault.example.com:8200"
        config.vault_token = "test-token"
        config.date_str = "20240101"
        return config

    @pytest.fixture
    def sample_entity_data(self):
        """Sample entity export data for testing."""
        return [
            {
                "client_id": "client-1",
                "namespace_id": "root",
                "timestamp": "2024-01-01T10:00:00Z",
                "mount_accessor": "accessor-1",
                "non_entity": False
            },
            {
                "client_id": "client-2",
                "namespace_id": "ns1",
                "timestamp": "2024-01-01T11:00:00Z",
                "mount_accessor": "accessor-2",
                "non_entity": True
            },
            {
                "client_id": "client-3",
                "namespace_id": "root",
                "timestamp": "2024-01-02T09:00:00Z",
                "mount_accessor": "accessor-1",
                "non_entity": False
            }
        ]

    @patch('main.requests.get')
    def test_fetch_entity_export_success(self, mock_get, mock_config, sample_entity_data):
        """Test successful entity export fetch from Vault API."""
        # Mock successful response
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = sample_entity_data
        mock_response.text = json.dumps(sample_entity_data)
        mock_response.content = json.dumps(sample_entity_data).encode('utf-8')
        mock_response.headers = {'content-type': 'application/json'}
        mock_get.return_value = mock_response
        
        with patch('builtins.open', mock_open()) as mock_file:
            with patch('main.parse_vault_response', return_value=sample_entity_data):
                result = fetch_entity_export_from_vault(mock_config, "2024-01-01", "2024-01-31")
        
        # Verify API call
        mock_get.assert_called_once()
        call_args = mock_get.call_args
        assert "sys/internal/counters/activity/export" in call_args[0][0]
        assert call_args[1]['params']['format'] == 'json'
        assert 'X-Vault-Token' in call_args[1]['headers']
        
        # Verify result
        assert result == sample_entity_data
        mock_file.assert_called_once()

    @patch('main.requests.get')
    def test_fetch_entity_export_api_error(self, mock_get, mock_config):
        """Test entity export fetch with API error."""
        mock_response = Mock()
        mock_response.status_code = 403
        mock_response.text = "Forbidden"
        mock_response.content = b"Forbidden"
        mock_response.headers = {'content-type': 'text/plain'}
        mock_get.return_value = mock_response
        
        with pytest.raises(VaultAPIError, match="403"):
            fetch_entity_export_from_vault(mock_config, "2024-01-01", "2024-01-31")

    @patch('main.requests.get')
    def test_fetch_entity_export_connection_error(self, mock_get, mock_config):
        """Test entity export fetch with connection error."""
        import requests
        mock_get.side_effect = requests.RequestException("Connection failed")
        
        with pytest.raises(VaultAPIError, match="Failed to connect to Vault"):
            fetch_entity_export_from_vault(mock_config, "2024-01-01", "2024-01-31")

    def test_process_entity_export_data_success(self, sample_entity_data):
        """Test successful processing of entity export data."""
        df = process_entity_export_data(sample_entity_data)
        
        # Verify DataFrame structure
        assert isinstance(df, pd.DataFrame)
        assert len(df) == 3
        assert 'client_id' in df.columns
        assert 'namespace_id' in df.columns
        assert 'entity_type' in df.columns
        
        # Verify data processing
        assert df['entity_type'].nunique() == 2  # entity and non_entity
        assert (df['entity_type'] == 'entity').sum() == 2
        assert (df['entity_type'] == 'non_entity').sum() == 1
        assert df['client_id'].nunique() == 3

    def test_process_entity_export_data_empty(self):
        """Test processing empty entity export data."""
        df = process_entity_export_data([])
        
        assert isinstance(df, pd.DataFrame)
        assert len(df) == 0

    def test_process_entity_export_data_missing_columns(self):
        """Test processing entity data with missing columns."""
        incomplete_data = [{"client_id": "client-1"}]
        
        df = process_entity_export_data(incomplete_data)
        
        assert isinstance(df, pd.DataFrame)
        assert len(df) == 1
        assert 'namespace_id' in df.columns
        assert 'mount_accessor' in df.columns
        assert 'non_entity' in df.columns


    def test_load_entity_export_from_file_success(self, sample_entity_data):
        """Test successful loading of entity export from file."""
        json_content = json.dumps(sample_entity_data)
        
        with patch('builtins.open', mock_open(read_data=json_content)):
            with patch('main.Path.exists', return_value=True):
                result = load_entity_export_from_file("test.json")
        
        assert result == sample_entity_data

    def test_load_entity_export_from_file_wrapped_data(self, sample_entity_data):
        """Test loading entity export with wrapped data format."""
        wrapped_data = {"data": sample_entity_data}
        json_content = json.dumps(wrapped_data)
        
        with patch('builtins.open', mock_open(read_data=json_content)):
            with patch('main.Path.exists', return_value=True):
                result = load_entity_export_from_file("test.json")
        
        assert result == sample_entity_data

    def test_load_entity_export_from_file_not_found(self):
        """Test loading entity export from non-existent file."""
        with patch('main.Path.exists', return_value=False):
            with pytest.raises(FileProcessingError, match="File not found"):
                load_entity_export_from_file("nonexistent.json")

    def test_load_entity_export_from_file_invalid_json(self):
        """Test loading entity export from invalid JSON file."""
        with patch('builtins.open', mock_open(read_data="invalid json")):
            with patch('main.Path.exists', return_value=True):
                with pytest.raises(FileProcessingError, match="Error reading"):
                    load_entity_export_from_file("invalid.json")

    @patch('main.load_entity_export_from_file')
    @patch('main.process_entity_export_data')
    @patch('main.write_entities_csv_report')
    def test_create_entity_export_report_from_file(self, mock_write, mock_process, mock_load, 
                                                   mock_config, sample_entity_data):
        """Test creating entity export report from existing file."""
        mock_load.return_value = sample_entity_data
        mock_df = pd.DataFrame(sample_entity_data)
        mock_process.return_value = mock_df
        
        create_entity_export_report(mock_config, json_file_name="test.json")
        
        mock_load.assert_called_once_with("test.json")
        mock_process.assert_called_once_with(sample_entity_data)
        mock_write.assert_called_once_with(mock_config, mock_df)

    @patch('main.fetch_entity_export_from_vault')
    @patch('main.process_entity_export_data')
    @patch('main.write_entities_csv_report')
    @patch('main.validate_date_format')
    def test_create_entity_export_report_from_api(self, mock_validate, mock_write, mock_process, 
                                                  mock_fetch, mock_config, sample_entity_data):
        """Test creating entity export report from Vault API."""
        mock_fetch.return_value = sample_entity_data
        mock_df = pd.DataFrame(sample_entity_data)
        mock_process.return_value = mock_df
        
        with patch.object(mock_config, 'validate_environment') as mock_validate_env:
            create_entity_export_report(mock_config, start_date="2024-01-01", end_date="2024-01-31")
        
        mock_validate.assert_called()
        mock_validate_env.assert_called_once()
        mock_fetch.assert_called_once_with(mock_config, "2024-01-01", "2024-01-31")
        mock_process.assert_called_once_with(sample_entity_data)
        mock_write.assert_called_once_with(mock_config, mock_df)

    def test_create_entity_export_report_missing_dates(self, mock_config):
        """Test creating entity export report without required dates."""
        with pytest.raises(ValueError, match="start_date and end_date must be provided"):
            create_entity_export_report(mock_config)

    def test_vault_config_entity_properties(self):
        """Test VaultConfig entity export filename properties."""
        config = VaultConfig()
        config.date_str = "20240101"
        
        assert config.entity_export_json_filename == "entity-export-20240101.json"
        assert config.entity_export_entities_csv_filename == "entity-export-20240101.csv"

    def test_dataframe_analysis_columns(self, sample_entity_data):
        """Test that processed DataFrame contains expected analysis columns."""
        df = process_entity_export_data(sample_entity_data)
        
        # Check for timestamp processing
        assert 'timestamp' in df.columns
        assert pd.api.types.is_datetime64_any_dtype(df['timestamp'])
        
        # Check for entity type mapping
        assert 'entity_type' in df.columns
        entity_types = df['entity_type'].unique()
        assert 'entity' in entity_types
        assert 'non_entity' in entity_types


    def test_write_entities_csv_report_success(self, mock_config, sample_entity_data):
        """Test successful entities CSV report writing with full metadata."""
        df = process_entity_export_data(sample_entity_data)
        
        written_rows = []
        def capture_writerow(row):
            written_rows.append(row)
        
        with patch('builtins.open', mock_open()) as mock_file:
            with patch('main.csv.writer') as mock_writer:
                mock_csv_writer = Mock()
                mock_csv_writer.writerow.side_effect = capture_writerow
                mock_writer.return_value = mock_csv_writer
                
                write_entities_csv_report(mock_config, df)
                
                # Verify file was opened for writing with correct filename
                mock_file.assert_called_once_with(mock_config.entity_export_entities_csv_filename, 'w', newline='')
                # Verify CSV writer was used
                mock_writer.assert_called_once()
                # Verify header and data rows were written
                assert mock_csv_writer.writerow.call_count >= 2  # At least header + 1 data row
        
        # Check that we have header and data rows
        assert len(written_rows) >= 2  # At least header + 1 data row
        header_row = written_rows[0]
        
        # Check for basic columns that should always be present
        expected_basic_columns = ['client_id', 'namespace_id', 'timestamp', 'mount_accessor']
        for col in expected_basic_columns:
            assert col in header_row
        
        # Verify all data rows have the same number of columns as header
        for row in written_rows[1:]:
            assert len(row) == len(header_row)
    
    def test_write_entities_csv_report_empty_df(self, mock_config):
        """Test entities CSV report writing with empty DataFrame."""
        empty_df = pd.DataFrame()
        
        # Should not raise an error, just print warning
        write_entities_csv_report(mock_config, empty_df)


if __name__ == "__main__":
    pytest.main([__file__])