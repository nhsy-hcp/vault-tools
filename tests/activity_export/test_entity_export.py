import json
import logging
from unittest.mock import Mock, mock_open, patch

import pandas as pd
import pytest

from src.common.file_utils import (
    FileProcessingError,
)
from src.common.file_utils import read_json as load_entity_export_from_file
from src.common.vault_client import VaultAPIError, VaultClient
from src.entity_export.main import (
    get_entity_export_data as fetch_entity_export_from_vault,
)
from src.entity_export.main import process_entity_export_data
from src.entity_export.main import run_entity_export as create_entity_export_report


@pytest.fixture
def mock_vault_client():
    client = Mock(spec=VaultClient)
    client.get = Mock(return_value=[])
    client.get_cache_stats = Mock(
        return_value={
            "hits": 0,
            "misses": 0,
            "total": 0,
            "hit_rate": "0.00%",
            "cache_size": 0,
            "cache_maxsize": 1000,
        }
    )
    return client


class TestEntityExportFunctionality:
    """Test cases for entity export functionality."""

    @pytest.fixture
    def sample_entity_data(self):
        """Sample entity export data for testing."""
        return [
            {
                "client_id": "client-1",
                "namespace_id": "root",
                "namespace_path": "",
                "timestamp": "2024-01-01T10:00:00Z",
                "mount_accessor": "accessor-1",
                "client_type": "entity",
            },
            {
                "client_id": "client-2",
                "namespace_id": "ns1",
                "namespace_path": "ns1/",
                "timestamp": "2024-01-01T11:00:00Z",
                "mount_accessor": "accessor-2",
                "client_type": "non_entity",
            },
            {
                "client_id": "client-3",
                "namespace_id": "root",
                "namespace_path": "",
                "timestamp": "2024-01-02T09:00:00Z",
                "mount_accessor": "accessor-1",
                "client_type": "entity",
            },
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

    @patch("src.common.file_utils.write_csv")
    @patch("src.common.file_utils.write_json")
    def test_process_entity_export_data_success(self, mock_write_json, mock_write_csv, sample_entity_data):
        """Test successful processing of entity export data."""
        df = process_entity_export_data(sample_entity_data, "test-cluster")

        assert isinstance(df, pd.DataFrame)
        assert len(df) == 3
        assert "entity_type" in df.columns

    def test_process_entity_export_data_empty(self):
        """Test processing empty entity export data."""
        df = process_entity_export_data([], "test-cluster")
        assert df is None

    def test_process_entity_export_data_missing_columns(self):
        """client_type is genuinely required — without it there is no entity_type."""
        incomplete_data = [{"client_id": "client-1"}]
        df = process_entity_export_data(incomplete_data, "test-cluster")
        assert df is None

    def test_load_entity_export_from_file_success(self, sample_entity_data):
        """Test successful loading of entity export from file."""
        json_content = json.dumps(sample_entity_data)
        with patch("builtins.open", mock_open(read_data=json_content)):
            result = load_entity_export_from_file("test.json")
        assert result == sample_entity_data

    def test_load_entity_export_from_file_not_found(self):
        """Test loading entity export from non-existent file."""
        with pytest.raises(FileProcessingError, match="Failed to read or parse"), patch("builtins.open", side_effect=FileNotFoundError):
            load_entity_export_from_file("nonexistent.json")

    @patch("src.entity_export.main.get_entity_export_data")
    @patch("src.entity_export.main.process_entity_export_data")
    def test_create_entity_export_report_from_api(self, mock_process, mock_fetch, mock_vault_client, sample_entity_data):
        """Test creating entity export report from Vault API."""
        mock_fetch.return_value = sample_entity_data
        create_entity_export_report(mock_vault_client, "2024-01-01", "2024-01-31", "test-cluster")

        mock_fetch.assert_called_once_with(mock_vault_client, "2024-01-01", "2024-01-31")
        mock_process.assert_called_once_with(sample_entity_data, "test-cluster", "outputs")


class TestEntityExportWithoutNamespaceColumns:
    """Vault omits namespace columns on non-namespaced (OSS) clusters.

    Regression tests: namespace_id/namespace_path were briefly added to
    REQUIRED_COLUMNS, which turned a working export into a silent no-op for
    those clusters — process_entity_export_data returned None, so neither the
    JSON nor the CSV was written and the run reported nothing exported.
    """

    @pytest.fixture
    def oss_entity_data(self):
        """Entity records as an OSS cluster reports them: no namespace fields."""
        return [
            {
                "client_id": "client-1",
                "timestamp": "2024-01-01T10:00:00Z",
                "mount_accessor": "accessor-1",
                "client_type": "entity",
            },
            {
                "client_id": "client-2",
                "timestamp": "2024-01-01T11:00:00Z",
                "mount_accessor": "accessor-2",
                "client_type": "non_entity",
            },
        ]

    @patch("src.entity_export.main.write_csv")
    @patch("src.entity_export.main.write_json")
    def test_exports_without_namespace_path(self, mock_write_json, mock_write_csv, oss_entity_data, tmp_path):
        df = process_entity_export_data(oss_entity_data, "test-cluster", output_dir=str(tmp_path))

        assert df is not None, "OSS-shaped records were rejected"
        assert len(df) == 2
        assert "entity_type" in df.columns
        mock_write_json.assert_called_once()
        mock_write_csv.assert_called_once()

    @patch("src.entity_export.main.write_csv")
    @patch("src.entity_export.main.write_json")
    def test_warns_but_does_not_fail(self, mock_write_json, mock_write_csv, oss_entity_data, tmp_path, caplog):
        with caplog.at_level(logging.WARNING):
            df = process_entity_export_data(oss_entity_data, "test-cluster", output_dir=str(tmp_path))

        assert df is not None
        assert "Namespace columns absent" in caplog.text

    @patch("src.entity_export.main.write_csv")
    @patch("src.entity_export.main.write_json")
    def test_namespace_id_present_without_path(self, mock_write_json, mock_write_csv, tmp_path):
        """The exact shape the original fixtures had before the branch."""
        data = [
            {
                "client_id": "client-1",
                "namespace_id": "root",
                "timestamp": "2024-01-01T10:00:00Z",
                "client_type": "entity",
            },
        ]
        df = process_entity_export_data(data, "test-cluster", output_dir=str(tmp_path))
        assert df is not None


class TestEntityExportNumericColumns:
    """NaN must not reach the CSV as the literal string '<NA>'."""

    @patch("src.entity_export.main.write_json")
    def test_missing_numeric_value_written_as_zero_not_na(self, mock_write_json, tmp_path):
        """Regression test for the Int64 cast without fillna.

        astype("Int64") preserves NaN as pandas.NA, which serialises to the
        string "<NA>" — silently converting a numeric column to text. The
        previous plain int64 cast raised instead, so the failure was at least
        visible.
        """
        data = [
            {"client_id": "c1", "client_type": "entity", "client_count": 5},
            {"client_id": "c2", "client_type": "entity"},  # client_count absent -> NaN
        ]
        df = process_entity_export_data(data, "test-cluster", output_dir=str(tmp_path))

        assert df is not None
        csv_files = list(tmp_path.glob("*.csv"))
        assert csv_files, "no CSV written"
        content = csv_files[0].read_text()
        assert "<NA>" not in content
        assert df["client_count"].tolist() == [5, 0]
