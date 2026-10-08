from unittest.mock import patch

from src.activity_export.main import run_activity_export


class TestCreateActivityReportIntegration:
    """Integration tests for create_activity_report function."""

    def test_create_report_from_json_file(self, mock_vault_client, sample_activity_data):
        """Test creating report from JSON file end-to-end."""
        with patch("src.activity_export.main.write_csv") as mock_write, patch("src.activity_export.main.write_json"), patch("src.activity_export.main.write_markdown"):
            run_activity_export(
                mock_vault_client,
                "2024-01-01",
                "2024-01-31",
                "test-cluster",
                data=sample_activity_data,
            )
            assert mock_write.call_count == 2

    def test_create_report_from_vault_api(self, mock_vault_client, sample_activity_data):
        """Test creating report from Vault API end-to-end."""
        mock_vault_client.get.return_value = {"data": sample_activity_data}

        with patch("src.activity_export.main.write_csv") as mock_write, patch("src.activity_export.main.write_json"), patch("src.activity_export.main.write_markdown"):
            run_activity_export(mock_vault_client, "2024-01-01", "2024-01-31", "test-cluster")
            assert mock_write.call_count == 2


class TestMainFunctionIntegration:
    """Integration tests for main function."""

    def test_run_activity_export_with_client(self, mock_vault_client, sample_activity_data):
        """Test run_activity_export function directly."""
        mock_vault_client.get.return_value = {"data": sample_activity_data}

        with patch("src.activity_export.main.write_csv"), patch("src.activity_export.main.write_json"), patch("src.activity_export.main.write_markdown"):
            result = run_activity_export(mock_vault_client, "2024-01-01", "2024-01-31", "test-cluster")

            # Verify function completed successfully
            assert result is not None
            assert len(result.namespaces) == 1
            assert len(result.mounts) == 1
            assert result.findings_document["tool"]["name"] == "vault-tools"


def test_export_file_names_carry_the_short_cluster_id(mock_vault_client, sample_activity_data):
    with patch("src.activity_export.main.write_csv") as write_csv, patch("src.activity_export.main.write_json") as write_json, patch("src.activity_export.main.write_markdown") as write_markdown:
        run_activity_export(mock_vault_client, "2024-01-01", "2024-01-31", "vault-cluster", data=sample_activity_data, cluster_id="d33099d9-206e-53c2-4e50-44fb62ac69a6")
    paths = [c.args[0] for m in (write_csv, write_json, write_markdown) for c in m.call_args_list]
    assert paths and all("/vault-cluster-d33099d9-" in p for p in paths)
