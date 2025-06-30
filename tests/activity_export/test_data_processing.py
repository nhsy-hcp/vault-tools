"""Tests for data processing functions."""
import json
import pytest
from unittest.mock import patch, mock_open
from pathlib import Path

from src.activity_export.main import process_activity_data
from src.common.file_utils import FileProcessingError, read_json
from src.common.utils import validate_date_format




class TestValidateDateFormat:
    """Test cases for date format validation."""
    
    def test_valid_date_format(self):
        """Test validation with valid date format."""
        # Should not raise an exception
        validate_date_format("2024-01-01")
        validate_date_format("2023-12-31")
        validate_date_format("2025-06-15")
    
    def test_invalid_date_format(self):
        """Test validation with invalid date formats."""
        with pytest.raises(ValueError, match=r"Invalid date format.*Expected format"):
            validate_date_format("2024/01/01")
        
        with pytest.raises(ValueError, match=r"Invalid date format.*Expected format"):
            validate_date_format("01-01-2024")
        
        with pytest.raises(ValueError, match=r"Invalid date format.*Expected format"):
            validate_date_format("2024.01.01")
        
        with pytest.raises(ValueError, match=r"Invalid date format.*Expected format"):
            validate_date_format("invalid-date")
    
    def test_invalid_date_values(self):
        """Test validation with invalid date values."""
        with pytest.raises(ValueError, match=r"Invalid date format.*Expected format"):
            validate_date_format("2024-13-01")  # Invalid month
        
        with pytest.raises(ValueError, match=r"Invalid date format.*Expected format"):
            validate_date_format("2024-02-30")  # Invalid day


class TestReadJson:
    """Test cases for reading data from JSON files using read_json."""
    
    def test_read_valid_json(self):
        """Test reading a valid JSON file."""
        test_data = {
            "by_namespace": [{"namespace_id": "root", "namespace_path": ""}],
            "total": {"clients": 5}
        }
        
        with patch("builtins.open", mock_open(read_data=json.dumps(test_data))):
            result = read_json("test.json")
            assert result == test_data
    
    def test_read_json_file_not_found(self):
        """Test reading non-existent file."""
        with patch("builtins.open", side_effect=FileNotFoundError):
            with pytest.raises(FileProcessingError, match="Failed to read or parse"):
                read_json("nonexistent.json")
    
    def test_read_invalid_json(self):
        """Test reading invalid JSON file."""
        with patch("builtins.open", mock_open(read_data="invalid json")):
            with pytest.raises(FileProcessingError, match="Failed to read or parse"):
                read_json("invalid.json")


class TestProcessActivityData:
    """Test cases for processing activity data."""
    
    def test_process_empty_data(self):
        """Test processing empty activity data."""
        data = {}
        namespaces, mounts = process_activity_data(data, "test-cluster")
        
        # Should return headers only
        assert len(namespaces) == 0
        assert len(mounts) == 0
    
    def test_process_single_namespace(self):
        """Test processing data with single namespace."""
        data = {
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
        
        namespaces, mounts = process_activity_data(data, "test-cluster")
        
        assert len(namespaces) == 1  # 1 namespace
        assert len(mounts) == 1      # 1 mount
        
        assert namespaces[0] == {'namespace_id': 'root', 'namespace_path': 'root/', 'mounts': 1, 'clients': 5, 'entity_clients': 4, 'non_entity_clients': 1}
        assert mounts[0] == {'namespace_id': 'root', 'namespace_path': 'root/', 'mount_path': 'auth/token/', 'clients': 3, 'entity_clients': 2, 'non_entity_clients': 1}
    
    def test_process_multiple_namespaces_and_mounts(self):
        """Test processing data with multiple namespaces and mounts."""
        data = {
            "by_namespace": [
                {
                    "namespace_id": "root",
                    "namespace_path": "",
                    "counts": {"clients": 5, "entity_clients": 4, "non_entity_clients": 1},
                    "mounts": [
                        {
                            "mount_path": "auth/token/",
                            "counts": {"clients": 3, "entity_clients": 2, "non_entity_clients": 1}
                        },
                        {
                            "mount_path": "secret/",
                            "counts": {"clients": 2, "entity_clients": 2, "non_entity_clients": 0}
                        }
                    ]
                },
                {
                    "namespace_id": "ns1",
                    "namespace_path": "ns1/",
                    "counts": {"clients": 3, "entity_clients": 3, "non_entity_clients": 0},
                    "mounts": [
                        {
                            "mount_path": "auth/userpass/",
                            "counts": {"clients": 3, "entity_clients": 3, "non_entity_clients": 0}
                        }
                    ]
                }
            ]
        }
        
        namespaces, mounts = process_activity_data(data, "test-cluster")
        
        assert len(namespaces) == 2  # 2 namespaces
        assert len(mounts) == 3      # 3 mounts
        
        # Check namespace data
        assert namespaces[0] == {'namespace_id': 'root', 'namespace_path': 'root/', 'mounts': 2, 'clients': 5, 'entity_clients': 4, 'non_entity_clients': 1}
        assert namespaces[1] == {'namespace_id': 'ns1', 'namespace_path': 'ns1/', 'mounts': 1, 'clients': 3, 'entity_clients': 3, 'non_entity_clients': 0}
        
        # Check mount data
        assert mounts[0] == {'namespace_id': 'root', 'namespace_path': 'root/', 'mount_path': 'auth/token/', 'clients': 3, 'entity_clients': 2, 'non_entity_clients': 1}
        assert mounts[1] == {'namespace_id': 'root', 'namespace_path': 'root/', 'mount_path': 'secret/', 'clients': 2, 'entity_clients': 2, 'non_entity_clients': 0}
        assert mounts[2] == {'namespace_id': 'ns1', 'namespace_path': 'ns1/', 'mount_path': 'auth/userpass/', 'clients': 3, 'entity_clients': 3, 'non_entity_clients': 0}
    
    def test_process_data_missing_fields(self):
        """Test processing data with missing optional fields."""
        data = {
            "by_namespace": [
                {
                    "namespace_id": "root",
                    # Missing namespace_path
                    # Missing counts
                    "mounts": [
                        {
                            # Missing mount_path
                            # Missing counts
                        }
                    ]
                }
            ]
        }
        
        namespaces, mounts = process_activity_data(data, "test-cluster")
        
        assert len(namespaces) == 1
        assert len(mounts) == 1
        
        # Should use default values for missing fields
        assert namespaces[0] == {'namespace_id': 'root', 'namespace_path': 'root/', 'mounts': 1, 'clients': 0, 'entity_clients': 0, 'non_entity_clients': 0}
        assert mounts[0] == {'namespace_id': 'root', 'namespace_path': 'root/', 'mount_path': '', 'clients': 0, 'entity_clients': 0, 'non_entity_clients': 0}