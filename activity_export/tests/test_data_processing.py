"""Tests for data processing functions."""
import json
import os
import sys
import pytest
from unittest.mock import patch, mock_open
from pathlib import Path

sys.path.insert(0, f"{os.path.dirname(__file__)}/../")

from main import (
    validate_date_format, 
    load_data_from_file, 
    process_activity_data,
    FileProcessingError
)


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


class TestLoadDataFromFile:
    """Test cases for loading data from JSON files."""
    
    def test_load_data_with_data_wrapper(self):
        """Test loading JSON file with 'data' wrapper."""
        test_data = {
            "data": {
                "by_namespace": [{"namespace_id": "root", "namespace_path": ""}],
                "total": {"clients": 5}
            }
        }
        
        with patch("builtins.open", mock_open(read_data=json.dumps(test_data))):
            with patch("pathlib.Path.exists", return_value=True):
                result = load_data_from_file("test.json")
                assert result == test_data["data"]
    
    def test_load_data_without_data_wrapper(self):
        """Test loading JSON file without 'data' wrapper."""
        test_data = {
            "by_namespace": [{"namespace_id": "root", "namespace_path": ""}],
            "total": {"clients": 5}
        }
        
        with patch("builtins.open", mock_open(read_data=json.dumps(test_data))):
            with patch("pathlib.Path.exists", return_value=True):
                result = load_data_from_file("test.json")
                assert result == test_data
    
    def test_load_data_file_not_found(self):
        """Test loading non-existent file."""
        with patch("pathlib.Path.exists", return_value=False):
            with pytest.raises(FileProcessingError, match="File not found"):
                load_data_from_file("nonexistent.json")
    
    def test_load_data_invalid_json(self):
        """Test loading invalid JSON file."""
        with patch("builtins.open", mock_open(read_data="invalid json")):
            with patch("pathlib.Path.exists", return_value=True):
                with pytest.raises(FileProcessingError, match="Error reading file"):
                    load_data_from_file("invalid.json")
    
    def test_load_data_missing_required_keys(self):
        """Test loading JSON file missing required keys."""
        test_data = {"other_key": "value"}
        
        with patch("builtins.open", mock_open(read_data=json.dumps(test_data))):
            with patch("pathlib.Path.exists", return_value=True):
                with pytest.raises(FileProcessingError, match="missing 'by_namespace' key"):
                    load_data_from_file("test.json")


class TestProcessActivityData:
    """Test cases for processing activity data."""
    
    def test_process_empty_data(self):
        """Test processing empty activity data."""
        data = {}
        namespaces, mounts = process_activity_data(data)
        
        # Should return headers only
        assert len(namespaces) == 1
        assert len(mounts) == 1
        assert namespaces[0] == ['namespace_id', 'namespace_path', 'mounts', 'clients', 'entity_clients', 'non_entity_clients']
        assert mounts[0] == ['namespace_id', 'namespace_path', 'mount_path', 'clients', 'entity_clients', 'non_entity_clients']
    
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
        
        namespaces, mounts = process_activity_data(data)
        
        assert len(namespaces) == 2  # Header + 1 namespace
        assert len(mounts) == 2      # Header + 1 mount
        
        assert namespaces[1] == ['root', '', 1, 5, 4, 1]
        assert mounts[1] == ['root', '', 'auth/token/', 3, 2, 1]
    
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
        
        namespaces, mounts = process_activity_data(data)
        
        assert len(namespaces) == 3  # Header + 2 namespaces
        assert len(mounts) == 4      # Header + 3 mounts
        
        # Check namespace data
        assert namespaces[1] == ['root', '', 2, 5, 4, 1]
        assert namespaces[2] == ['ns1', 'ns1/', 1, 3, 3, 0]
        
        # Check mount data
        assert mounts[1] == ['root', '', 'auth/token/', 3, 2, 1]
        assert mounts[2] == ['root', '', 'secret/', 2, 2, 0]
        assert mounts[3] == ['ns1', 'ns1/', 'auth/userpass/', 3, 3, 0]
    
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
        
        namespaces, mounts = process_activity_data(data)
        
        assert len(namespaces) == 2
        assert len(mounts) == 2
        
        # Should use default values for missing fields
        assert namespaces[1] == ['root', '', 1, 0, 0, 0]
        assert mounts[1] == ['root', '', '', 0, 0, 0]