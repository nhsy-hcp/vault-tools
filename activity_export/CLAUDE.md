# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Purpose

This is a Vault Client Activity Report tool that fetches activity data from HashiCorp Vault servers and generates reports in JSON and CSV formats. It analyzes client usage across namespaces and mount paths for billing and monitoring purposes.

## Architecture

- **main.py**: Refactored with modern Python best practices
  - `VaultConfig`: Configuration class for environment variables and file paths
  - `create_activity_report()`: Main orchestrator function for regular activity reports
  - `create_entity_export_report()`: Main orchestrator function for entity export reports
  - `fetch_data_from_vault()`: Handles Vault API interactions for activity data
  - `fetch_entity_export_from_vault()`: Handles Vault API interactions for entity export data
  - `load_data_from_file()`: Loads activity data from JSON files with format validation
  - `load_entity_export_from_file()`: Loads entity export data from JSON files
  - `process_activity_data()`: Transforms raw activity data into structured format
  - `process_entity_export_data()`: Transforms entity export data using pandas for analysis
  - `write_csv_reports()`: Writes activity CSV files with proper error handling
  - `write_entities_csv_report()`: Writes comprehensive entity export CSV with full metadata
  - `read_activity_report()`: Displays generated activity reports
  - Date utility functions with type hints: `_get_first_day_of_month()`, `_get_last_day_of_month()`, `_get_last_month()`
  - Custom exceptions: `VaultAPIError`, `FileProcessingError`

- **Data Flow**: 
  - **Activity Reports**: Vault API → JSON file → CSV reports (namespaces & mounts)
  - **Entity Export**: Vault API → JSON file → CSV with comprehensive metadata
- **Output Files**: 
  - Activity: `activity-YYYYMMDD.json`, `activity-namespaces-YYYYMMDD.csv`, `activity-mounts-YYYYMMDD.csv`
  - Entity Export: `entity-export-YYYYMMDD.json`, `entity-export-YYYYMMDD.csv`

## Environment Setup

Required environment variables:
- `VAULT_ADDR`: Vault server URL (e.g., https://vault.example.com:8200)
- `VAULT_TOKEN`: Authentication token for Vault access

## Common Commands

Install dependencies:
```bash
pip install -r requirements.txt
```

Install with development dependencies:
```bash
pip install -e ".[dev]"
```

Run tests:
```bash
pytest tests/
```

Generate activity report from Vault API:
```bash
python main.py --start_date 2024-01-01 --end_date 2024-01-31 --print
```

Generate report from existing JSON file:
```bash
python main.py --filename activity-20240425.json --print
```

Use default end date (last month) with required start date:
```bash
python main.py --start_date 2024-01-01 --print
```

Generate entity export report from Vault API:
```bash
python main.py --entity-export --start_date 2024-01-01 --end_date 2024-01-31
```

Generate entity export report from existing JSON file:
```bash
python main.py --entity-export --entity-filename entity-export-20240425.json
```

Enable debug logging:
```bash
python main.py --debug --start_date 2024-01-01 --end_date 2024-01-31 --print
```

## Key Implementation Details

- **Date Range**: `start_date` is required when fetching data from Vault API (no default billing start date)
- Automatic `end_date` defaults to last complete month if not specified
- **Debug Logging**: Configurable debug logging with `--debug` flag for troubleshooting
- **Logging Configuration**: Reduces noise from requests/urllib3 libraries in production mode
- TLS verification enabled by default for security (requests library)
- Timeout set to 300 seconds for Vault API calls
- Supports both fresh data fetch and processing existing JSON files
- Handles multiple JSON file formats (with/without "data" wrapper)
- Comprehensive error handling with custom exceptions
- Type hints throughout for better code maintainability
- CSV output includes namespace summaries and detailed mount-level breakdowns
- Proper input validation for date formats and environment variables

### Entity Export Features

- **API Endpoint**: Uses `/sys/internal/counters/activity/export` (tech preview)
- **Data Analysis**: Leverages pandas for advanced data processing and analysis
- **Export Formats**: 
  - JSON for raw data
  - Basic CSV with core activity fields (client_id, namespace_id, timestamp, mount_accessor, entity_type)
  - Comprehensive CSV with full metadata (entity names, aliases, policies, custom metadata, group memberships)
- **Timestamp Handling**: Converts to RFC3339 format for API calls, processes with pandas
- **Metadata Support**: Includes entity metadata, alias metadata, policies, and group memberships
- **JSON Serialization**: Complex fields (policies, metadata) serialized as JSON strings in CSV
- **Flexible Input**: Supports both API fetching and processing existing JSON files
- **Error Handling**: Robust error handling for API failures and data processing issues