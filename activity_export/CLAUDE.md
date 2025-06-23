# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Purpose

This is a Vault Client Activity Report tool that fetches activity data from HashiCorp Vault servers and generates reports in JSON and CSV formats. It analyzes client usage across namespaces and mount paths for billing and monitoring purposes.

## Architecture

- **main.py**: Refactored with modern Python best practices
  - `VaultConfig`: Configuration class for environment variables and file paths
  - `create_activity_report()`: Main orchestrator function
  - `fetch_data_from_vault()`: Handles Vault API interactions
  - `load_data_from_file()`: Loads data from JSON files with format validation
  - `process_activity_data()`: Transforms raw data into structured format
  - `write_csv_reports()`: Writes CSV files with proper error handling
  - `read_activity_report()`: Displays generated reports
  - Date utility functions with type hints: `_get_first_day_of_month()`, `_get_last_day_of_month()`, `_get_last_month()`
  - Custom exceptions: `VaultAPIError`, `FileProcessingError`

- **Data Flow**: Vault API → JSON file → CSV reports (namespaces & mounts)
- **Output Files**: `activity-YYYYMMDD.json`, `activity-namespaces-YYYYMMDD.csv`, `activity-mounts-YYYYMMDD.csv`

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

Use default date range (billing start to last month):
```bash
python main.py --print
```

## Key Implementation Details

- Default billing start date: 2023-06-01
- Automatic date range defaults to last complete month if not specified
- TLS verification enabled by default for security (requests library)
- Timeout set to 300 seconds for Vault API calls
- Supports both fresh data fetch and processing existing JSON files
- Handles multiple JSON file formats (with/without "data" wrapper)
- Comprehensive error handling with custom exceptions
- Type hints throughout for better code maintainability
- CSV output includes namespace summaries and detailed mount-level breakdowns
- Proper input validation for date formats and environment variables