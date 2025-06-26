# Vault Client Activity Report

## Description

This project includes a Python script, `main.py`, that generates and reads activity reports for Vault client usage. The script fetches data from a Vault server, processes it, and outputs the results in JSON and CSV formats. The codebase follows modern Python best practices with comprehensive error handling, type hints, and extensive test coverage.

## Features

- Generate activity reports for namespaces and mounts
- Generate entity export reports with comprehensive metadata analysis
- Fetch data from a Vault server using specified date ranges
- Process existing JSON activity and entity export files
- Multiple CSV output formats:
  - Basic activity data (5 core columns)
  - Comprehensive entity metadata (16 columns with policies, groups, custom metadata)
- Print activity reports to the console
- Debug logging support for troubleshooting
- JSON serialization for complex fields (policies, metadata objects)
- Comprehensive error handling and validation
- Type hints for better code maintainability
- Extensive test coverage with pytest

## Requirements

- Python 3.8+
- `pip` for managing dependencies
- Required Python packages (listed in `requirements.txt`):
  - `requests>=2.31.0,<3.0.0` (currently 2.32.4)
  - `pandas>=2.2.2,<3.0.0` (currently 2.3.0)
  - `pytest>=8.1.1,<9.0.0` (currently 8.4.1) (for testing)

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/nhsy-hcp/vault-tools.git
   cd activity_export
   ```

2. Install the required packages:
   ```bash
   pip install -r requirements.txt
   ``` 

3. For development with testing dependencies:
   ```bash
   pip install -e ".[dev]"
   ```

4. Ensure you have access to a Vault server and have the necessary permissions to fetch activity data.

5. Set the required environment variables:
   ```bash
   export VAULT_ADDR='https://your-vault-server:8200'
   export VAULT_TOKEN='your-vault-token'
   ```

## Usage

### Generate Activity Report from Vault API
```bash
# Generate report for specific date range
python main.py -s 2024-01-01 -e 2024-01-31 -p

# Generate report for last month (requires start_date)
python main.py -s 2024-01-01 -p
```

### Generate Entity Export Report
```bash
# Generate entity export report for specific date range
python main.py --entity-export -s 2024-01-01 -e 2024-01-31

# Process existing entity export JSON file
python main.py --entity-export --entity-filename entity-export-20240425.json
```

### Debug Logging
```bash
# Enable debug logging for troubleshooting
python main.py --debug -s 2024-01-01 -e 2024-01-31 -p
```

### Process Existing JSON File
```bash
# Process existing activity JSON file
python main.py -f activity-20240425.json -p
```

### CLI Arguments

The script supports the following command-line arguments:

```
usage: main.py [-h] [-s START_DATE] [-e END_DATE] [-f FILENAME]
               [-p | --print | --no-print]
               [--entity-export | --no-entity-export]
               [--entity-filename ENTITY_FILENAME] [--debug | --no-debug]

options:
  -h, --help            show this help message and exit
  -s, --start_date START_DATE
                        Start date (YYYY-MM-DD) for the activity report
  -e, --end_date END_DATE
                        End date (YYYY-MM-DD) for the activity report
  -f, --filename FILENAME
                        JSON file name for the activity report
  -p, --print, --no-print
                        Print the activity report to console
  --entity-export, --no-entity-export
                        Generate entity export report instead of regular
                        activity report
  --entity-filename ENTITY_FILENAME
                        JSON file name for the entity export report
  --debug, --no-debug   Enable debug logging
```

**Important:** The `start_date` parameter is now required when fetching data from the Vault API (not using existing JSON files).

## Testing

This project includes comprehensive test coverage using pytest. Tests are organized into multiple categories:

### Test Structure
- `tests/test_default.py` - Basic utility function tests
- `tests/test_config.py` - VaultConfig class tests
- `tests/test_data_processing.py` - Data processing and validation tests
- `tests/test_vault_api.py` - Vault API interaction tests
- `tests/test_integration.py` - End-to-end integration tests
- `tests/test_entity_export.py` - Entity export functionality tests (62 total tests)

### Running Tests

#### Command Line
```bash
# Run all tests
pytest

# Run with verbose output
pytest -v

# Run specific test file
pytest tests/test_config.py

# Run tests with coverage
pytest --cov=main --cov-report=html

# Run tests matching a pattern
pytest -k "test_config"
```

#### PyCharm IDE
The project is configured for PyCharm IDE integration:

1. **Configure Test Runner:**
   - Go to File → Settings → Tools → Python Integrated Tools
   - Set "Default test runner" to "pytest"

2. **Run Tests:**
   - Right-click on `tests` folder → "Run pytest in tests"
   - Right-click on individual test files to run specific tests
   - Use the green arrow icons next to test functions

3. **Debug Tests:**
   - Set breakpoints in test code
   - Right-click → "Debug pytest in tests"

4. **View Coverage:**
   - Run → "Run 'pytest in tests' with Coverage"
   - Coverage results will appear in the Coverage tool window

### Test Configuration
- `pytest.ini` - pytest configuration for CLI usage
- `pyproject.toml` - Modern Python project configuration with pytest settings
- Custom markers for test categorization (unit, integration, api, slow)

### Test Categories
```bash
# Run only unit tests
pytest -m unit

# Run only integration tests  
pytest -m integration

# Skip slow tests
pytest -m "not slow"
```

## Output Files

### Activity Reports
- `activity-YYYYMMDD.json` - Raw activity data from Vault
- `activity-namespaces-YYYYMMDD.csv` - Namespace-level summary
- `activity-mounts-YYYYMMDD.csv` - Mount-level detailed breakdown

### Entity Export Reports
- `entity-export-YYYYMMDD.json` - Raw entity export data from Vault
- `entity-export-YYYYMMDD.csv` - Comprehensive entity metadata export (16 columns)

## Architecture

The codebase is organized with modern Python best practices:

- **VaultConfig**: Configuration management class
- **Custom Exceptions**: VaultAPIError, FileProcessingError
- **Modular Functions**: Separated concerns for API, file I/O, and data processing
- **Type Hints**: Full type annotation for better IDE support
- **Error Handling**: Comprehensive exception handling and validation

## Development

### Code Quality
The project follows Python best practices:
- Type hints throughout
- Proper error handling with custom exceptions
- Input validation
- Modular, testable functions
- Comprehensive documentation

### Adding Tests
When adding new functionality:
1. Add unit tests for individual functions
2. Add integration tests for end-to-end workflows
3. Update test markers as appropriate
4. Ensure coverage remains high

### Dependencies
Core dependencies are minimal and production-focused:
- `requests` for HTTP API calls
- `pandas` for potential data processing enhancements

Development dependencies include:
- `pytest` for testing framework
- `pytest-cov` for coverage reporting
- `pytest-mock` for mocking capabilities