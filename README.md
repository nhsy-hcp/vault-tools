# Vault Tools

A unified CLI tool for comprehensive HashiCorp Vault operations, providing defensive security capabilities for namespace auditing, activity monitoring, and entity management.

## Features

- **Namespace Audit**: Multi-threaded namespace traversal with rate limiting and comprehensive reporting
- **Activity Export**: Vault activity log processing and export with flexible date ranges
- **Entity Export**: Entity data extraction and CSV/JSON reporting

## Quick Start

1. **Prerequisites**: Python 3.8+ and access to a HashiCorp Vault instance
2. **Install**: `pip install -r requirements.txt`
3. **Configure**: Set `VAULT_ADDR` and `VAULT_TOKEN` environment variables
4. **Run**: `python main.py --help` to see available commands

## Installation

### Prerequisites

- Python 3.8 or higher
- Access to a HashiCorp Vault instance
- Valid Vault token with appropriate permissions

### Setup

1. Clone the repository:
   ```bash
   git clone https://github.com/your-username/vault-tools.git
   cd vault-tools
   ```

2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

3. Verify installation:
   ```bash
   python main.py --help
   ```

## Usage

The main entry point is `main.py` with three primary subcommands:

### Namespace Audit

Comprehensively audit Vault namespaces, auth methods, and secret engines:

```bash
# Basic namespace audit
python main.py namespace-audit

# Audit with custom worker count and output directory
python main.py namespace-audit --workers 8 --output-dir custom-output

# See all options
python main.py namespace-audit --help
```

### Activity Export

Export Vault activity logs and usage metrics:

```bash
# Export activity logs for the last 30 days
python main.py activity-export --days 30

# Export for specific date range
python main.py activity-export --start-date 2024-01-01 --end-date 2024-01-31

# See all options
python main.py activity-export --help
```

### Entity Export

Extract and export Vault entity data:

```bash
# Basic entity export
python main.py entity-export

# See all options
python main.py entity-export --help
```

## Configuration

### Required Environment Variables

Set the following environment variables before running the tool:

```bash
export VAULT_ADDR="https://vault.example.com"
export VAULT_TOKEN="your-vault-token"
export VAULT_SKIP_VERIFY="true"  # Optional, for dev environments
```

### Optional Configuration

Additional environment variables for customization:

```bash
# Output and logging
export VAULT_TOOLS_OUTPUT_DIR="custom-outputs"  # Default: "outputs"
export VAULT_TOOLS_DEBUG="true"                 # Default: false

# Performance tuning (namespace audit)
export VAULT_TOOLS_WORKERS="8"                  # Default: 4
export VAULT_TOOLS_NO_RATE_LIMIT="true"         # Default: false
export VAULT_TOOLS_RATE_LIMIT_BATCH="50"        # Default: 100
export VAULT_TOOLS_RATE_LIMIT_SLEEP="5"         # Default: 3 seconds
export VAULT_TOOLS_TIMEOUT="60"                 # Default: 30 seconds

# Namespace targeting
export VAULT_TOOLS_NAMESPACE="team-a/"          # Default: root namespace
```

### Centralized Configuration System

The tool uses a centralized configuration system with the following benefits:
- **Environment-based configuration**: All settings can be controlled via environment variables
- **Type validation**: Configuration values are validated at startup
- **Consistent defaults**: Sensible defaults across all modules
- **Error reporting**: Clear error messages for misconfiguration

## Testing

The project includes comprehensive test suites for all modules:

```bash
# Run all tests
pytest tests/ -v

# Run specific module tests
pytest tests/namespace_audit/ -v
pytest tests/activity_export/ -v

# Run tests with coverage
pytest tests/ --cov=src --cov-report=html
```

### Test Structure

- **119 total tests** across all modules with zero hanging issues
- **namespace_audit**: 89+ tests covering threading, mocking, and integration scenarios
- **activity_export**: 30+ tests covering API interaction, data processing, and file operations
- **Centralized fixtures**: Reusable mock configurations and test data in `fixtures.py` files
- **Modular organization**: Tests split by functionality for maintainability
- **No hanging tests**: All threading and queue operations properly mocked

## Development Notes

### Recent Improvements (Phase 2)

The codebase has been enhanced with the following improvements:

#### **Code Quality Enhancements**
- **Eliminated Dead Code**: Removed unused argument parsing functions from main.py
- **Cleaned Up Redundancy**: Removed unnecessary `finally: pass` blocks and duplicate logging
- **Enhanced Error Messages**: Improved VaultClient error messages with actionable troubleshooting hints

#### **Centralized Configuration**
- **New Configuration System**: Introduced `src/common/config.py` for unified configuration management
- **Environment-Based Settings**: All configuration controllable via environment variables
- **Configurable Output Directory**: Output directory now configurable via `VAULT_TOOLS_OUTPUT_DIR`

#### **Enhanced Error Handling**
- **Specific Exception Classes**: Added `VaultDataError`, `VaultPermissionError`, and `ConfigurationError`
- **Better Diagnostics**: More specific error context for troubleshooting connection and permission issues

#### **Test Suite Improvements**
- **Fixed Mock Issues**: Proper context manager mocking using `MagicMock`
- **Eliminated Hanging Tests**: Replaced problematic threading tests with reliable mocks
- **Modular Organization**: Tests split into focused, maintainable modules
- **Centralized Fixtures**: Shared test configurations and test data
- **119 Total Tests**: Comprehensive coverage with zero hanging issues

## Architecture Overview

### Core Design Principles

- **Defensive Security Focus**: All tools designed for security analysis and auditing
- **Modular Architecture**: Each tool is a separate module with clear boundaries
- **Thread Safety**: Multi-threaded operations with proper synchronization
- **Rate Limiting**: Built-in protection against API overload
- **Comprehensive Error Handling**: Specific exception types with actionable messages

### Key Components

- **`main.py`**: Unified CLI entry point with subcommands
- **`src/common/`**: Shared utilities (VaultClient, Config, FileUtils)
- **`src/namespace_audit/`**: Multi-threaded namespace traversal
- **`src/activity_export/`**: Activity log processing and export
- **`src/entity_export/`**: Entity data extraction

### Output Structure

All tools generate structured output in the configured directory (default: `outputs/`):

- **JSON files**: Raw API responses for programmatic access
- **CSV files**: Processed summaries for analysis
- **Naming pattern**: `{cluster-name}-{data-type}-{YYYYMMDD}.{ext}`

## Contributing

1. Fork the repository
2. Create a feature branch: `git checkout -b feature-name`
3. Make changes and add tests
4. Run the test suite: `pytest tests/ -v`
5. Submit a pull request

### Development Guidelines

- Follow existing code patterns and naming conventions
- Add tests for new functionality
- Update documentation for user-facing changes
- Ensure all tests pass before submitting

## License

This project is intended for defensive security purposes only. Use responsibly and in accordance with your organization's security policies.

## Support

For issues, questions, or contributions, please use the project's issue tracker.