# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Security Notice

This project is designed for **defensive security purposes only**. All tools are intended for:
- Security auditing and assessment
- Compliance monitoring
- Infrastructure analysis
- Defensive security operations

Do not use these tools for malicious purposes or unauthorized access.

## Project Overview

Vault Tools is a unified CLI tool for interacting with HashiCorp Vault, providing three main capabilities:
- **Namespace Audit**: Comprehensive auditing of Vault namespaces, auth methods, and secret engines
- **Activity Export**: Export Vault activity logs and usage metrics
- **Entity Export**: Export Vault entity data

## Commands

### Development Commands
```bash
# Install dependencies
pip install -r requirements.txt

# Run the main CLI
python main.py --help

# Run specific tools
python main.py namespace-audit --help
python main.py activity-export --help
python main.py entity-export --help

# Run tests
pytest tests/
pytest tests/namespace_audit/  # Run specific module tests
pytest -v                     # Verbose output
```

### Environment Variables Required
```bash
export VAULT_ADDR="https://vault.example.com"
export VAULT_TOKEN="your-vault-token"
export VAULT_SKIP_VERIFY="true"  # Optional, for dev environments
```

### Optional Configuration Variables
```bash
export VAULT_TOOLS_OUTPUT_DIR="custom-outputs"  # Default: "outputs"
export VAULT_TOOLS_DEBUG="true"                 # Default: false
export VAULT_TOOLS_WORKERS="8"                  # Default: 4 (namespace audit)
export VAULT_TOOLS_NO_RATE_LIMIT="true"         # Default: false
export VAULT_TOOLS_NAMESPACE="team-a/"          # Default: root namespace
export VAULT_TOOLS_RATE_LIMIT_BATCH="50"        # Default: 100
export VAULT_TOOLS_RATE_LIMIT_SLEEP="5"         # Default: 3 seconds
export VAULT_TOOLS_TIMEOUT="60"                 # Default: 30 seconds
```

### Testing Commands
```bash
# Run all tests
pytest tests/ -v

# Run specific module tests  
pytest tests/namespace_audit/ -v
pytest tests/activity_export/ -v

# Run tests with coverage
pytest tests/ --cov=src --cov-report=html

# Run tests excluding slow ones
pytest tests/ -m "not slow" -v
```

## Architecture

### Core Components

1. **Main CLI (`main.py`)**: Unified entry point with subcommands for each tool
2. **Common Utilities (`src/common/`)**:
   - `vault_client.py`: Centralized Vault client with connection validation and enhanced error handling
   - `config.py`: Centralized configuration management with environment variable support
   - `file_utils.py`: Shared file I/O utilities for JSON/CSV output
   - `utils.py`: Common utilities across modules

3. **Module Structure**: Each tool is organized as a separate module under `src/`:
   - `namespace_audit/`: Multi-threaded namespace traversal with rate limiting
   - `activity_export/`: Vault activity log processing and export
   - `entity_export/`: Entity data extraction and export

### Key Design Patterns

- **Context Manager Pattern**: VaultClient uses context managers for proper resource cleanup
- **Worker Thread Pool**: NamespaceAuditor uses configurable worker threads for parallel processing
- **Rate Limiting**: Built-in rate limiting with configurable batch sizes and sleep intervals
- **Structured Data Classes**: Uses dataclasses for configuration and statistics tracking
- **Centralized Configuration**: Environment-based configuration system with validation
- **Enhanced Error Handling**: Specific exception classes for better error context
- **Centralized Logging**: Consistent logging across all modules

### Threading Model

The namespace audit tool uses a producer-consumer pattern:
- Main thread populates a queue with namespace paths
- Worker threads consume paths and traverse child namespaces
- Thread-safe data collection with locks for shared state
- Configurable worker count (default: 4 threads)

### Output Structure

All tools write to configurable output directory (default: `outputs/`) with consistent naming:
- JSON files: Raw API responses for programmatic access
- CSV files: Processed summaries for analysis
- Filename pattern: `{cluster-name}-{data-type}-{YYYYMMDD}.{ext}`
- **Configurable**: Set `VAULT_TOOLS_OUTPUT_DIR` environment variable

### Enhanced Error Handling

- **Specific Exceptions**: 
  - `VaultConnectionError`: Connection and authentication issues
  - `VaultDataError`: Malformed API responses
  - `VaultPermissionError`: Authorization issues
  - `ConfigurationError`: Invalid configuration
- **Enhanced Messages**: Actionable troubleshooting hints in error messages
- **Graceful Permission Handling**: Logs warnings for forbidden namespaces
- **Comprehensive Error Statistics**: Detailed error reporting and tracking

### Test Suite Architecture

#### Comprehensive Test Coverage
- **119 total tests** across all modules with no hanging issues
- **namespace_audit**: 89+ tests including threading, mocking, and integration
- **activity_export**: 30+ tests covering API interaction and data processing
- **Centralized fixtures**: Reusable mock configurations in `fixtures.py` files
- **Modular structure**: Tests organized by functionality for maintainability

#### Key Test Improvements
- **Fixed Mock Issues**: Proper `MagicMock` usage for context managers
- **Eliminated Hanging Tests**: Replaced problematic threading tests with reliable mocks
- **Import Path Corrections**: Fixed patching locations for write operations
- **Thread Safety Testing**: Comprehensive concurrency and queue operation tests
- **Error Condition Coverage**: Edge cases and failure scenarios properly tested

#### Test Organization
- `test_data_classes.py`: Statistics and data storage unit tests
- `test_auditor_core.py`: Core functionality and configuration tests  
- `test_namespace_traversal.py`: API interaction and data fetching tests
- `test_worker_threads.py`: Threading and concurrency behavior tests
- `test_integration_simple.py`: Component interaction and workflow tests
- `test_integration.py`: Full end-to-end workflow tests
- `fixtures.py`: Centralized test fixtures and mock configurations
- `test_default.py`: Compatibility layer for CI/CD systems

#### Key Test Fixes
- **Queue Operations**: Proper mocking of `queue.Queue` to prevent hanging
- **Threading Mock**: Complete `threading.Thread` and queue lifecycle mocking
- **Context Managers**: Correct `VaultClient.get_client()` context manager mocking
- **Import Patching**: Fixed write operation mocking at correct module paths
- **Exception Handling**: Proper `KeyboardInterrupt` and error condition testing

#### Running Tests
```bash
# All tests with verbose output
pytest tests/ -v

# Specific test modules
pytest tests/namespace_audit/test_auditor_core.py -v
pytest tests/activity_export/test_vault_api.py -v

# Tests by category
pytest tests/ -m "unit" -v        # Unit tests only
pytest tests/ -m "not slow" -v   # Exclude slow tests
pytest tests/ -m "integration" -v # Integration tests only

# With coverage reporting
pytest tests/ --cov=src --cov-report=html

# Stop on first failure
pytest tests/ -x
```

## Development Workflow

### Code Standards
- Follow existing patterns and naming conventions
- Use type hints where appropriate
- Add docstrings for public functions and classes
- Maintain thread safety in concurrent code
- Handle errors gracefully with specific exception types

### Testing Requirements
- Add tests for new functionality
- Ensure all existing tests pass
- Use proper mocking for external dependencies
- Test error conditions and edge cases
- Maintain test organization by functionality

### Performance Considerations
- Use appropriate rate limiting for API calls
- Implement proper threading patterns for concurrent operations
- Monitor resource usage in multi-threaded code
- Use efficient data structures for large datasets