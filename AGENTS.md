# Vault Tools

## Project Overview

Vault Tools is a unified CLI tool for interacting with HashiCorp Vault, providing three main capabilities:

- **Namespace Audit**: Comprehensive auditing of Vault namespaces, auth methods, and secret engines, with a markdown audit report
- **Activity Export**: Export Vault activity logs and usage metrics
- **Entity Export**: Export Vault entity data

## Project Structure

```
/vault-tools/
├── main.py                   # CLI entry point with unified subcommands
├── pyproject.toml            # Project metadata and dependencies
├── setup.py                  # Package setup configuration
├── uv.lock                   # UV package manager lock file
├── pytest.ini                # Pytest configuration
├── Taskfile.yml              # Task automation definitions
├── .env.example              # Environment variable template
├── .gitignore                # Git ignore patterns
├── .gitleaks.toml            # Secret scanning configuration
├── .markdownlint.json        # Markdown linting rules
├── .pre-commit-config.yaml   # Pre-commit hooks configuration
├── AGENTS.md                 # AI agent guidelines (this file)
├── LICENSE                   # Project license
├── README.md                 # Project documentation
├── src/
│   ├── common/
│   │   ├── vault_client.py         # Centralized Vault API client
│   │   ├── config.py               # Configuration management
│   │   ├── file_utils.py           # File I/O utilities (JSON/CSV/markdown)
│   │   ├── utils.py                # Common utilities
│   │   ├── audit_logger.py         # Audit logging functionality
│   │   └── logging_config.py       # Logging configuration
│   │
│   ├── namespace_audit/
│   │   ├── main.py           # Multi-threaded namespace traversal
│   │   └── report.py         # Markdown audit report rendering (pure functions)
│   │
│   ├── activity_export/
│   │   └── main.py           # Activity log processing
│   │
│   └── entity_export/
│       └── main.py           # Entity data extraction
│
├── tests/                    # 391 comprehensive tests
│   ├── common/               # 166 tests for shared utilities
│   ├── namespace_audit/      # 166 tests with threading & mocking
│   │   ├── conftest.py       # Pytest configuration
│   │   ├── fixtures.py       # Test fixtures
│   │   ├── report_fixtures.py # Realistic AuditData for report tests
│   │   ├── test_auditor_core.py
│   │   ├── test_data_classes.py
│   │   ├── test_namespace_traversal.py
│   │   ├── test_report.py
│   │   ├── test_worker_threads.py
│   │   ├── test_integration_simple.py
│   │   ├── test_integration.py
│   │   └── test_default.py
│   ├── activity_export/      # 43 tests for API & data processing
│   │   ├── conftest.py
│   │   ├── fixtures.py
│   │   ├── test_data_processing.py
│   │   ├── test_vault_api.py
│   │   ├── test_entity_export.py   # entity_export is tested from here
│   │   ├── test_integration.py
│   │   └── test_default.py
│   ├── entity_export/        # Package marker only; tests live in activity_export/
│   └── test_cli_parsing.py   # 16 argparse-level tests, no Vault required
├── inputs/                   # Input files for scripts
└── outputs/                  # Generated reports (configurable)
    ├── _archive/             # Archived reports
    └── audit/                # Audit reports
```

## Development Commands

### Environment Setup

```bash
# Install dependencies with uv (modern Python package manager)
task init

# Check dependencies
task deps

# Install in development mode
task install
```

### Running the CLI

```bash
# Main CLI help
python main.py --help

# Subcommand help
python main.py namespace-audit --help
python main.py activity-export --help
python main.py entity-export --help

# Using task runner
task run -- namespace-audit --help
```

### Testing

```bash
# Run all tests
task test

# Run with coverage
task test:all

# Run CI verification pipeline
task test:ci

# Specific test modules
pytest tests/namespace_audit/ -v
pytest tests/activity_export/ -v

# Test categories
pytest tests/ -m "unit" -v
pytest tests/ -m "not slow" -v
pytest tests/ -m "integration" -v
```

### Code Quality

```bash
# Run all linting, formatting, and secret-scanning checks
task lint

# Run the same checks the pre-commit hook runs, on staged files only
uv run pre-commit run

# Run a single hook across the repository
uv run pre-commit run ruff-format --all-files
uv run pre-commit run gitleaks --all-files
```

Formatting, import sorting, and secret scanning are all pre-commit hooks
(`ruff-format`, `ruff`'s `I` rules, and `gitleaks`), so they run automatically
on every commit rather than from a separate task.

## Environment Variables

### Required

```bash
export VAULT_ADDR="https://vault.example.com"
export VAULT_TOKEN="your-vault-token"
export VAULT_SKIP_VERIFY="true"  # Optional, for dev environments
```

### Optional Configuration

```bash
export VAULT_TOOLS_OUTPUT_DIR="custom-outputs"  # Default: "outputs"
export VAULT_TOOLS_AUDIT_DIR="custom/audit"     # Default: "outputs/audit"
export VAULT_TOOLS_DEBUG="true"                 # Default: false
```

These three are the complete set. Everything else is a CLI flag — `--workers`,
`--output-dir`, `--start-date`/`--end-date`. Rate limiting uses
`NamespaceAuditor`'s constructor defaults (batch 100, sleep 3s) and is not
currently exposed on the CLI.

## Architecture & Design Patterns

### Core Components

1. **Main CLI (`main.py`)**: Unified entry point with subcommands for each tool
2. **Common Utilities (`src/common/`)**:
   - `vault_client.py`: Centralized Vault client with connection validation and enhanced error handling
   - `config.py`: Centralized configuration management with environment variable support
   - `file_utils.py`: Shared file I/O utilities — `write_json`, `write_csv`,
     `write_csv_stream`, `write_markdown`, `read_json`, `read_csv`. All wrap
     failures in `FileProcessingError`; never let a bare `OSError` escape.
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
- Markdown file: Human-readable report (`namespace-audit` only)
- Filename pattern: `{cluster-name}-{data-type}-{YYYYMMDD}.{ext}`
- **Configurable**: Set `VAULT_TOOLS_OUTPUT_DIR` environment variable

`namespace-audit` writes seven files per run: three JSON, three CSV, and
`{cluster-name}-audit-report-{YYYYMMDD}.md`. The report is always written; there
is no flag to enable or suppress it. Note that the two CSV summary writers return
early when they have no rows, so a root-only cluster produces fewer files — the
report's "Output files" index checks existence rather than assuming all six.

### Markdown Report (`src/namespace_audit/report.py`)

Rendering is deliberately separated from collection:

- **Pure functions**: no Vault calls, no filesystem access. Takes `AuditData` /
  `AuditStats`, returns a string. Testable without mock plumbing.
- **No circular import**: `main.py` imports `report.py`, so `report.py` guards
  its `AuditData`/`AuditStats` annotations behind `TYPE_CHECKING` and defers them
  with `from __future__ import annotations`. Never add a runtime
  `from .main import ...` here.
- **No new dependencies**: `md_table()` is hand-rolled because
  `DataFrame.to_markdown()` requires `tabulate`, which the project does not
  depend on. The tool version comes from `importlib.metadata`, not from
  `main.__version__`.
- **Node set**: the namespace tree is built from the `auth_methods` keys, which
  include the root as `""`. `data.namespaces` holds only *discovered children*
  and omits the root, so it cannot be the sole source.
- **Size caps**: `MAX_REPORT_NODES` (500) and `MAX_MATRIX_NAMESPACES` (25) bound
  the tree, inventory and matrix; past them the report points at the CSV.
- **Finding checks** are tuned against real cluster data to avoid noise. Built-in
  mount types are excluded from the `local` check (cubbyhole is *always* local),
  and both `token` and `ns_token` count as the built-in token backend (child
  namespaces mount the `ns_`-prefixed variants). Deliberately not flagged:
  `max_lease_ttl == 0` (means "inherit the system default", not "unlimited" —
  measured at 99.7% of mounts on a real cluster) and `seal_wrap: false` (the
  default for most mounts).
- **Lease baseline**: `collect_findings(data, system_max_lease_ttl=...)` compares
  against the cluster's own ceiling, read once per run by
  `NamespaceAuditor._fetch_system_lease_ttls()` from
  `sys/config/state/sanitized`. Do not hardcode Vault's stock 768h as the live
  threshold — a cluster tuned to 24h makes it useless.
  `LONG_MAX_LEASE_TTL_SECONDS` is the fallback for when the endpoint is
  unreadable. A system max of `0` means "unset" and must be treated as unknown,
  never as a baseline, or every mount becomes an override.

Before adding a finding check, measure how many rows it produces against real
cluster data. Two checks in the original draft fired on 134 and 1515 mounts
respectively — both were the *default* state, not a deviation, and would have
buried the ~15 genuine findings.

When adding a writer to `_write_reports`, patch it in
`tests/namespace_audit/fixtures.py::mock_file_operations` too, or unit tests will
write real files to disk.

### Enhanced Error Handling

- **Specific Exceptions**:
  - `VaultConnectionError`: Connection and authentication issues
  - `VaultDataError`: Malformed API responses
  - `VaultPermissionError`: Authorization issues
  - `ConfigurationError`: Invalid configuration
- **Enhanced Messages**: Actionable troubleshooting hints in error messages
- **Graceful Permission Handling**: Logs warnings for forbidden namespaces
- **Comprehensive Error Statistics**: `AuditStats` records both a count and the
  identity of what failed — `forbidden_namespaces` holds `(path, scope)` and
  `errors` holds `(path, message)`, which is what the report's "Access gaps"
  section renders. The `increment_forbidden()` / `increment_errors()` arguments
  are optional so bare calls still compile; pass the namespace wherever it is
  known, or the failure becomes an unattributed number again.

## Test Suite Architecture

### Comprehensive Test Coverage

- **391 total tests** across all modules with no hanging issues
- **common**: 166 tests covering VaultClient, config, logging and file I/O
- **namespace_audit**: 166 tests including threading, mocking, report rendering
  and integration
- **activity_export**: 43 tests covering API interaction and data processing
  (this directory also holds the entity_export tests)
- **Centralized fixtures**: Reusable mock configurations in `fixtures.py` files
- **Modular structure**: Tests organized by functionality for maintainability

### Test Organization

- `test_data_classes.py`: Statistics and data storage unit tests
- `test_auditor_core.py`: Core functionality and configuration tests
- `test_namespace_traversal.py`: API interaction and data fetching tests
- `test_report.py`: Markdown rendering, tree building and finding checks
- `report_fixtures.py`: Realistic mount objects (config, deprecation_status,
  local) for the report tests — the minimal `{"type": ...}` stubs elsewhere are
  not enough to exercise the finding checks
- `test_worker_threads.py`: Threading and concurrency behavior tests
- `test_integration_simple.py`: Component interaction and workflow tests
- `test_integration.py`: Full end-to-end workflow tests
- `fixtures.py`: Centralized test fixtures and mock configurations
- `test_default.py`: Compatibility layer for CI/CD systems

### Key Test Improvements

- **Fixed Mock Issues**: Proper `MagicMock` usage for context managers
- **Eliminated Hanging Tests**: Replaced problematic threading tests with reliable mocks
- **Import Path Corrections**: Fixed patching locations for write operations
- **Thread Safety Testing**: Comprehensive concurrency and queue operation tests
- **Error Condition Coverage**: Edge cases and failure scenarios properly tested

### Key Test Fixes

- **Queue Operations**: Proper mocking of `queue.Queue` to prevent hanging
- **Threading Mock**: Complete `threading.Thread` and queue lifecycle mocking
- **Context Managers**: Correct `VaultClient.get_client()` context manager mocking
- **Import Patching**: Fixed write operation mocking at correct module paths
- **Exception Handling**: Proper `KeyboardInterrupt` and error condition testing

## Development Guidelines

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

### Key Areas for AI Assistance

- **Vault API Interactions**: Always refer to `src/common/vault_client.py`
- **New Features**: Ensure seamless integration with `main.py` CLI structure
- **File Operations**: Prioritize use of existing `file_utils.py`
- **Testing**: Follow existing structure in `tests/` directory
- **Connectivity Issues**: Check environment variables and `vault_client.py`

## Troubleshooting

### Common Issues

1. **Vault Connection Failures**: Verify `VAULT_ADDR` and `VAULT_TOKEN` environment variables
2. **Permission Errors**: Check token permissions and namespace access
3. **Rate Limiting**: Adjust `rate_limit_batch_size` / `rate_limit_sleep_seconds` on `NamespaceAuditor`
4. **Threading Issues**: Reduce `--workers` if experiencing resource constraints
5. **Test Failures**: Ensure all dependencies are installed with `task init`

### Debugging

- Enable debug mode: `export VAULT_TOOLS_DEBUG="true"`
- Check logs in the output directory
- Use verbose test output: `pytest tests/ -v`
- Verify Vault connectivity: `vault status`
