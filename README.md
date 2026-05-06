# Vault Tools

[![Test Vault Tools](https://github.com/nhsy-hcp/vault-tools/actions/workflows/test.yml/badge.svg)](https://github.com/nhsy-hcp/vault-tools/actions/workflows/test.yml)
[![Python 3.12+](https://img.shields.io/badge/python-3.12+-blue.svg)](https://www.python.org/downloads/)
[![License: MPL 2.0](https://img.shields.io/badge/License-MPL_2.0-brightgreen.svg)](https://opensource.org/licenses/MPL-2.0)

A unified CLI tool for comprehensive HashiCorp Vault operations, providing defensive security capabilities for namespace auditing, activity monitoring, and entity management.

## Features

- **Namespace Audit**: Multi-threaded namespace traversal with rate limiting and comprehensive reporting
- **Activity Export**: Vault activity log processing and export with flexible date ranges
- **Entity Export**: Entity data extraction and CSV/JSON reporting

## Quick Start

1. **Prerequisites**: Python 3.12+ and access to a HashiCorp Vault instance
2. **Install**: `uv sync`
3. **Configure**: Set `VAULT_ADDR` and `VAULT_TOKEN` environment variables
4. **Run**: `uv run vault-tools --help` or `python main.py --help` to see available commands

**New in v2.0.0:** Connection pooling, response caching, audit logging, rich CLI output, and streamlined development tools!

## Installation

### Prerequisites

- Python 3.12 or higher
- [uv](https://docs.astral.sh/uv/) package manager
- Access to a HashiCorp Vault instance
- Valid Vault token with appropriate permissions

### Setup and Run

```bash
# Install uv if not already installed
curl -LsSf https://astral.sh/uv/install.sh | sh

# Clone the repository
git clone https://github.com/your-username/vault-tools.git
cd vault-tools

# Sync dependencies (creates virtual environment automatically)
uv sync

# Run the CLI
uv run vault-tools --help
uv run vault-tools namespace-audit

# Or activate the virtual environment
source .venv/bin/activate  # On Unix/macOS
# .venv\Scripts\activate   # On Windows
vault-tools --help
```

### Pre-commit Hooks

```bash
# With uv
uv run pre-commit install

# Run manually on all files
pre-commit run --all-files
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

## Key Features (v2.0.0)

### Performance & Reliability

- **Connection Pooling**: Reusable HTTP connections with 20-30% performance improvement
- **Response Caching**: TTL-based cache (5min) for read-only endpoints, reducing API load
- **Automatic Retry**: Exponential backoff with circuit breaker for transient failures
- **Rate Limiting**: Configurable batch processing to prevent API overload

### Security & Compliance

- **Audit Logging**: Structured JSON logs in `outputs/audit/audit.log` with rotation
- **Secret Scanning**: Pre-commit hooks with gitleaks to prevent credential leaks
- **User Context**: Tracks username, hostname, PID for all operations

### Developer Experience

- **Rich CLI Output**: Progress bars, colored status indicators (✓ ✗ ⚠), formatted tables
- **Structured Logging**: JSON output for log aggregation (ELK, Splunk, Datadog)
- **Modern Tooling**: Fast linting with ruff, uv package manager support
- **Cache Statistics**: Performance metrics displayed after each run

### Optional Configuration

Customize behavior via environment variables:

```bash
export VAULT_TOOLS_OUTPUT_DIR="custom-outputs"  # Output directory
export VAULT_TOOLS_WORKERS="8"                  # Worker threads (namespace audit)
export VAULT_TOOLS_NAMESPACE="team-a/"          # Target namespace
export VAULT_TOOLS_DEBUG="true"                 # Enable debug logging
```

See `python main.py <command> --help` for all options.

## Testing

```bash
# Run all tests
pytest tests/ -v

# Run specific module
pytest tests/namespace_audit/ -v

# Run with coverage
pytest tests/ --cov=src

# Test GitHub Actions workflow locally (requires act)
task test:gha
```

**119 tests** with comprehensive coverage across all modules.

### Continuous Integration

The project uses GitHub Actions for automated testing on all branches:

- Python 3.12 with uv package manager
- Pre-commit hooks (linting, security scanning)
- Full test suite with coverage reporting

Test locally with `act` before pushing:

```bash
# Install act: https://github.com/nektos/act
brew install act  # macOS

# Validate workflow structure (dry-run)
task test:gha
```

## Architecture

**Modular design** with three main components:

- `src/namespace_audit/` - Multi-threaded namespace traversal
- `src/activity_export/` - Activity log processing
- `src/entity_export/` - Entity data extraction
- `src/common/` - Shared utilities (VaultClient, Config, FileUtils)

**Output:** Structured JSON/CSV files in `outputs/` directory.

## Contributing

1. Fork and create feature branch
2. Add tests for new functionality
3. Run `pytest tests/ -v` and `task lint`
4. Submit pull request

## License

This project is intended for defensive security purposes only. Use responsibly and in accordance with your organization's security policies.

## Support

For issues, questions, or contributions, please use the project's issue tracker.
