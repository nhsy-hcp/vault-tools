# Development

## Pre-commit Hooks

```bash
# With uv
uv run pre-commit install

# Run manually on all files
pre-commit run --all-files
```

## Testing

```bash
# Run all tests
task test

# Run with coverage
task test:all

# Run the same gate CI enforces (lint + 80% coverage)
task test:ci

# Run a specific module
uv run pytest tests/namespace_audit/ -v
```

### Continuous Integration

The project uses GitHub Actions for automated testing on all branches:

- Python 3.12 with uv package manager
- Pre-commit hooks (linting, formatting, secret scanning)
- Full test suite, failing the build below 80% coverage

Run the workflow locally before pushing — this executes the real job in a
container, not a dry run:

```bash
# Install act: https://github.com/nektos/act
brew install act  # macOS

task test:gha
```

`test:gha` validates the workflow schema first, then runs the `test` job with
the container architecture matched to your host. Override it to reproduce
CI's own architecture:

```bash
task test:gha ACT_ARCH=linux/amd64
```

## Architecture

**Modular design**, one package per subcommand:

- `src/namespace_audit/` - Multi-threaded namespace traversal (`main.py`),
  markdown report rendering (`report.py`) and the ACL policy review (`acl.py`)
- `src/cluster_audit/` - Cluster health collection, checks and report
- `src/identity_audit/` - Entity collection, checks and report
- `src/activity_export/` - Activity log processing and usage checks
- `src/entity_export/` - Entity data extraction
- `src/full_audit/` - Runs every step and merges their findings
- `src/findings_diff/` - The `diff` subcommand
- `src/common/` - Shared utilities (VaultClient, Config, FileUtils), the
  findings model and rule catalogue (`findings.py`) and markdown helpers

**Output:** Structured JSON/CSV files in the `outputs/` directory, a markdown
report and a `findings.json` per audit.

## Key features

### Performance & reliability

- **Connection Pooling**: Reusable HTTP connections with 20-30% performance improvement
- **Automatic Retry**: Transport-level retry with exponential backoff on transient HTTP failures (408/429/5xx)
- **Rate Limiting**: Configurable batch processing to prevent API overload

### Security & compliance

- **Audit Logging**: Structured JSON logs in `outputs/audit/audit.log` with rotation
- **Secret Scanning**: Pre-commit hooks with gitleaks to prevent credential leaks
- **User Context**: Tracks username, hostname, PID for all operations

### Developer experience

- **Rich CLI Output**: Progress bars, colored status indicators (✓ ✗ ⚠), formatted tables
- **Structured Logging**: JSON output for log aggregation (ELK, Splunk, Datadog)
- **Modern Tooling**: Fast linting with ruff, uv package manager support
- **Quiet by Default**: The console carries progress and results; `--debug` adds per-namespace detail

## Contributing

1. Fork and create feature branch
2. Add tests for new functionality
3. Run `task test:ci` — the same lint and 80% coverage gate CI enforces
4. Submit pull request
