# Universal AI Agent Guidelines

This document provides core operating constraints for AI agents. These rules apply across all tasks within this environment.

## 1. File System & Environment

- **Scope:** DO NOT write any files outside the project folder.
- **Temporary Files:** Use `.tmp/` within the project root for all temporary files. Ensure this directory is created if it doesn't exist.
- **Planning Folder:** Use `.plans/` within the project root for all development plans. Ensure this directory is created if it doesn't exist.
- **Dependency Hygiene:** Any new libraries or dependencies must be immediately added to the project's dependency manifests (e.g., `pyproject.toml`, `requirements.txt`, `package.json`) before proceeding with implementation.

## 2. Git Operations

- **Staging:** NEVER use `git add .`. Always stage specific files relevant to the task.
- **Branch Naming:** Use the format `type/short-description` (e.g., `feat/dynamic-secrets`, `fix/vault-connection`). Valid types include `feat`, `fix`, `docs`, `refactor`, `test`, and `chore`.
- **Commit Messages:** Follow the [Conventional Commits](https://www.conventionalcommits.org/)
  specification: `type: description` (e.g., `feat: add gcp secrets engine`).
  Use lowercase and keep the description concise.
- **Documentation Sync:** Any change to logic, architecture, or configuration must be tracked
  for documentation updates in the relevant files (e.g., `README.md`, `GEMINI.md`, or `docs/`).
  Documentation updates are batched and confirmed with the user as the penultimate step before
  final staging and committing (see section 6.2.4).
- **Confirmation:** You MUST ask for user confirmation before:
  - Staging files (propose the list of specific files to be staged).
  - Creating a new `git branch` (propose the name following the format above).
  - Performing a `git commit` (propose the message following the format above).

## 3. Code Quality & Verification

- **Configuration Defaults:** If `.pre-commit-config.yaml` or `.gitignore` files do not exist, you MUST ask the user for clarification on the project type (e.g., Python, Node.js, Go) before generating sane defaults for these files.
- **Pre-commit Verification:** You MUST run `task lint` (or equivalent pre-commit hooks including `gitleaks` and `shellcheck`) and ensure all checks pass before proposing a commit. Automatically fixable issues (like formatting) should be handled before the final proposal.
- **Pre-commit Best Practices:**
  - **Installation:** Upon initial project setup, ensure hooks are installed by running `pre-commit install`.
  - **No Skipping:** NEVER use `--no-verify` or any mechanism to bypass hooks during a commit.
  - **Auto-Fixes:** Leverage hooks that provide auto-fixes (e.g., `ruff --fix`, `terraform fmt`). Apply these fixes and re-stage files before finalizing the commit.
  - **Incrementalism:** Run hooks frequently on staged changes to catch errors early, rather than waiting until the end of a task.
- **Self-Correction:** If linting, `gitleaks`, `shellcheck`, or tests fail, you must attempt to fix the issues internally before reporting back to the user or proposing the changes.
- **Safety & Secret Management:**
  - NEVER hardcode secrets, API keys, or private credentials.
  - Mandate the use of `.env.template` for new environment variables; update the template whenever a new variable is introduced.
  - Always run `gitleaks` (via `task lint` or standalone) to verify that no sensitive files or patterns are present in the staged changes.
  - Always verify that no sensitive files (e.g., `.env` files, private keys, or local-only configuration) are staged for commit.

## 4. Automation & Scripting

- **Task Runner:** Use `Taskfile.yml` (via `task`) for all automation and orchestration.
- **Modularity:** For any automation logic or scripts exceeding 20 lines, create a standalone bash script in the `scripts/` folder and invoke it from the Taskfile.
- **Script Standards:**
  - All bash scripts in `scripts/` must use `#!/bin/bash` and `set -euo pipefail` for robust error handling.
  - All bash scripts MUST pass `shellcheck` linting.
- **Environment Awareness:** Always verify the runtime environment (operating system, available CLI tools, and versions) before executing complex scripts or automation tasks.

## 5. Standard Task Interface

Projects should ideally implement the following idempotent tasks to provide a consistent interface for AI agents:

- `task init`: Perform one-time environment setup (dependencies, hooks, provider initialization).
- `task deps`: Check for required dependencies and validate the local environment.
- `task up`: Start the local development environment or infrastructure.
- `task down`: Stop and tear down the local development environment.
- `task clean`: Remove build artifacts, temporary files (`.tmp/`), and cache.
- `task lint`: Run all code quality, formatting, and security checks (including `gitleaks` and `shellcheck`).
- `task test`: Execute the local unit and integration test suite.
- `task test:all`: Run the complete test suite across all modules.
- `task test:ci`: Execute the full verification pipeline as defined in CI (including linting and all tests).
- `task build`: Compile, package, or build container images for the project.

## 6. Standard Workflows

### 6.1. Development Lifecycle

1. **Discovery:** Thoroughly explore the codebase and relevant documentation (`docs/`, `README.md`, `GEMINI.md`) before making changes.
2. **Planning:** Formulate a clear strategy. For complex tasks, save a concise plan to the `.plans/` folder and share the file path with the user for alignment and review.
3. **Iteration:** Implement changes in small, logical steps. Run local tests frequently to catch issues early.

### 6.2. Review & Verification

1. **Linting Gate:** Run the full project linting suite (e.g., `task lint`) and resolve all issues.
2. **Test Coverage:** Run all relevant automated tests (e.g., `task test:all`). For bug fixes, ensure a regression test is included.
3. **CI Simulation:** Verify that local execution matches the CI pipeline configuration. Use `act` to test GitHub Actions locally where possible. Always execute the project's designated CI verification task (e.g., `task test:ci`) to ensure alignment with the remote pipeline.
4. **Documentation Sync Confirmation:** As the penultimate step of a complete development phase (before final staging and committing), ask the user for confirmation before performing documentation updates. This batching ensures accuracy and minimizes token consumption.
5. **Clean Up:** Remove any temporary files (`.tmp/`), debug logs, or commented-out code before proposing final changes.
6. **Final Approval:** Propose staged files, branch names, and commit messages to the user for final confirmation.

## 7. Operational Excellence

- **Communicative Brevity:** Do not provide verbose summaries of tool results or recap actions (e.g., "I have updated the file...") unless explicitly requested. Focus strictly on the task and next steps.
- **Targeted Ingestion:** For large files (>100 lines), use `grep` to locate relevant sections first. When reading, use the `offset` and `limit` parameters in `read_file` to ingest only the necessary context.
- **Batching & Parallelism:** Execute independent tool calls (e.g., reading multiple files or searching multiple directories) in parallel within a single turn to minimize round-trips and response time.
- **Concise Planning:** Keep development plans extremely concise. For detailed strategies, save the plan to the `.plans/` folder and provide the link, rather than outputting long prose in the chat.
- **Output Management:** For commands expected to produce large outputs (e.g., `terraform plan`, long builds), redirect stdout and stderr to `.tmp/out.log` and `.tmp/err.log`. Inspect these logs using `grep`, `tail`, or `head` to remain within token limits.
- **Proactive Verification:** Immediately verify the result of any filesystem modification or file write (e.g., using `ls`, `read_file`, or `grep`) to ensure the operation succeeded as intended.
- **State Awareness:** Always double-check the current state of the environment (e.g., `git status`, `terraform show`, `kubectl get pods`) before initiating destructive or significant state-changing operations.
- **Markdown to PDF Conversion:** If requested by the user to convert a markdown file to PDF, use `pandoc` with the `typst` PDF engine (e.g., `pandoc -i input.md -o output.pdf --pdf-engine=typst`).

---

## Project-Specific Context: Vault Tools

### Project Overview

Vault Tools is a unified CLI tool for interacting with HashiCorp Vault, providing three main capabilities:

- **Namespace Audit**: Comprehensive auditing of Vault namespaces, auth methods, and secret engines
- **Activity Export**: Export Vault activity logs and usage metrics
- **Entity Export**: Export Vault entity data

## Project Structure

```
/vault-tools/
├── main.py                   # CLI entry point with unified subcommands
│
├── src/
│   ├── common/
│   │   ├── vault_client.py   # Centralized Vault API client
│   │   ├── config.py         # Configuration management
│   │   ├── file_utils.py     # File I/O utilities
│   │   └── utils.py          # Common utilities
│   │
│   ├── namespace_audit/
│   │   └── main.py           # Multi-threaded namespace traversal
│   │
│   ├── activity_export/
│   │   └── main.py           # Activity log processing
│   │
│   └── entity_export/
│       └── main.py           # Entity data extraction
│
├── tests/                    # 119 comprehensive tests
│   ├── namespace_audit/      # 89+ tests with threading & mocking
│   ├── activity_export/      # 30+ tests for API & data processing
│   └── fixtures.py           # Centralized test fixtures
│
├── inputs/                   # Input files for scripts
├── outputs/                  # Generated reports (configurable)
└── .plans/                   # Development plans and roadmaps
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
# Run all linting and security checks
task lint

# Auto-format code
task format

# Security scan
task security

# Secret scanning
task secrets
```

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
export VAULT_TOOLS_DEBUG="true"                 # Default: false
export VAULT_TOOLS_WORKERS="8"                  # Default: 4 (namespace audit)
export VAULT_TOOLS_NO_RATE_LIMIT="true"         # Default: false
export VAULT_TOOLS_NAMESPACE="team-a/"          # Default: root namespace
export VAULT_TOOLS_RATE_LIMIT_BATCH="50"        # Default: 100
export VAULT_TOOLS_RATE_LIMIT_SLEEP="5"         # Default: 3 seconds
export VAULT_TOOLS_TIMEOUT="60"                 # Default: 30 seconds
```

## Architecture & Design Patterns

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

## Test Suite Architecture

### Comprehensive Test Coverage

- **119 total tests** across all modules with no hanging issues
- **namespace_audit**: 89+ tests including threading, mocking, and integration
- **activity_export**: 30+ tests covering API interaction and data processing
- **Centralized fixtures**: Reusable mock configurations in `fixtures.py` files
- **Modular structure**: Tests organized by functionality for maintainability

### Test Organization

- `test_data_classes.py`: Statistics and data storage unit tests
- `test_auditor_core.py`: Core functionality and configuration tests
- `test_namespace_traversal.py`: API interaction and data fetching tests
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
3. **Rate Limiting**: Adjust `VAULT_TOOLS_RATE_LIMIT_BATCH` and `VAULT_TOOLS_RATE_LIMIT_SLEEP`
4. **Threading Issues**: Reduce `VAULT_TOOLS_WORKERS` if experiencing resource constraints
5. **Test Failures**: Ensure all dependencies are installed with `task init`

### Debugging

- Enable debug mode: `export VAULT_TOOLS_DEBUG="true"`
- Check logs in the output directory
- Use verbose test output: `pytest tests/ -v`
- Verify Vault connectivity: `vault status`
