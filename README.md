# Vault Tools

[![Test Vault Tools](https://github.com/nhsy-hcp/vault-tools/actions/workflows/test.yml/badge.svg)](https://github.com/nhsy-hcp/vault-tools/actions/workflows/test.yml)
[![Python 3.12+](https://img.shields.io/badge/python-3.12+-blue.svg)](https://www.python.org/downloads/)
[![License: MPL 2.0](https://img.shields.io/badge/License-MPL_2.0-brightgreen.svg)](https://opensource.org/licenses/MPL-2.0)

A unified CLI tool for comprehensive HashiCorp Vault operations, providing defensive security capabilities for namespace auditing, activity monitoring, and entity management.

## Features

- **Namespace Audit**: Multi-threaded namespace traversal with rate limiting, JSON/CSV output and a markdown audit report
- **Activity Export**: Vault activity log processing and export with flexible date ranges
- **Entity Export**: Entity data extraction and CSV/JSON reporting

## Quick Start

1. **Prerequisites**: Python 3.12+ and access to a HashiCorp Vault instance
2. **Install**: `uv sync`
3. **Configure**: Set `VAULT_ADDR` and `VAULT_TOKEN` environment variables
4. **Run**: `uv run vault-tools --help` or `python main.py --help` to see available commands

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
git clone https://github.com/nhsy-hcp/vault-tools.git
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

Run the CLI directly with `python main.py`, through uv as `uv run vault-tools`,
or via the task runner as `task run -- <args>` (everything after `--` is passed
straight through). There are four subcommands:

### Namespace Audit

Comprehensively audit Vault namespaces, auth methods, and secret engines:

Namespaces are traversed recursively, so a nested hierarchy is audited in full,
not just its top level.

```bash
# Basic namespace audit
python main.py namespace-audit

# Audit with custom worker count and output directory
python main.py namespace-audit --workers 8 --output-dir custom-output

# See all options
python main.py namespace-audit --help
```

Each run writes seven files to the output directory: three JSON dumps of the raw
API responses, three CSV summaries, and a markdown report,
`{cluster-name}-audit-report-{YYYYMMDD}.md`. The report is written on every run —
there is no flag to enable or suppress it.

The report is the human-readable view of the audit and contains:

- **Summary** — total namespaces, maximum nesting depth, mount totals and
  distinct type counts, duration, errors and denials.
- **Access gaps** — every namespace the token was denied, by name, and whether
  the whole namespace or only its child listing was refused. This is the section
  to read first: it bounds how much of the cluster the rest of the report
  actually covers.
- **Namespace inventory** — the hierarchy as an indented tree with per-namespace
  mount counts, then a table of namespace IDs, depth and custom metadata.
- **Type distribution** — how many mounts of each auth method and secrets engine
  type exist and in how many namespaces, plus a per-namespace matrix for smaller
  clusters.
- **Security observations** — prompts for review derived from mount metadata:
  deprecated or pending-removal plugins, auth mounts enumerable by
  unauthenticated callers (`listing_visibility: unauth`), mounts whose
  `max_lease_ttl` overrides the cluster ceiling, non-replicated `local` mounts,
  namespaces with no auth method beyond the built-in token backend, and leaf
  namespaces holding nothing but Vault's own built-in engines.
- **Output files** — an index of the sibling JSON and CSV files from the same run.

These observations are review prompts, not a compliance verdict — informational
rows are expected in a healthy cluster. Very large clusters are truncated in the
tree and inventory tables, which then point at the corresponding CSV.

Lease findings are calibrated against your cluster's own `max_lease_ttl`, read
once per run from `sys/config/state/sanitized` and shown in the summary as
**System lease TTL**. A mount is flagged only when it *overrides* that ceiling,
reported with the multiple — so a 2160h lease on a cluster tuned down to 24h
reads as "90x higher" rather than being compared against Vault's stock 768h and
under-reported. If the token cannot read that endpoint the audit still succeeds:
the row is omitted and the check falls back to a fixed 768h threshold, saying so
in the finding.

Mounts that leave `max_lease_ttl` at `0` are deliberately *not* flagged. Zero
means "inherit the system default", not "unlimited" — on a typical cluster
upwards of 99% of mounts sit at zero, so reporting them would bury every other
finding.

### Activity Export

Export Vault activity logs and usage metrics. Both dates are required:

```bash
# Export for a specific date range
python main.py activity-export --start-date 2026-01-01 --end-date 2026-01-31

# Short flags
python main.py activity-export -s 2026-01-01 -e 2026-01-31

# See all options
python main.py activity-export --help
```

### Entity Export

Extract and export Vault entity data. Both dates are required:

```bash
python main.py entity-export --start-date 2026-01-01 --end-date 2026-01-31

# See all options
python main.py entity-export --help
```

A range with no client records is not an error: Vault answers `204 No Content`
and the export reports that there is no data and exits successfully.

### All

Run all three subcommands in sequence, sharing one Vault connection:

```bash
python main.py all -s 2026-01-01 -e 2026-01-31

# Via the task runner
task run -- all -s 2026-01-01 -e 2026-01-31
```

## Configuration

### Required Environment Variables

Set the following environment variables before running the tool:

```bash
export VAULT_ADDR="https://vault.example.com"
export VAULT_TOKEN="your-vault-token"
export VAULT_SKIP_VERIFY="true"  # Optional, for dev environments
```

### Vault Token Permissions

The tool is read-only and never writes to Vault. Rather than running it with a
root token, use the supplied [`audit-policy.hcl`](audit-policy.hcl), which grants
only the endpoints the tool actually calls.

Write the policy and mint a short-lived token in the **root namespace**:

```bash
# Create the policy (root namespace)
vault policy write vault-tools-audit audit-policy.hcl

# Create a token with a 1 hour TTL
vault token create -policy=vault-tools-audit -ttl=1h

# Capture just the token and export it for the tool
export VAULT_TOKEN=$(vault token create -policy=vault-tools-audit -ttl=1h -field=token)
```

An hour is ample headroom — a full audit typically completes in seconds. Add
`-explicit-max-ttl=1h` if the token must not be renewable beyond that, or lower
`-ttl` for CI use.

Two things to know about the policy:

- **It must live in the root namespace.** Vault ACL policies are namespace-local,
  and a token does *not* inherit a same-named policy defined in a child
  namespace. Child namespaces are therefore reached through namespace-prefixed
  paths (`+/sys/mounts`, `+/+/sys/mounts`, ...), where `+` matches one namespace
  segment. The policy covers the root namespace plus five levels of nesting; a
  deeper hierarchy needs one more `+/` rule per extra level.
- **`sys/internal/counters/activity/export` needs `sudo`.** Vault root-protects
  that endpoint, so `read` alone returns 403 and `entity-export` fails. It is the
  only rule in the policy requiring `sudo`; everything else is plain `read`/`list`.
- **`sys/config/state/sanitized` is optional.** It supplies the cluster's lease
  TTLs, which calibrate the audit report's lease findings. Removing the rule
  degrades those findings to a fixed threshold; it does not fail the run.

If the token lacks `sys/namespaces` at some level, the audit stops descending
there and reports the namespaces it did reach. The **Permission Denied (skipped)**
count in the console summary table should be `0`; when it is not, the **Access
gaps** section of the markdown report names each denied namespace and says
whether the whole namespace or only its child listing was refused, so you can see
exactly which subtrees are missing and widen the policy accordingly.

## Key Features

### Performance & Reliability

- **Connection Pooling**: Reusable HTTP connections with 20-30% performance improvement
- **Response Caching**: TTL-based cache (5min) for read-only endpoints, reducing API load
- **Automatic Retry**: Transport-level retry with exponential backoff on transient HTTP failures (408/429/5xx)
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
export VAULT_TOOLS_AUDIT_DIR="custom/audit"     # Audit log directory
export VAULT_TOOLS_DEBUG="true"                 # Enable debug logging
```

Everything else is a CLI flag — see `python main.py <command> --help`. Worker
count is `--workers`, output directory is `--output-dir` (which overrides
`VAULT_TOOLS_OUTPUT_DIR`), and the export window is `--start-date`/`--end-date`.

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

**Modular design** with three main components:

- `src/namespace_audit/` - Multi-threaded namespace traversal (`main.py`) and
  markdown report rendering (`report.py`)
- `src/activity_export/` - Activity log processing
- `src/entity_export/` - Entity data extraction
- `src/common/` - Shared utilities (VaultClient, Config, FileUtils)

**Output:** Structured JSON/CSV files in the `outputs/` directory, plus a
markdown audit report from `namespace-audit`.

## Contributing

1. Fork and create feature branch
2. Add tests for new functionality
3. Run `task test:ci` — the same lint and 80% coverage gate CI enforces
4. Submit pull request

## License

This project is intended for defensive security purposes only. Use responsibly and in accordance with your organization's security policies.

## Support

For issues, questions, or contributions, please use the project's issue tracker.
