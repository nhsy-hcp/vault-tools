# Vault Tools

## Project Overview

Vault Tools is a unified CLI tool for interacting with HashiCorp Vault. Its
subcommands:

- **Namespace Audit** (`namespace-audit`): Comprehensive auditing of Vault namespaces, auth methods, secret engines, ACL and Sentinel policies, with a markdown audit report; ACL and Sentinel bodies are assessed whenever the token's policies allow it
- **Cluster Audit** (`cluster-audit`): Seal, HA, replication, raft, audit devices, snapshots and node metrics; works on sealed and DR-secondary nodes
- **Identity Audit** (`identity-audit`): Identity entities and aliases
- **Activity Export** (`activity-export`): Export Vault activity logs and usage metrics, plus client-usage checks
- **Entity Export** (`entity-export`): Export Vault entity data
- **Full Audit** (`full-audit`): Every audit and export in one run, with a combined report
- **Diff** (`diff`): Compare two `findings.json` files

Every audit writes a `findings.json` in the vault-ops Claude skill's schema
(`schemas/findings.schema.json`), and its rule IDs (`VT-MOUNT-001`, …) come
from the skill's catalogue. The skill lives at `~/Projects/ai/vault-ops-skill`
and is where most of these checks were first written.

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
├── policies/                 # Vault token policies (templates to `vault policy write`)
│   ├── audit-policy.hcl                  # Least-privilege base policy for every subcommand
│   ├── audit-policy-acl-reader.hcl       # Add-on: read ACL policy bodies (VT-POL)
│   └── audit-policy-sentinel-reader.hcl  # Add-on: read Sentinel EGP/RGP bodies (VT-SNT)
├── schemas/
│   └── findings.schema.json  # Vendored from the vault-ops skill
├── scripts/
│   ├── check-policy-fmt.sh   # vault policy fmt check (pre-commit hook)
│   └── seed-sentinel-policies.sh
├── src/
│   ├── common/
│   │   ├── vault_client.py         # Centralized Vault API client
│   │   ├── config.py               # Configuration management
│   │   ├── file_utils.py           # File I/O utilities (JSON/CSV/markdown)
│   │   ├── exceptions.py           # VaultToolsError hierarchy
│   │   ├── findings.py             # Finding model, rule catalogue, findings.json, diff, exit codes
│   │   ├── remediation.py          # Per-rule meaning, drafted operator commands, ranking order
│   │   ├── markdown.py             # md_table, md_escape, findings tables
│   │   ├── utils.py                # Common utilities
│   │   ├── audit_logger.py         # Audit logging functionality
│   │   └── logging_config.py       # Logging configuration
│   │
│   ├── namespace_audit/
│   │   ├── main.py           # Multi-threaded namespace traversal
│   │   ├── report.py         # Markdown audit report rendering (pure functions)
│   │   └── acl.py            # Opt-in ACL policy body assessment (pure functions)
│   │
│   ├── cluster_audit/
│   │   ├── collector.py      # Cluster health reads (allowlisted, never raises)
│   │   ├── findings.py       # Health, replication, audit, snapshot, license, lease rules
│   │   ├── report.py         # Cluster health section and report (pure functions)
│   │   └── main.py           # `cluster-audit` command
│   │
│   ├── identity_audit/
│   │   ├── collector.py      # Namespace discovery and entity reads
│   │   ├── findings.py       # VT-ID rules
│   │   ├── report.py         # Report, CSV rows, findings.json (pure functions)
│   │   └── main.py           # `identity-audit` command
│   │
│   ├── activity_export/
│   │   ├── main.py           # Activity log processing and the usage findings files
│   │   └── findings.py       # VT-CLI rules (pure functions)
│   │
│   ├── entity_export/
│   │   └── main.py           # Entity data extraction
│   │
│   ├── full_audit/
│   │   ├── main.py           # Runs every step, merges findings
│   │   └── report.py         # The combined report, in the vault-ops skill's layout (pure)
│   │
│   └── findings_diff/
│       └── main.py           # `diff` command
│
├── tests/
│   ├── namespace_audit/      # Threading & mocking tests
│   │   ├── conftest.py       # Pytest configuration
│   │   ├── fixtures.py       # Test fixtures
│   │   ├── report_fixtures.py # Realistic AuditData for report tests
│   │   ├── test_acl_review.py
│   │   ├── test_findings_json.py
│   │   ├── test_mount_and_sentinel_rules.py
│   │   ├── test_auditor_core.py
│   │   ├── test_data_classes.py
│   │   ├── test_namespace_traversal.py
│   │   ├── test_report.py
│   │   ├── test_worker_threads.py
│   │   ├── test_integration_simple.py
│   │   ├── test_integration.py
│   │   └── test_default.py
│   ├── common/               # includes test_findings.py (model, diff, exit codes)
│   ├── activity_export/      # Tests for API & data processing
│   │   ├── conftest.py
│   │   ├── fixtures.py
│   │   ├── test_data_processing.py
│   │   ├── test_vault_api.py
│   │   ├── test_entity_export.py   # entity_export is tested from here
│   │   ├── test_integration.py
│   │   ├── test_usage_findings.py  # VT-CLI rules
│   │   └── test_default.py
│   ├── cluster_audit/        # fakes.py: a fake Vault keyed by path
│   ├── identity_audit/       # fakes.py: a fake Vault keyed by (namespace, path)
│   ├── full_audit/           # Orchestration with every step patched
│   ├── entity_export/        # Package marker only; tests live in activity_export/
│   └── test_cli_parsing.py   # Argparse-level tests and main() exit codes, no Vault required
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
python main.py cluster-audit --help
python main.py identity-audit --help
python main.py activity-export --help
python main.py entity-export --help
python main.py full-audit --help
python main.py diff --help

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

The dev extra floors pytest at **9.0.3** (`pyproject.toml`), the release that
fixed the predictable `/tmp/pytest-of-{user}` handling reported as
GHSA-6w46-j5rx-g56g. Do not lower that floor to unblock a plugin — check the
plugin supports pytest 9 first. `pytest-cov` requires only `pytest>=7`, so it is
not the constraint.

Two things about pytest 9 worth knowing before debugging a script against it:

- `--collect-only -q` prints an indented tree, not one node ID per line. Parse
  the trailing `N tests collected` summary instead of counting `::` matches.
- Test configuration lives in **`pytest.ini`**, which wins outright over the
  `[tool.pytest.ini_options]` block duplicated in `pyproject.toml`. Edit
  `pytest.ini`; a change to the `pyproject.toml` copy is silently ignored.

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

Vault policy files (`*.hcl`, e.g. `policies/audit-policy.hcl` and
`policies/audit-policy-acl-reader.hcl`) are formatted with **`vault policy fmt`**: two-space
indent, `key = value` spacing, and a blank line between consecutive `path`
blocks. The `vault-policy-fmt` pre-commit hook (`scripts/check-policy-fmt.sh`)
checks this as part of `task lint`. It formats a copy in `.tmp/` and fails with a
diff, never rewriting the file itself. Apply the fix with `task fmt:policy`. The
check needs a `vault` binary on PATH (no server or token) and skips with a
message without one, which is why CI, having none, still passes. Formatting is
not the only rule for these files: every `path` rule must still map to a request
the tool actually issues.

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
`--output-dir`, `--no-sentinel`, `--start-date`/`--end-date`, `--names-only`,
`--list`/`--list-entities`, `--fail-on`/`--fail-on-gaps`. Rate limiting uses
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

   - `findings.py`: The `Finding` model, the `RULES` catalogue, the
     findings.json builders, `diff_documents`, `merge_documents` and
     `exit_code_for`. Pure.
   - `markdown.py`: `md_table`, `md_escape` and `render_findings_table`, shared
     by every report.

3. **Module Structure**: Each tool is organized as a separate module under `src/`:
   - `namespace_audit/`: Multi-threaded namespace traversal with rate limiting
   - `cluster_audit/`: Cluster health collection and checks
   - `identity_audit/`: Identity entity collection and checks
   - `activity_export/`: Vault activity log processing and export, plus usage checks
   - `entity_export/`: Entity data extraction and export
   - `full_audit/`: Runs the others in order and merges their findings
   - `findings_diff/`: Compares two findings documents

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
- Markdown file: Human-readable report (every audit; not the two exports)
- `*-findings-*.json`: Machine-readable findings (every audit, and activity-export)
- Filename pattern: `{cluster-name}-{cluster-id-8}-{data-type}-{YYYYMMDD}.{ext}`,
  built by `common/utils.py::file_prefix`. The first eight hex characters of
  the cluster ID keep two clusters with the same name from overwriting each
  other's files. The ID is not appended again when the name already ends with
  it (Vault's default `vault-cluster-<8 hex>` names), and is omitted when
  unknown (a sealed node reports none). Use `file_prefix` in every new writer.
- **Configurable**: Set `VAULT_TOOLS_OUTPUT_DIR` environment variable

`namespace-audit` writes up to fourteen files per run: up to eight JSON, up to
five CSV, and `{cluster-name}-audit-report-{YYYYMMDD}.md`. The report and
`namespace-findings.json` are always written; there is no flag to suppress
them. The count is a maximum, not a guarantee: the CSV summary writers return
early when they have no rows, the Sentinel pair (`sentinel-policies.json`,
`summary-sentinel-policies.csv`) is skipped entirely unless policies were
collected, `license.json` is written only when the license was read, and
`acl-policy-review.json` only when ACL bodies were read — so a root-only Community
dev server produces nine with the base policy, ten when the token can also read
ACL bodies. The report's "Output files" index checks existence
rather than assuming the full set.

The other commands, per run:

- `cluster-audit`: three files (`cluster-health.json`, `cluster-findings.json`,
  `cluster-audit-report.md`).
- `identity-audit`: up to four (`identity-findings.json`,
  `identity-summary.csv` when any namespace was read, `identity-entities.json`
  under `--list` only, `identity-audit-report.md`).
- `activity-export`: its three export files plus `activity-findings.json`, `.md`
  and, only when there are findings, `.csv`.
- `full-audit`: every file its steps write, plus `full-findings.json` and
  `full-audit.md`.

The two ACL files differ from each other on purpose. `acl-policies.json` is
written whenever a namespace was reached, even if every list is empty: ACL
policies exist on every Vault edition, so "nothing defined" is a real result
worth recording per namespace. `summary-acl-policies.csv` is skipped when there
are no rows, because a CSV of nothing but a header is not useful to grep. On a
run where the token is denied `sys/policies/acl` everywhere you therefore get
the JSON with 134 empty lists, no CSV, and the reason in **Access gaps**.

### Console output vs logging

**rich owns the console; stdlib loggers are diagnostics.** `setup_logging` sets
the root level to WARNING by default (DEBUG under `--debug`, INFO under
`--json-logs`, which has no progress bar to protect). So:

- Anything a user must see on a default run needs a `console.print`, **not** a
  `logger.info`. An INFO line added anywhere — including in `file_utils` or
  `vault_client` — is invisible by default, and if the threshold were raised it
  would print over the live progress bar and shred it. That is exactly what a
  default of INFO used to do, 134 times in a single audit.
- Nothing may be printed while the progress bar is running. To say something
  during the walk, relabel the bar via `_set_progress_description` — the
  rate-limit pause is the worked example.
- File writes are reported once, together, by `_print_output_files` after the
  summary table, from the `output_files` list `_write_reports` populates. Do not
  add a per-file `console.print` at the writer: that produced the same fact
  twice, in two different styles, for the markdown report.
- `setup_logging` sets the root level explicitly as well as passing `level=` to
  `basicConfig`, because `basicConfig` is a no-op once the root logger has a
  handler and would otherwise be honoured only on the first call in a process.

There is deliberately **no response cache**. One existed, keyed on
`sys/auth`/`sys/mounts`/`sys/policies` prefixes, but the traversal reads those
through hvac inside `get_client()` and never through `VaultClient.get()`, so it
could not fire; the only paths that do reach `get()` are not in that prefix list.
It reported `Hits: 0 | Misses: 1` on every run. Reinstating one only makes sense
alongside a call path that actually re-reads something — note the `visited` set
already guarantees each namespace is walked once.

### Vault token policies: read-only, least privilege

- **The tool issues only GET and LIST requests.** Every Vault call goes
  through hvac's `read_*`/`list_*`/`is_*` helpers or raw GETs (`RawReader`,
  `VaultClient.get`). `VaultClient.post()` exists but is unused; do not start
  using it, and never add a call that writes, tunes, enables, revokes or
  deletes anything in Vault.
- **Policy files grant `read` and `list` only.** That covers `policies/audit-policy.hcl`
  and the add-ons `policies/audit-policy-acl-reader.hcl` and
  `policies/audit-policy-sentinel-reader.hcl`. Never `create`, `update`, `patch` or
  `delete`. Every `path` rule must map to a request the tool actually issues,
  with a comment saying which.
- **`sudo` is kept to the minimum, and widening it needs the user's
  confirmation.** `sudo` lets a token call a root-protected endpoint with the
  methods its other capabilities allow; it is not a write grant. Today it is
  used on exactly three **exact** paths (no glob), each because Vault
  root-protects a read:
  - `sys/internal/counters/activity/export` (`read`, `sudo`): entity-export.
  - `sys/audit` (`read`, `sudo`): cluster-audit, listing audit devices.
  - `sys/storage/raft/snapshot-auto/config` (`list`, `sudo`): cluster-audit,
    listing snapshot config names. The configs themselves are never read: they
    hold storage credentials.

  **Any new `sudo` rule, any glob on a `sudo` path, or any change that widens
  a policy's capabilities must be proposed to the user and confirmed before it
  is written**, with the endpoint, the reason Vault requires it, and why an
  exact path is not enough.
- **Never modify `.pre-commit-config.yaml` without the user's confirmation.**
  That includes adding, removing or re-pinning a hook, even when a plan step
  seems to cover it ("update `task lint`"). Propose the exact hook change and
  wait for a yes.
- **Optional reads live in add-ons**, so the user decides through the token
  what is assessed: policy bodies (ACL, Sentinel) are the current examples.
  Prefer a new add-on over widening `policies/audit-policy.hcl`.

### ACL policy collection

`NamespaceAuditor._fetch_acl_policies()` lists `sys/policies/acl` once per
namespace via hvac's `list_acl_policies()` and stores the sorted names on
`AuditData.acl_policies`.

- **The token is the source of truth for policy bodies.** `policies/audit-policy.hcl`
  grants `list` only. Bodies need `read` on `sys/policies/acl/*`, which lets
  the token reconstruct the cluster's access model, so that grant lives only in
  the separate `policies/audit-policy-acl-reader.hcl` add-on. Never add it to
  `policies/audit-policy.hcl`. There is no flag: the auditor always tries to read
  bodies, and the token's policies decide (`--names-only` is the one opt-out).
- **A denied body read is not an access gap.** It means the token was not given
  the add-on, which is a choice. The first 403 per kind (`acl`, `sentinel`)
  marks that kind denied for the run (`_note_body_read`), and the rest are
  skipped, so a base token costs one extra call, not one per policy, and adds
  no gap rows. The outcome is `AuditData.policy_bodies` (`assessed`, `partial`,
  `not readable`, `names only`, `none found`), shown in the reports and in
  findings.json's `cluster_context.policy_bodies`. It never makes
  `coverage.complete` false.
- **Assessment (`namespace_audit/acl.py`)** covers every body except `root`,
  built-ins included, and reduces each to an `AclAssessment`: a sha256, a rule
  count and the flagged rules' paths and capabilities. The body and every
  allowed/denied parameter value are dropped inside `_assess_acl_bodies`. They
  must never reach `AuditData`, a finding or a file, and a test plants a
  parameter value to check that. The HCL parser
  is the skill's: it keeps `path` blocks, `capabilities` and the legacy
  `policy = "read|write|sudo|deny"` attribute (expanded the way Vault expands
  it), and returns `None` (VT-POL-005) instead of raising.
- **VT-POL-002 matches in both directions** (`escalation_areas`). A broad glob
  covers a representative target (`sys/*` covers `sys/auth/x`), and a narrow
  rule falls inside a target's area (`sys/policies/acl/admin`,
  `auth/token/roles/ci`), including through a namespace prefix
  (`+/sys/policies/acl/*` in a root policy). The skill checks only the first
  direction and so misses grants on one named policy, mount or role.
- **`sudo` on a match-everything path is VT-POL-001 alone**, never VT-POL-003
  as well. Reporting both doubled every copy of an `admin` policy. Expect VT-POL-003 on this tool's own
  `policies/audit-policy.hcl`, which needs `sudo` on three exact paths. That is expected
  and deliberately not special-cased.
- **No tri-state.** Unlike Sentinel, `sys/policies/acl` exists on every Vault
  edition, so there is nothing to probe for and no `"unsupported path"`
  heuristic. `Forbidden` still logs at debug for the reason given below.
- **`BUILTIN_ACL_POLICIES` is matched exactly, never by prefix.** It holds
  `default`, `root` and `default-ceiling` — all present in every namespace, 266
  of the 1,499 policies on the reference cluster. `default-ceiling` is included
  because it grants self-read on `agent-registry/...` and `agent_registry` is
  already a built-in mount type here. A `startswith("default")` would wrongly
  swallow a user-defined `default-admin`.
- **The key is stored even when the list is empty**, unlike the Sentinel dicts.
  Twelve namespaces on the reference cluster define nothing of their own, and an
  absent key would render as "not audited" rather than "nothing here".
- The markdown table groups by namespace (133 rows); the CSV keeps one row per
  policy (1,233 rows) as the greppable grain.

### Sentinel EGP/RGP collection

`NamespaceAuditor._fetch_sentinel_policies()` runs inside the same `get_client()`
block as the auth and engine collectors, using hvac's native
`list_egp_policies()` / `read_egp_policy()` (in
`hvac/api/system_backend/policies.py`, *not* `policy.py`, which is ACL-only).

- **`self.sentinel_supported` is tri-state and load-bearing.** `None` = never
  probed, `True` = the endpoint answered, `False` = the cluster has no Sentinel.
  The report renders all three differently, because "zero policies" and "no
  Sentinel at all" are different findings. Mutated only under `thread_lock`, via
  `_mark_sentinel_supported()`, which makes `False` sticky — the flag describes
  the cluster, so a later success is not evidence against it, and letting `True`
  win a race would restart the probing the flag exists to stop.
- **The `SENTINEL_UNSUPPORTED_MARKERS` string check is a deliberate heuristic.**
  Vault returns 404 both for "this build has no Sentinel" and for "this namespace
  has zero policies", and only the error body separates them: `"unsupported
  path"` on Vault 1.x Community, `"enterprise-only feature"` on 2.x. If Vault ever reworks
  the message the short-circuit stops firing and every namespace re-probes to an
  empty result — benign, which is why the heuristic is acceptable. Do not
  "harden" it into something that fails closed.
- **Cost on a non-Sentinel cluster is one API call for the whole run**: the EGP
  probe fails, `sentinel_supported` goes `False`, the RGP probe in the same call
  is skipped, and every later namespace short-circuits before the request.
- **Names are always kept; bodies only when the token allows.** The LIST rule is
  in `policies/audit-policy.hcl`; body reads need `policies/audit-policy-sentinel-reader.hcl`,
  like the skill's `vault-ops-sentinel-reader`. An unread policy is stored as
  `{"name": ...}`. A read body is reduced at once by
  `report.py::reduce_sentinel_policy` to its name, enforcement level, paths,
  sha256, line count, `always_true`/`always_false` and import names. The
  source is never stored or written, so `sentinel-policies.json` carries no
  policy text. A 403 follows the same one-probe rule as ACL bodies; any other
  read failure records one error per `(namespace, kind)`.
- **Namespaces with no policies get no dict entry at all**, or every table would
  carry a blank row per namespace.
- `examples/sentinel/` plus `task seed:sentinel` write five no-op policies
  covering each finding branch, including a hard-mandatory control that must
  produce *no* finding. Every body evaluates to `true` unconditionally.

### License and version collection

`validate_connection()` reads `sys/health` once and returns `ConnectionInfo`;
the auditor copies `vault_version`, `cluster_id` and `is_enterprise` onto
`AuditData`. `NamespaceAuditor._fetch_license_status()` then reads
`sys/license/status` once per run and stores the `autoloaded` sub-dict. It
delegates to `cluster_audit.collector.fetch_license_status`, which
`cluster-audit` uses too, so the tri-state rules below live in one place.

- **`is_enterprise` is tri-state.** `True`/`False` from the `+ent` version
  suffix, `None` when `sys/health` omits the version. The suffix check lives
  only in `vault_client.py` — the report reads the flag, never the string.
- **Unknown edition is probed, not skipped.** `False` makes no call. `None`
  calls the endpoint anyway: a 404 (`VaultAPIError` caused by
  `hvac.exceptions.InvalidPath`) settles it as Community and records nothing;
  a success settles it as Enterprise. A 404 on a known-Enterprise cluster is an
  error, not a Community signal.
- **Every failure keeps its reason** on `AuditData.license_unavailable_reason`:
  `"denied"`, `"unexpected response"` or `"error: <message>"`. The License
  section words its note from it, so a 5xx is not blamed on token permissions.
- **A denial is not an access gap.** It is deliberately not passed to
  `increment_forbidden`: that list means "the tree is incomplete below this
  namespace", and a cluster-level read says nothing about coverage. Access
  gaps shows it on its own "Cluster-level reads" line instead.
- **Expiry findings** (`cluster_audit/findings.py::license_findings`): within
  `LICENSE_EXPIRY_WARNING_DAYS` (90) is VT-LIC-001 at Medium; already past the
  soft expiry is the same rule escalated to High, citing `termination_time`, when
  Vault actually stops serving. It stays one rule so a `diff` shows the finding
  worsening, not one resolving and another appearing. Timestamps without an
  offset are read as UTC.

### Markdown Report (`src/namespace_audit/report.py`)

Rendering is deliberately separated from collection:

- **Pure functions**: no Vault calls, no filesystem access. Takes `AuditData` /
  `AuditStats`, returns a string. Testable without mock plumbing.
- **No circular import**: `main.py` imports `report.py`, so `report.py` guards
  its `AuditData`/`AuditStats` annotations behind `TYPE_CHECKING` and defers them
  with `from __future__ import annotations`. Never add a runtime
  `from .main import ...` here.
- **No new dependencies**: `md_table()` (now in `src/common/markdown.py`) is
  hand-rolled because `DataFrame.to_markdown()` requires `tabulate`, which the
  project does not depend on. The tool version comes from `importlib.metadata`
  (`common/findings.py::get_tool_version`), not from `main.__version__`.
- **Import direction**: `namespace_audit.report` imports `cluster_audit.report`
  and `cluster_audit.findings` (for the health section, the license and lease
  rules), never the reverse. Shared pieces go in `src/common/`.
- **`AuditData` is the single source**: every section reads the same `data`
  object. Do not add kwargs to `build_markdown_report` that duplicate an
  `AuditData` field — the license section once took its data from a kwarg while
  the summary and findings read `data`, and the two could disagree.
- **One clock**: `collect_findings(..., now=...)` receives the report's
  `generated_at`, so time-based findings match the "Generated" header and tests
  pin them with a fixed date rather than the wall clock.
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

When adding a writer to `_write_reports`, make sure the `file_utils` function it
calls is patched in `tests/namespace_audit/fixtures.py::mock_file_operations`,
or unit tests will write real files to disk. Patch the `file_utils` function,
not the `_write_*` method — replacing the method means no test ever runs it.

When adding a per-namespace collector, add its endpoint to
`tests/namespace_audit/fixtures.py::make_hvac_client` as well. The mock hvac
client is a bare `Mock`, which has no `__getitem__`, so an unstubbed call makes
the collector's subscript raise `TypeError` and every traversal test records a
spurious error rather than failing where the gap is. Both that fixture and
`mock_vault_client` set `adapter.get.side_effect = InvalidPath()`, so the
cluster health collector's raw GETs find nothing and raise no finding in
unrelated tests. Keep it that way.

### Findings model and findings.json (`src/common/findings.py`)

- **Rule IDs are permanent and come from the skill.** `RULES` holds each ID's
  default severity, category and title. The fingerprint is
  `sha256(rule|namespace|kind|path)[:16]`, identical to the skill's (a test pins
  two values), so a rename reads as "resolved" plus "new" in every diff. Add a
  rule to `RULES` before emitting it; `finding()` raises `KeyError` otherwise.
- **Severity may escalate per finding** (`finding(..., severity="High")`), as
  VT-LIC-001 does once a license has expired. Title case in markdown, lower case
  in JSON.
- **The schema is vendored, not imported.** Re-vendor
  `schemas/findings.schema.json` from the skill and bump
  `FINDINGS_SCHEMA_VERSION` together. Tests validate every producer's output
  against it (`jsonschema` is a dev dependency only).
- **Coverage in findings.json is stricter than "Access gaps" in markdown.**
  Cluster-level denials (`sys/audit`, `sys/license/status`, …) are not listed as
  namespace gaps in the report, but they do make `coverage.complete` false. A
  CI gate asking "was anything not judged?" has to see them. Unattributed
  failures count too.
- **Exit codes**: 0 ok, 1 fatal (including a failed audit — namespace-audit used
  to exit 0 after printing the error), 2 `--fail-on-gaps` with incomplete
  coverage, 3 `--fail-on` with a finding at or above the severity. 3 wins over 2.
- **`merge_documents`** (full-audit) dedupes by fingerprint, because
  namespace-audit embeds cluster findings that cluster-audit also reports.

### Cluster health collection (`src/cluster_audit/`)

- **`collect_cluster_health` never raises.** Every read is optional. A 403 goes
  to `ClusterCoverage.denied` (by endpoint path) and other failures to `errors`,
  recorded as exception class plus HTTP status only, because hvac messages can
  echo URLs. A 404 means "not applicable". The block then stays `None`, and the
  finding checks never judge `None`.
- **Allowlist, don't copy.** No addresses (leader, peers, audit sockets), cluster
  IDs, file paths, snapshot URLs, storage credentials, error text or metric
  labels leave `collector.py`, and a test asserts it. Snapshot configs are
  listed but never read: a read returns storage credentials in plaintext.
- **Node state decides what is read.** A sealed or uninitialised node answers
  only `sys/health` (queried with `HEALTH_PARAMS` so it returns 200) and
  `sys/seal-status`. A DR secondary answers only the unauthenticated endpoints.
  `cluster-audit` reads `sys/health` before validating the token for exactly
  this reason. That is why it, alone, works on a sealed node.
- **Time-based checks use the node's clock** (`server_time_utc`), not ours, so
  a long namespace walk or host clock skew does not read as replication lag.
- **namespace-audit embeds it**: one `collect_cluster_health` call before the
  walk, stored on `AuditData.cluster_health` / `cluster_coverage`, and
  `health_findings` joins `collect_findings`. full-audit passes everything
  cluster-audit read (health, license, lease TTLs) in as a `ClusterReads`
  through `NamespaceAuditor(cluster_reads=...)`, so no cluster endpoint is read
  twice.
- **One finding per dead secondary.** A peer with no heartbeat since the
  primary started is VT-REPL-002 (Low) and is left out of VT-HLTH-002's
  disconnected list. The skill reports both. The trade-off: after a primary
  restart, a production secondary that is really down looks the same and is
  now reported only at Low.
- **Thresholds are the skill's heuristics** (100,000 leases, 60s lag, 2s skew,
  25h snapshot grace, `MIN_SUPPORTED_VERSION` 1.19, which goes stale). None has
  been measured against the reference cluster yet.

### Identity audit (`src/identity_audit/`)

- **Privacy is the design constraint.** Entity names, metadata and alias names
  can hold emails, usernames and AppRole role_ids. Findings, the CSV and the
  report identify entities **by ID only**; `--list` writes everything else to a
  separate `identity-entities.json`. Because the skill uses the name as the
  object path, VT-ID-001..003 fingerprints do not match the skill's. VT-ID-005
  reports counts only, never the shared alias names.
- **A denied entity body is counted but not judged**: the entity still appears
  (from the LIST), VT-ID-001 is skipped for it, and the namespace gets one
  access-gap row. Only a 403 is a gap. A 404 (deleted mid-walk) drops the
  entity entirely, and a 5xx or timeout is recorded once per namespace as an
  error, so nobody widens a token policy that was never the problem.
- **Discovery is its own LIST-only walk** (`discover_namespaces`), not
  `NamespaceAuditor`'s. That walk also collects mounts and policies and drives
  the progress bar and rate limiting. full-audit passes the namespace list the
  walk already found (stored keys, `""` for root), so the tree is listed once.
- **VT-ID-004 is judged only when the activity log records something**: the
  higher of the billing period and the current month, at least 100 entities
  and more than 3x the active entity clients.

### Activity usage checks (`src/activity_export/findings.py`)

- Run on every `activity-export` (and `all`/`full-audit`) over the data already
  exported. Two extra root reads: `sys/internal/counters/config` always, and
  `activity/monthly` only when the window reaches the current month. Either
  failing leaves the checks unjudged and is recorded; the export never fails
  because of them.
- **A disabled log (VT-CLI-005) must never read as "no clients"**: the report
  says every zero is "not recorded". With no completed billing period yet, the
  month in progress is judged instead (`evidence.source`).
- `run_activity_export` returns `ActivityExportResult(namespaces, mounts,
  findings_document)`, not a bare tuple.

### Full audit (`src/full_audit/`)

- **The report (`report.py`) mirrors the vault-ops skill's audit report**,
  generated deterministically from a `FullAuditContext`. Every sentence in the
  executive summary is built from a measured value; add a sentence only when it
  reads from collected data. Keep the section order (header, executive summary,
  metrics, cluster health and licence, inventory, findings ranked, summary,
  changes, steps, not covered, source files).
- **`src/common/remediation.py` is the catalogue**, ported from the skill's
  `rules.md`: meaning, drafted command templates and watch-out notes per rule,
  plus `RANK_ORDER`. A test requires every rule in `RULES` to have an entry, so
  a new rule needs one too. Take commands from the skill's catalogue and never
  invent endpoints or flags. A rule with no command gets `action` text instead.
  Commands are always "for an operator to run": vault-tools never executes them.
- **Ranking**: High first, then `RANK_ORDER` (cluster-wide before access before
  narrower before hygiene), then severity, then group size. Ranking by count
  alone put 120 copies of one `admin` policy above an expiring licence.

- Order: cluster-audit, namespace-audit, identity-audit, activity-export,
  entity-export. Each step is wrapped by `_run_step`, so an exception becomes a
  `failed` row and the next step runs. A failed step forces
  `coverage.complete` to false.
- **Shared reads**: cluster-audit's `ClusterReads` go to namespace-audit, the
  walk's namespace list to identity-audit, and identity-audit's
  `activity/monthly` read to activity-export (`current_month`, with `NOT_READ`
  as the "not read" default because `None` already means "unreadable").
- **The report's file index is `files_written_since`**: this cluster's files in
  the output directory modified after the run started. Matching by date was
  wrong twice over: the steps mix local and UTC dates in file names, and an
  earlier same-day run's files (an identity `--list` file, say) were claimed
  as this run's.
- A node that rejects authenticated reads runs only cluster-audit; the rest are
  `skipped` with the reason. If cluster-audit cannot connect at all, full-audit
  returns `None` (exit 1): there is no cluster name to file a report under.
- Omitted `-s/-e` means the last 12 calendar months (`default_window`). That is
  close to, but not exactly, Vault's billing period. `all` is unchanged and
  kept for compatibility.

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

Counts are deliberately not recorded here — they go stale on every change. Run
`task test` for the current total.

- **common**: VaultClient, config, logging, file I/O, and the findings model,
  diff and exit codes
- **namespace_audit**: threading, mocking, report rendering, finding rules, ACL
  review and integration
- **cluster_audit** / **identity_audit**: collectors against small fake Vaults
  (`fakes.py`), every rule, and the no-leak assertions
- **full_audit**: orchestration with every step patched
- **activity_export**: API interaction and data processing (this directory also
  holds the entity_export tests)
- **test_cli_parsing.py**: argparse-level tests, no Vault required
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
