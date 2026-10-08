# Configuration

## Required Environment Variables

Set the following environment variables before running the tool:

```bash
export VAULT_ADDR="https://vault.example.com"
export VAULT_TOKEN="your-vault-token"
export VAULT_SKIP_VERIFY="true"  # Optional, for dev environments
```

## Optional Configuration

Customize behavior via environment variables:

```bash
export VAULT_TOOLS_OUTPUT_DIR="custom-outputs"  # Output directory
export VAULT_TOOLS_AUDIT_DIR="custom/audit"     # Audit log directory
export VAULT_TOOLS_DEBUG="true"                 # Enable debug logging
```

Everything else is a CLI flag — see `python main.py <command> --help`. Worker
count is `--workers`, output directory is `--output-dir` (which overrides
`VAULT_TOOLS_OUTPUT_DIR`), the export window is `--start-date`/`--end-date`,
and CI gating is `--fail-on`/`--fail-on-gaps`. The opt-in collections are
`--list` (identity-audit) and `--list-entities` (full-audit). Policy bodies are
read whenever the token allows; `--names-only` (namespace-audit, full-audit)
opts out.

## Output file names

Every file starts with the cluster name and the first eight hex characters of
the cluster ID: `{cluster-name}-{cluster-id-8}-{kind}-{YYYYMMDD}.{ext}`, e.g.
`vault-cluster-d33099d9-audit-report-20261008.md`. So two clusters that share a
name never overwrite each other's outputs. A name that already ends in its ID,
like Vault's default `vault-cluster-d33099d9`, is not doubled. A sealed node
reports no ID, so its files use the name alone. File names elsewhere in these
docs are written `{cluster-name}-{kind}-…` for brevity.
