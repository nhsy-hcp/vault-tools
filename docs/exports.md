# Activity and entity exports

## Activity Export

Export Vault activity logs and usage metrics, and check them for client
anti-patterns. Both dates are required:

```bash
# Export for a specific date range
python main.py activity-export --start-date 2026-01-01 --end-date 2026-01-31

# Short flags
python main.py activity-export -s 2026-01-01 -e 2026-01-31

# See all options
python main.py activity-export --help
```

Alongside the export, `{cluster-name}-activity-findings-{YYYYMMDD}.json` and
`.md` (plus `.csv` when there are findings) report:

- `VT-CLI-001`: most of a namespace's clients are token-only.
- `VT-CLI-002`: sharp growth over recent months.
- `VT-CLI-003`: a mount where most clients are new each month (identities
  created per run).
- `VT-CLI-004`: on Enterprise, most clients in root.
- `VT-CLI-005`: the activity log is disabled.

When the log is off the report says that every zero count means "not
recorded", not "no clients". When the window has no completed billing period
yet, the month in progress is judged instead.

## Entity Export

Extract and export Vault entity data. Both dates are required:

```bash
python main.py entity-export --start-date 2026-01-01 --end-date 2026-01-31

# See all options
python main.py entity-export --help
```

A range with no client records is not an error: Vault answers `204 No Content`
and the export reports that there is no data and exits successfully.

## All (legacy)

Run three subcommands in sequence, sharing one Vault connection.
`full-audit` is the superset; `all` is kept for compatibility:

```bash
python main.py all -s 2026-01-01 -e 2026-01-31

# Via the task runner
task run -- all -s 2026-01-01 -e 2026-01-31
```
