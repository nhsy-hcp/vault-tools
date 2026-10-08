# Activity and entity exports

## Activity Export

Export Vault activity logs and usage metrics, and check them for client
anti-patterns. Pass both dates or neither; with neither, the window is the
last 12 calendar months and is printed before the export starts:

```bash
# The last 12 calendar months
python main.py activity-export

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

Extract and export Vault entity data. The dates work as for activity-export:

```bash
python main.py entity-export
python main.py entity-export --start-date 2026-01-01 --end-date 2026-01-31

# See all options
python main.py entity-export --help
```

A range with no client records is not an error: Vault answers `204 No Content`
and the export reports that there is no data and exits successfully.

Vault root-protects `sys/internal/counters/activity/export`, so the token needs
`read` and `sudo` on that exact path ([token and policies](token-and-policies.md)).
A 403 names that rule. activity-export does not need it.

## `all` (removed in 3.1.0)

`all` ran namespace-audit and both exports. Use `full-audit`, which runs every
audit and export, isolates a failing step, honours `--fail-on`/`--fail-on-gaps`
and writes a combined report. `full-audit --only activity-export --only
entity-export` runs just the exports (cluster-audit always runs first).
