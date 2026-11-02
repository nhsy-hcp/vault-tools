# Cluster audit

Cluster-level health on its own, without walking namespaces:

```bash
python main.py cluster-audit
```

It reads the unauthenticated `sys/health` first, so a **sealed**, uninitialised
or **DR-secondary** node still gets a report (seal state, or replication status)
where every other command would fail on token validation. It writes
`{cluster-name}-cluster-health-{YYYYMMDD}.json`,
`{cluster-name}-cluster-findings-{YYYYMMDD}.json` and
`{cluster-name}-cluster-audit-report-{YYYYMMDD}.md`. Checks:

- `VT-HLTH-001`…`006`: node sealed or no active leader, replication unhealthy,
  Vault older than 1.19, raft autopilot unhealthy, irrevocable leases, more than
  100,000 leases (`--lease-count-warning`).
- `VT-REPL-001`…`005`: peer lag, a secondary with no heartbeat, clock skew, a
  corrupted merkle tree (High), and performance paths filters.
- `VT-AUD-001`…`003`: no audit device, only one device, or a device logging raw
  values or unhashed accessors.
- `VT-SNAP-001`…`003`: no automated snapshots, a failing or overdue snapshot,
  and snapshots on the node's local disk. A snapshot is overdue once it is later
  than its own interval or 25h (`--snapshot-grace`), whichever is longer, past
  its scheduled start; a run still in progress is never overdue.
- `VT-LIC-001` and `VT-LEASE-001`, as in [namespace-audit](namespace-audit.md).

Metrics are the queried node's own gauges, never cluster totals. Addresses,
cluster IDs, file paths, snapshot URLs and storage credentials are never stored.

## Tuning thresholds

Two thresholds can be set per run on `cluster-audit`, `namespace-audit` and
`full-audit`; the defaults are the vault-ops skill's values:

| Flag | Default | Rule |
| --- | --- | --- |
| `--lease-count-warning N` | 100,000 | `VT-HLTH-006` fires above N outstanding leases on the queried node. |
| `--snapshot-grace DURATION` | `25h` | `VT-SNAP-002` grace past the scheduled start (`90m`, `2h`, `1d`, or seconds). The schedule's own interval is always a floor. |

Lower `--snapshot-grace` for schedules more frequent than daily. Below 25h it
can fire falsely once after a schedule is lengthened, until the next run,
because Vault keeps the old next-run time until then. A tuned value is recorded
in the finding's evidence (`threshold`, `grace_seconds`).

To see how close a cluster is to each threshold before tuning, run
`cluster-audit` on each node and then:

```bash
uv run scripts/threshold-margins.py outputs/*-cluster-health-*.json
```
