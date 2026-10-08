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
  100,000 leases.
- `VT-REPL-001`…`005`: peer lag, a secondary with no heartbeat, clock skew, a
  corrupted merkle tree (High), and performance paths filters.
- `VT-AUD-001`…`003`: no audit device, only one device, or a device logging raw
  values or unhashed accessors.
- `VT-SNAP-001`…`003`: no automated snapshots, a failing or overdue snapshot,
  and snapshots on the node's local disk.
- `VT-LIC-001` and `VT-LEASE-001`, as in [namespace-audit](namespace-audit.md).

Metrics are the queried node's own gauges, never cluster totals. Addresses,
cluster IDs, file paths, snapshot URLs and storage credentials are never stored.
