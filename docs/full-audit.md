# Full audit

Every audit and export in one run:

```bash
source .env                                            # VAULT_ADDR and VAULT_TOKEN
uv run vault-tools full-audit                          # activity window: the last 12 calendar months
uv run vault-tools full-audit -s 2026-01-01 -e 2026-06-30 --list-entities
uv run vault-tools full-audit --names-only             # policy names only, even if the token can read bodies
uv run vault-tools full-audit --fail-on medium --fail-on-gaps   # for CI: exit 3 on findings, 2 on gaps
uv run vault-tools full-audit --skip entity-export     # token without the entity-export sudo rule
uv run vault-tools full-audit --only namespace-audit   # cluster-audit always runs as well
uv run vault-tools full-audit --only cluster-audit     # just cluster health, with the combined report
```

`--skip` and `--only` are repeatable and mutually exclusive; cluster-audit
cannot be skipped, because every other step needs what it reads. A step left
out is listed as skipped in the report and makes `coverage.complete` false,
since nothing in it was judged. Such a run is **partial**: it writes
`{cluster-name}-partial-findings-{YYYYMMDD}.json` and `-partial-audit-….md`
instead, so it never replaces a complete run's files, and it is never compared
with one (no "Changes since the last run", and `diff` never auto-picks it). The
activity window is only read, validated and printed when an export step runs.

The report path is printed at the end under **Combined files**. Run it again
later and the new report gains a **Changes since the last run** section
comparing against the previous one in the same output directory.

It runs cluster-audit, namespace-audit, identity-audit, activity-export and
entity-export, in that order. Each step writes its usual files, and cluster
health and the namespace list are read once and shared between steps. On top
of those, `{cluster-name}-full-audit-{YYYYMMDD}.md` is a single review document
laid out like the vault-ops skill's audit report:

- **Header and executive summary**: cluster and ID, version, run time,
  coverage and findings by severity. Then a summary generated from the data:
  node health, replication, time-bound items (licence expiry, including when
  it expires and terminates the same day with no grace period), the top risks,
  raft failure tolerance, and where findings cluster (e.g. one `admin` policy
  copied into 120 namespaces).
- **Summary metrics**: namespaces and depth, mounts and types, policies,
  Sentinel, lease TTLs, licence, leases, entities, clients, denied and errors.
- **Cluster health and licence**: node state, replication, raft peers and
  autopilot, audit devices (non-default options), automated snapshots, node
  metrics with their thresholds, and licence features.
- **Inventory**: auth and secrets types, the hierarchy collapsed by shape
  (depth, auth types, engine types, count, examples), the busiest ACL
  namespaces, Sentinel by level, identity entities and client usage.
- **Findings, ranked**: one item per rule. Cluster-wide availability and
  lifecycle items come first, then access, then narrower risks, then hygiene.
  Each item says what the rule means, the affected count with examples,
  **drafted commands for an operator to run** filled with the finding's
  namespace and object, and what to watch out for. Copies of the same finding
  are listed once.
- **Summary, Changes since the last run, Steps, Not covered, Source files**:
  a rule table; an automatic diff against the previous full-audit for the same
  cluster in the output directory; per-step status and duration; what was
  skipped or not assessed; and every file the run wrote.

The console prints step timings, the findings by severity and the top five
ranked findings. vault-tools never runs the drafted commands.

`{cluster-name}-full-findings-{YYYYMMDD}.json` holds the merged findings. A
failing step does not stop the rest, but it does mark coverage incomplete. On a
sealed or DR-secondary node only cluster-audit runs, and the skipped steps mark
coverage incomplete too, so `--fail-on-gaps` exits 2 there.
