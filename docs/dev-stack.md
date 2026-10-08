# Dev stack

A local Vault to test vault-tools against, ported from the vault-ops skill's
stack. There are two parts:

- **`compose.yaml`**: Vault Enterprise on raft with TLS. The primary always
  runs; a DR secondary and a performance secondary are optional.
- **`compose.ce.yaml`**: a throwaway Vault Community dev server, in memory and
  plain HTTP, for the CE smoke tests.

Its ports (primary 8310, DR 8320, performance 8340, Community 8330) and compose
project names (`vault-tools`, `vault-tools-ce`) differ from the skill's, so
both stacks can run at once.

## Prerequisites

- Docker with Compose (or Podman: set `CONTAINER_CLI=podman`), `task`, `uv`,
  the `vault` CLI, `jq`, `curl`, `openssl`, `lsof`.
- For `compose.yaml`: a Vault Enterprise licence in `.env` (`VAULT_LICENSE`).
  The optional secondaries need one that includes DR and performance
  replication. `compose.ce.yaml` needs no licence.

```bash
task init   # creates .env from .env.example if it is missing
task deps   # checks tools, the container runtime, free ports and .env
```

`.env.example` points `VAULT_ADDR` at the primary, `VAULT_TOKEN` at its `root`
token and `VAULT_CACERT` at the stack's CA. The images are pinned to a minor
version (`vault-enterprise:2.1-ent`, `vault:2.1`), so patch releases arrive on
the next pull.

## Primary only (the default)

This covers every check except replication: namespaces, ACL and Sentinel
policies, identity, client usage, audit devices, snapshots, licence and metrics.

```bash
task up               # start, init, unseal; token "root"; TLS CA in .tmp/vault/tls
task seed             # ~130 namespaces with mounts, KV data, PKI, transit, identity, client activity
task seed:findings    # configuration that trips every live-testable rule
task token:policies   # 1h audit token (base policy + both body-reader add-ons) in .tmp/audit-token
source .env
VAULT_TOKEN="$(cat .tmp/audit-token)" uv run vault-tools full-audit
```

`task token:audit` mints a token with the base policy only, which shows the
"not readable" policy-body path. The dev stack's tasks (`seed`,
`seed:findings`, `token:*`, `status`) always target the local primary with the
`root` token, whatever `VAULT_ADDR` your shell exports, so a seed never lands on
a real cluster.

`task seed:findings` seeds, among others, VT-AUTH-001, VT-MOUNT-002 to 006,
VT-NS-002, VT-ID-001 to 003 and 005, VT-POL-004, VT-AUD-003, VT-SNAP-003 and
VT-SNT-001 to 005 and 007. VT-SNT-006 (a hard-mandatory policy that always fails)
is not seeded, because it would lock you out of the cluster.

## Optional: DR and performance secondaries

Use these for replication or node-state work:

- VT-HLTH-002, VT-REPL-002 (a stale activation token) and VT-REPL-005 (a paths
  filter);
- `cluster-audit` against a DR secondary, which answers only unauthenticated
  reads;
- a performance secondary's own inventory;
- parsing real replication responses.

```bash
task up:dr up:pr      # or: task up:all
task dr:enable        # DR primary -> vault-dr, waits for stream-wals
task pr:enable        # performance primary -> vault-pr; restores token "root" there
task seed seed:findings  # seed after enabling replication (see below)
task token:policies token:pr
task audit:dev        # full-audit on the primary, cluster-audit on each running secondary
```

**Enable replication before seeding.** Enabling it restarts the primary, which
drops client activity that has not been saved yet. `seed:findings` adds the
replication findings only when the primary is already a performance primary.

VT-REPL-001, 003 and 004 (lag, clock skew and a corrupted merkle tree) cannot
be produced on demand, so they are covered by unit tests only.

The secondaries cost three Enterprise containers, and they need
`enable_unauthenticated_access = ["generate-root"]` in `compose/vault.hcl`.
Activating a performance secondary wipes its tokens, so `pr-enable.sh` restores
`root` with the unauthenticated generate-root ceremony and the primary's unseal
key. That setting is for dev only.

`task dr:status` and `task pr:status` show the replication state.
`NODE=vault-dr task logs` tails a node's log.

## Community server and CE smoke tests

```bash
task test:ce          # start, test unsealed, seal, test sealed, remove
task up:ce            # or start it for manual runs (root token vault-tools-ce-root)
task down:ce
```

`task test:ce` (`scripts/test-ce.sh`) sets up a KV v1 mount and an `admin`
policy, mints a 15-minute audit token from `policies/` and runs
`tests/test_ce.py` twice:

- **Unsealed:** every subcommand exits 0 with complete coverage. Edition,
  Sentinel and policy-body status are checked, and VT-AUD-001, VT-MOUNT-006,
  VT-POL-001 and VT-CLI-005 must fire.
- **Sealed:** `cluster-audit` exits 0 with VT-HLTH-001 only, the authenticated
  subcommands exit 1, and `full-audit` runs only cluster-audit.

The tests are skipped unless `VAULT_TOOLS_CE` is set, so `task test` and CI
never need a server.

## Tear down

```bash
task down             # stop every node; data volumes and .tmp/vault unseal keys are kept
task clean            # also removes the volumes and .tmp/ (keys and data stay in step)
task test:e2e         # destructive: everything from scratch, then every test and lint
```

## Known limits

- On a freshly seeded cluster, `activity-export` and `entity-export` report no
  clients for the current month. The activity log exports months that have
  ended, while the seeded logins fall in the current month, which only
  `sys/internal/counters/activity/monthly` reports.
