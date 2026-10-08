# Vault Tools

[![Test Vault Tools](https://github.com/nhsy-hcp/vault-tools/actions/workflows/test.yml/badge.svg)](https://github.com/nhsy-hcp/vault-tools/actions/workflows/test.yml)
[![Python 3.12+](https://img.shields.io/badge/python-3.12+-blue.svg)](https://www.python.org/downloads/)
[![License: MPL 2.0](https://img.shields.io/badge/License-MPL_2.0-brightgreen.svg)](https://opensource.org/licenses/MPL-2.0)

A unified CLI tool for comprehensive HashiCorp Vault operations, providing defensive security capabilities for namespace auditing, activity monitoring, and entity management.

## Features

- **Namespace Audit**: Multi-threaded namespace traversal with rate limiting, JSON/CSV output and a markdown audit report, plus a review of what each ACL and Sentinel policy grants when the token is allowed to read them
- **Cluster Audit**: Seal, HA, replication, raft, audit devices, automated snapshots and node metrics — works against a sealed or DR-secondary node too
- **Identity Audit**: Orphaned, disabled and directly-granted entities, duplicate aliases and entity sprawl
- **Activity Export**: Vault activity log processing and export with flexible date ranges, plus client-usage checks
- **Entity Export**: Entity data extraction and CSV/JSON reporting
- **Full Audit**: Every audit and export in one run, with a combined report
- **Machine-readable findings**: Every audit writes a `findings.json` compatible with the vault-ops skill, with a `diff` subcommand and CI exit codes

## Quick Start

1. **Prerequisites**: Python 3.12+, [uv](https://docs.astral.sh/uv/), the
   `vault` CLI, and an admin able to write policies in the Vault cluster
2. **Install**: `uv sync`
3. **Create a read-only audit token**: see [Create an audit token](#create-an-audit-token)
4. **Configure**: export `VAULT_ADDR` and `VAULT_TOKEN`, or put them in `.env`
   (copy [`.env.example`](.env.example))
5. **Run**: `uv run vault-tools full-audit`, then open the report path it
   prints under **Combined files**

```bash
uv sync
export VAULT_ADDR=https://vault.example.com:8200
vault policy write vault-tools-audit policies/audit-policy.hcl   # once, by an admin
export VAULT_TOKEN="$(vault token create -policy=vault-tools-audit -no-default-policy -orphan -ttl=1h -field=token)"
uv run vault-tools full-audit
# → outputs/{cluster-name}-{cluster-id-8}-full-audit-{YYYYMMDD}.md
```

## Installation

### Prerequisites

- Python 3.12 or higher
- [uv](https://docs.astral.sh/uv/) package manager
- Access to a HashiCorp Vault instance
- Valid Vault token with appropriate permissions

### Setup and Run

```bash
# Clone the repository
git clone https://github.com/nhsy-hcp/vault-tools.git
cd vault-tools

# Sync dependencies (creates virtual environment automatically)
uv sync

# Load VAULT_ADDR and VAULT_TOKEN (see "Create an audit token" below)
source .env

# Run the CLI
uv run vault-tools --help
uv run vault-tools full-audit              # every audit and export, plus a combined report
uv run vault-tools namespace-audit         # or any single subcommand

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

### Create an audit token

The tool is read-only: it only sends GET and LIST requests. The token's policies
decide what it can see, so mint a dedicated token from the supplied policies
instead of using a root token. An admin runs this once, in the **root
namespace** (unset `VAULT_NAMESPACE`):

```bash
export VAULT_ADDR=https://vault.example.com:8200

# Once per cluster, by an admin
vault policy write vault-tools-audit           policies/audit-policy.hcl
vault policy write vault-tools-acl-reader      policies/audit-policy-acl-reader.hcl       # optional add-on
vault policy write vault-tools-sentinel-reader policies/audit-policy-sentinel-reader.hcl  # optional add-on

# Mint a short-lived token. Choose one line, by what you want assessed:
# base only: inventory, health, identity, usage; policy names only
export VAULT_TOKEN="$(vault token create -policy=vault-tools-audit -no-default-policy -orphan -ttl=1h -field=token)"
# + ACL review (VT-POL): what each ACL policy grants
export VAULT_TOKEN="$(vault token create -policy=vault-tools-audit -policy=vault-tools-acl-reader -no-default-policy -orphan -ttl=1h -field=token)"
# + ACL and Sentinel review (VT-POL, VT-SNT): everything
export VAULT_TOKEN="$(vault token create -policy=vault-tools-audit -policy=vault-tools-acl-reader -policy=vault-tools-sentinel-reader -no-default-policy -orphan -ttl=1h -field=token)"

uv run vault-tools full-audit
```

To keep the address and token out of your shell history, put them in `.env`
instead. It is git-ignored, and [`.env.example`](.env.example) is the template.
Each line uses `export`, so sourcing it sets the variables for the tool. Load
it into the shell before each run:

```bash
cp .env.example .env                 # then set VAULT_ADDR and VAULT_TOKEN in it
source .env
uv run vault-tools full-audit
```

Already logged in with the `vault` CLI? You can reuse that session's token
instead of minting one:

```bash
export VAULT_TOKEN="$(vault print token)"
```

That is your own token, usually far broader than the audit token: fine for a
quick look, but use the audit token above for anything you share or automate.

`task run -- full-audit` loads `.env` by itself, so no `source` is needed there.

- `-no-default-policy` works because `audit-policy.hcl` grants the
  `auth/token/lookup-self` check itself. `-orphan` keeps the token from
  disappearing if the admin's own token is revoked first.
- An hour is ample: a full audit of a 130-namespace cluster takes seconds.
  Revoke the token when you're done (`vault token revoke <token>`), and drop the
  add-ons if you only needed them for one policy review.
- For a self-signed dev server set `VAULT_SKIP_VERIFY=true`.
- Without an add-on the run still succeeds. The report lists those policies by
  name and says, under **Not covered**, which add-on to attach. See
  [Vault Token Permissions](#vault-token-permissions) for what each rule grants
  and why.

## Usage

Run the CLI directly with `python main.py`, through uv as `uv run vault-tools`,
or via the task runner as `task run -- <args>` (everything after `--` is passed
straight through). The subcommands are:

| Subcommand | What it does |
| --- | --- |
| `namespace-audit` | Walks every namespace: mounts, ACL and Sentinel policies, plus cluster health |
| `cluster-audit` | Cluster-level health only; also works on sealed and DR-secondary nodes |
| `identity-audit` | Identity entities and aliases in every namespace |
| `activity-export` | Activity log export plus client-usage checks |
| `entity-export` | Client entity export |
| `full-audit` | All of the above, plus a combined report |
| `all` | `namespace-audit`, `activity-export` and `entity-export` in sequence (kept for compatibility) |
| `diff` | Compares two `findings.json` files; needs no Vault connection |

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

Each run writes up to fourteen files to the output directory: up to eight JSON
files, up to five CSV summaries, and a markdown report,
`{cluster-name}-audit-report-{YYYYMMDD}.md`. The report and
`{cluster-name}-namespace-findings-{YYYYMMDD}.json` (see
[Findings, diffs and CI](#findings-diffs-and-ci)) are written on every run.
The two Sentinel files are written only on a cluster that has Sentinel
policies, `license.json` only when the Enterprise license could be read,
`acl-policy-review.json` only when the token could read ACL bodies, and the CSV summaries are
skipped when they would be empty, so a small cluster produces fewer files — eight
on a root-only Community dev server.

The console shows the run itself — a progress bar, the summary table and the
list of files written — and nothing else. Per-namespace detail, file-write
confirmations and connection setup are logged at INFO and hidden by default,
because printing them alongside a live progress bar corrupts it. Pass `--debug`
to see them, or `--json-logs` for the full event stream in a form a log
aggregator can consume.

The report is the human-readable view of the audit and contains:

- **Header** — the cluster name and ID, the `VAULT_ADDR` it was audited through,
  the generation timestamp, the tool version, the starting namespace and the
  Vault version with its edition (Enterprise or Community), so a report found on
  its own still says which cluster it describes. The console prints the same
  address when the run starts.
- **Summary** — total namespaces, maximum nesting depth, mount totals and
  distinct type counts, duration, errors and denials, plus the license expiry
  date and licensed feature count on Enterprise.
- **Cluster health** — the same section `cluster-audit` writes (see below),
  read once before the walk: node and seal state, replication, raft, audit
  devices, automated snapshots and node metrics.
- **License** — Enterprise only: license ID, issuer, soft-expiry and hard
  termination dates, performance standby count and the licensed features. If
  the license could not be read, the section says why — denied, a server error,
  or an unexpected response — rather than disappearing. Community clusters omit
  the section.
- **Access gaps** — every namespace the token was denied, by name, and whether
  the whole namespace or only its child listing was refused. This is the section
  to read first: it bounds how much of the cluster the rest of the report
  actually covers. A denied license read is listed separately as a cluster-level
  read, because it does not make any namespace incomplete.
- **Namespace inventory** — the hierarchy as an indented tree with per-namespace
  mount counts, then a table of namespace IDs, depth and custom metadata.
- **Type distribution** — how many mounts of each auth method and secrets engine
  type exist and in how many namespaces, plus a per-namespace matrix for smaller
  clusters.
- **ACL policies** — the policies each namespace defines, one row per
  namespace. Vault's own `default`, `root` and `default-ceiling` exist in every
  namespace and are excluded, so a namespace showing `0` genuinely defines
  none of its own. What each policy grants is reviewed too when the token
  allows it; see [Policy body review](#policy-body-review-acl-and-sentinel).
- **Sentinel policies** — the endpoint- and role-governing policies in force per
  namespace, with their enforcement levels, the endpoints an EGP covers and the
  size of each policy body. Vault Enterprise with the Governance & Policy module
  only; see below.
- **Security observations** — prompts for review, each tagged with a rule ID
  from the vault-ops skill's catalogue (`VT-MOUNT-001` and so on):
  - Mounts: deprecated or pending-removal plugins, auth mounts enumerable by
    unauthenticated callers (`listing_visibility: unauth`), a `max_lease_ttl`
    that overrides the cluster ceiling, a `default_lease_ttl` above 768h,
    non-replicated `local` mounts, KV version 1, and more than 20 mounts of
    one type in a namespace.
  - Namespaces: no auth method beyond the built-in token backend, and leaf
    namespaces holding nothing but Vault's own built-in engines.
  - Sentinel: policies that do not actually block anything (`advisory` or
    `soft-mandatory` enforcement, a wildcard EGP path, or a body that always
    evaluates to true), a hard-mandatory policy that always denies, an `http`
    import, and same-named policies whose bodies differ across namespaces.
  - Cluster: a cluster `default_lease_ttl` above 768h, an Enterprise license
    expiring within 90 days (Medium) or already past its soft expiry (High,
    with the hard termination date), and every cluster health check listed
    under `cluster-audit`.
  - ACL permissions, when the token can read policy bodies.
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

#### Sentinel policies

`sys/policies/egp` and `sys/policies/rgp` exist only on Vault Enterprise with the
Governance & Policy module. Everywhere else they return 404, which the audit
detects once and then stops probing — a Community run costs a single extra API
call and reports **Sentinel EGP/RGP endpoints are unavailable on this cluster**
rather than "zero policies found". The two readings mean very different things,
so the report never collapses them. Pass `--no-sentinel` to skip the collection
entirely; the section then says so explicitly.

Enforcement levels, EGP paths and every VT-SNT check need the policy *body*, so
they are assessed only when the token can read bodies (see below). Without that,
the report lists the policy names and says they were not assessed. Policy source
is never written anywhere: `{cluster-name}-sentinel-policies-{YYYYMMDD}.json`
holds names, enforcement levels, paths, a body hash and import names, so
compare hashes between runs to spot an edited policy.

To exercise this against a local cluster, `task seed:sentinel` writes five no-op
policies from [`examples/sentinel/`](examples/sentinel) — one per enforcement
level, a wildcard EGP path, an always-true rule, and a hard-mandatory control
that must produce no finding. Every one of them passes unconditionally, so
nothing is ever blocked. `task unseed:sentinel` removes them.
Both accept namespaces: `task seed:sentinel -- team-a/ team-b/`.

#### Policy body review (ACL and Sentinel)

**The token is the source of truth.** There is no flag to turn the review on.
vault-tools tries to read ACL and Sentinel policy bodies, and the token's
policies decide what it gets:

| Token carries | ACL permissions (VT-POL) | Sentinel (VT-SNT) |
| --- | --- | --- |
| `policies/audit-policy.hcl` only | Names only | Names only |
| plus [`policies/audit-policy-acl-reader.hcl`](policies/audit-policy-acl-reader.hcl) | Assessed | Names only |
| plus [`policies/audit-policy-sentinel-reader.hcl`](policies/audit-policy-sentinel-reader.hcl) | Names only | Assessed |
| plus both add-ons | Assessed | Assessed |

A missing add-on is **not** an access gap and does not fail `--fail-on-gaps`.
The first denied body read settles it for the run, so the rest are skipped. The
report's header and **Not covered** section then say which add-on to attach,
and findings.json records it under `cluster_context.policy_bodies`.
`--names-only` lists names without reading any body, even when the token could.

With the ACL add-on, every ACL policy body (all but `root`, built-ins included,
so a widened `default` is caught) is checked for what it grants:

- `VT-POL-001`: write or `sudo` on a path that matches everything (`*`, `+/*`, …).
- `VT-POL-002`: write access to something that controls access: policies,
  auth methods, mounts, namespaces, token creation or roles, identity.
- `VT-POL-003`: `sudo` anywhere.
- `VT-POL-004`: a same-named policy whose body differs across namespaces.
- `VT-POL-005`: a body that could not be parsed.

The add-ons are separate because reading bodies lets a token reconstruct the
cluster's access model. Grant them for a policy review, then drop them again.
Bodies are reduced in memory either way. For ACL, only a hash and the flagged
rules' paths and capabilities are kept, in
`{cluster-name}-acl-policy-review-{YYYYMMDD}.json`. For Sentinel, only names,
levels, paths, hash, imports and flagged rules are kept. Policy text and
allowed/denied parameter values are never written anywhere. Each ACL rule is
judged on its own, so a `deny` elsewhere, or another policy on the same token,
can narrow a flagged rule. Expect `VT-POL-003` on this tool's own
`policies/audit-policy.hcl`, which needs `sudo` on three exact read-only paths.

```bash
vault policy write vault-tools-audit policies/audit-policy.hcl
vault policy write vault-tools-acl-reader policies/audit-policy-acl-reader.hcl
vault policy write vault-tools-sentinel-reader policies/audit-policy-sentinel-reader.hcl
# Choose what to assess by choosing the token's policies:
export VAULT_TOKEN="$(vault token create -policy=vault-tools-audit -policy=vault-tools-acl-reader -policy=vault-tools-sentinel-reader -no-default-policy -orphan -ttl=1h -field=token)"
python main.py namespace-audit
```

### Cluster Audit

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
- `VT-LIC-001` and `VT-LEASE-001`, as in namespace-audit.

Metrics are the queried node's own gauges, never cluster totals. Addresses,
cluster IDs, file paths, snapshot URLs and storage credentials are never stored.

### Identity Audit

```bash
python main.py identity-audit
python main.py identity-audit --list   # also write names, metadata and aliases
```

Reads every identity entity in every namespace and checks for:

- `VT-ID-001`: entities with no aliases.
- `VT-ID-002`: policies attached directly to an entity.
- `VT-ID-003`: disabled entities.
- `VT-ID-004`: a namespace with at least 100 entities and more than three times
  its active entity clients. Only judged when the activity log records something.
- `VT-ID-005`: the same alias name on several entities.

Entity names, metadata and alias names can hold emails, usernames and AppRole
role_ids. The findings, the per-namespace CSV and the report therefore identify
entities by ID only. `--list` writes everything to a separate
`{cluster-name}-identity-entities-{YYYYMMDD}.json`; treat that file as
confidential.

### Activity Export

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

### Entity Export

Extract and export Vault entity data. Both dates are required:

```bash
python main.py entity-export --start-date 2026-01-01 --end-date 2026-01-31

# See all options
python main.py entity-export --help
```

A range with no client records is not an error: Vault answers `204 No Content`
and the export reports that there is no data and exits successfully.

### Full Audit

Every audit and export in one run:

```bash
source .env                                            # VAULT_ADDR and VAULT_TOKEN
uv run vault-tools full-audit                          # activity window: the last 12 calendar months
uv run vault-tools full-audit -s 2026-01-01 -e 2026-06-30 --list-entities
uv run vault-tools full-audit --names-only             # policy names only, even if the token can read bodies
uv run vault-tools full-audit --fail-on medium --fail-on-gaps   # for CI: exit 3 on findings, 2 on gaps
```

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
sealed or DR-secondary node only cluster-audit runs.

### Findings, diffs and CI

Every audit writes a `*-findings-*.json` in the vault-ops skill's schema
([`schemas/findings.schema.json`](schemas/findings.schema.json)). Each finding
has a stable fingerprint, a rule ID, a severity and structured evidence, and
the document records coverage: what was denied or errored.

```bash
# What changed between two runs (no Vault connection needed)
python main.py diff outputs/old-namespace-findings.json outputs/new-namespace-findings.json

# Gate CI on the results
python main.py namespace-audit --fail-on medium --fail-on-gaps
```

| Exit code | Meaning |
| --- | --- |
| 0 | Completed |
| 1 | Fatal: connection, token or configuration error, or the audit failed |
| 2 | `--fail-on-gaps` and coverage was incomplete |
| 3 | `--fail-on <severity>` and a finding was at or above it (wins over 2) |

`--fail-on` and `--fail-on-gaps` work on every command that writes findings.

### All

Run three subcommands in sequence, sharing one Vault connection.
`full-audit` is the superset; `all` is kept for compatibility:

```bash
python main.py all -s 2026-01-01 -e 2026-01-31

# Via the task runner
task run -- all -s 2026-01-01 -e 2026-01-31
```

### Output file names

Every file starts with the cluster name and the first eight hex characters of
the cluster ID: `{cluster-name}-{cluster-id-8}-{kind}-{YYYYMMDD}.{ext}`, e.g.
`vault-cluster-d33099d9-audit-report-20261008.md`. So two clusters that share a
name never overwrite each other's outputs. A name that already ends in its ID,
like Vault's default `vault-cluster-d33099d9`, is not doubled. A sealed node
reports no ID, so its files use the name alone. File names below are written
`{cluster-name}-{kind}-…` for brevity.

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
root token, use the supplied policies in [`policies/`](policies), which grant
only the endpoints the tool actually calls; the steps are under
[Create an audit token](#create-an-audit-token). Lower `-ttl` for CI use.

Things to know about the policy:

- **It must live in the root namespace.** Vault ACL policies are namespace-local,
  and a token does *not* inherit a same-named policy defined in a child
  namespace. Child namespaces are therefore reached through namespace-prefixed
  paths (`+/sys/mounts`, `+/+/sys/mounts`, ...), where `+` matches one namespace
  segment. The policy covers the root namespace plus five levels of nesting; a
  deeper hierarchy needs one more `+/` rule per extra level.
- **Three rules need `sudo`.** Vault root-protects
  `sys/internal/counters/activity/export` (entity-export), listing `sys/audit`
  and listing `sys/storage/raft/snapshot-auto/config` (cluster-audit), so
  `read` alone returns 403. Each is an exact path, which grants nothing below it:
  devices cannot be enabled or disabled, and snapshot configs, which hold
  storage credentials, stay unreadable. Everything else is plain `read`/`list`.
- **`sys/config/state/sanitized` is optional.** It supplies the cluster's lease
  TTLs, which calibrate the audit report's lease findings. Removing the rule
  degrades those findings to a fixed threshold; it does not fail the run.
- **`sys/policies/acl` is granted `list`, never `read`.** Listing yields policy
  names, which is all the ACL inventory needs. `read` would yield the HCL
  bodies, and a token able to read every policy in the tree can reconstruct
  the cluster's whole access model — a large privilege increase for a
  read-only audit. Body reads live in the separate add-on
  [`policies/audit-policy-acl-reader.hcl`](policies/audit-policy-acl-reader.hcl): attach it to
  the token to assess permissions. Removing the list rule drops that report
  section and records the denials; it does not fail the run.
- **The `sys/policies/egp` and `sys/policies/rgp` rules list names only.**
  Reading Sentinel bodies needs the
  [`policies/audit-policy-sentinel-reader.hcl`](policies/audit-policy-sentinel-reader.hcl)
  add-on. The rules are Enterprise-Premium-only, so on any other cluster they
  grant nothing. A denied listing puts the affected namespaces in **Access
  gaps** rather than failing the audit.
- **`sys/license/status` is optional.** It supplies the report's License
  section and expiry findings on Enterprise, and grants nothing on Community.
  Removing the rule makes the License section report the read as denied and
  **Access gaps** note it as a cluster-level read; it does not fail the run.
- **The cluster health rules are optional.** These cover replication, raft,
  metrics, audit devices and snapshots. A missing rule empties that block,
  lists the endpoint under **Cluster-level reads**, and makes `findings.json`
  coverage incomplete. `sys/health`, `sys/seal-status` and `sys/leader` are
  unauthenticated and need no rule.
- **`identity/entity/id` is namespace-local** (`list`, plus `read` on `/*`),
  with one rule per nesting level, for `identity-audit`.
  `sys/internal/counters/config` and `activity/monthly` are root-only reads for
  the usage checks.

Policy files are kept `vault policy fmt`-clean: `task lint` checks it and
`task fmt:policy` fixes it.

If the token lacks `sys/namespaces` at some level, the audit stops descending
there and reports the namespaces it did reach. The **Permission Denied (skipped)**
count in the console summary table should be `0`; when it is not, the **Access
gaps** section of the markdown report names each denied namespace and says
whether the whole namespace or only its child listing was refused, so you can see
exactly which subtrees are missing and widen the policy accordingly.

## Key Features

### Performance & Reliability

- **Connection Pooling**: Reusable HTTP connections with 20-30% performance improvement
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
- **Quiet by Default**: The console carries progress and results; `--debug` adds per-namespace detail

### Optional Configuration

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

**Modular design**, one package per subcommand:

- `src/namespace_audit/` - Multi-threaded namespace traversal (`main.py`),
  markdown report rendering (`report.py`) and the ACL policy review (`acl.py`)
- `src/cluster_audit/` - Cluster health collection, checks and report
- `src/identity_audit/` - Entity collection, checks and report
- `src/activity_export/` - Activity log processing and usage checks
- `src/entity_export/` - Entity data extraction
- `src/full_audit/` - Runs every step and merges their findings
- `src/findings_diff/` - The `diff` subcommand
- `src/common/` - Shared utilities (VaultClient, Config, FileUtils), the
  findings model and rule catalogue (`findings.py`) and markdown helpers

**Output:** Structured JSON/CSV files in the `outputs/` directory, a markdown
report and a `findings.json` per audit.

## Contributing

1. Fork and create feature branch
2. Add tests for new functionality
3. Run `task test:ci` — the same lint and 80% coverage gate CI enforces
4. Submit pull request

## License

This project is intended for defensive security purposes only. Use responsibly and in accordance with your organization's security policies.

## Support

For issues, questions, or contributions, please use the project's issue tracker.
