# Namespace audit

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
[Findings, diffs and CI](findings-and-ci.md)) are written on every run.
The two Sentinel files are written only on a cluster that has Sentinel
policies, `license.json` only when the Enterprise license could be read,
`acl-policy-review.json` only when the token could read ACL bodies, and the CSV summaries are
skipped when they would be empty, so a small cluster produces fewer files. A
root-only Community dev server gives nine with the base policy, and ten when the
token can also read ACL bodies (`acl-policy-review.json`).

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
- **Cluster health** — the same section [`cluster-audit`](cluster-audit.md) writes,
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
  allows it; see [Policy body review](token-and-policies.md#policy-body-review-acl-and-sentinel).
- **Sentinel policies** — the endpoint- and role-governing policies in force per
  namespace, with their enforcement levels, the endpoints an EGP covers and the
  size of each policy body. Vault Enterprise with the Governance & Policy module
  only; see below.
- **Security observations** — prompts for review, each tagged with a rule ID
  from the vault-ops skill's catalogue (`VT-MOUNT-001` and so on):
  - Mounts: deprecated or pending-removal plugins (`VT-MOUNT-001`), auth
    mounts enumerable by unauthenticated callers (`VT-AUTH-001`,
    `listing_visibility: unauth`), a `max_lease_ttl` that overrides the
    cluster ceiling (`VT-MOUNT-002`), non-replicated `local` mounts
    (`VT-MOUNT-003`), a `default_lease_ttl` above 768h (`VT-MOUNT-004`), more
    than 20 mounts of one type in a namespace (`VT-MOUNT-005`), and KV
    version 1 (`VT-MOUNT-006`).
  - Namespaces: no auth method beyond the built-in token backend
    (`VT-NS-001`), and leaf namespaces holding nothing but Vault's own
    built-in engines (`VT-NS-002`).
  - Sentinel, when the token can read bodies: policies that do not actually
    block anything (`VT-SNT-001` `advisory`, `VT-SNT-002` `soft-mandatory`,
    `VT-SNT-003` a wildcard EGP path, `VT-SNT-004` a body that always
    evaluates to true), same-named policies whose bodies differ across
    namespaces (`VT-SNT-005`), a hard-mandatory policy that always denies
    (`VT-SNT-006`), and an `http` import (`VT-SNT-007`).
  - Cluster: a cluster `default_lease_ttl` above 768h, an Enterprise license
    expiring within 90 days (Medium) or already past its soft expiry (High,
    with the hard termination date), and every cluster health check listed
    under [`cluster-audit`](cluster-audit.md).
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

## Sentinel policies

`sys/policies/egp` and `sys/policies/rgp` exist only on Vault Enterprise with the
Governance & Policy module. Everywhere else they return 404, which the audit
detects once and then stops probing — a Community run costs a single extra API
call and reports **Sentinel EGP/RGP endpoints are unavailable on this cluster**
rather than "zero policies found". The two readings mean very different things,
so the report never collapses them. Pass `--no-sentinel` to skip the collection
entirely; the section then says so explicitly.

Enforcement levels, EGP paths and every VT-SNT check need the policy *body*, so
they are assessed only when the token can read bodies (see
[Policy body review](token-and-policies.md#policy-body-review-acl-and-sentinel)). Without that,
the report lists the policy names and says they were not assessed. Policy source
is never written anywhere: `{cluster-name}-sentinel-policies-{YYYYMMDD}.json`
holds names, enforcement levels, paths, a body hash and import names, so
compare hashes between runs to spot an edited policy.

To exercise this against a local cluster, `task seed:sentinel` writes five no-op
policies from [`examples/sentinel/`](../examples/sentinel) — one per enforcement
level, a wildcard EGP path, an always-true rule, and a hard-mandatory control
that must produce no finding. Every one of them passes unconditionally, so
nothing is ever blocked. `task unseed:sentinel` removes them.
Both accept namespaces: `task seed:sentinel -- team-a/ team-b/`.
