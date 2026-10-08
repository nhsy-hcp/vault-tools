# Audit token and policies

## Create an audit token

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
instead. It is git-ignored, and [`.env.example`](../.env.example) is the template.
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

- `-no-default-policy` works because `policies/audit-policy.hcl` grants the
  `auth/token/lookup-self` check itself. `-orphan` keeps the token from
  disappearing if the admin's own token is revoked first.
- An hour is ample: a full audit of a 130-namespace cluster takes seconds.
  Revoke the token when you're done (`vault token revoke <token>`), and drop the
  add-ons if you only needed them for one policy review.
- For a self-signed dev server set `VAULT_SKIP_VERIFY=true`.
- Without an add-on the run still succeeds. The report lists those policies by
  name and says, under **Not covered**, which add-on to attach. See
  [Vault token permissions](#vault-token-permissions) for what each rule grants
  and why.

## Vault token permissions

The tool is read-only and never writes to Vault. Rather than running it with a
root token, use the supplied policies in [`policies/`](../policies), which grant
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
  [`policies/audit-policy-acl-reader.hcl`](../policies/audit-policy-acl-reader.hcl): attach it to
  the token to assess permissions. Removing the list rule drops that report
  section and records the denials; it does not fail the run.
- **The `sys/policies/egp` and `sys/policies/rgp` rules list names only.**
  Reading Sentinel bodies needs the
  [`policies/audit-policy-sentinel-reader.hcl`](../policies/audit-policy-sentinel-reader.hcl)
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

## Policy body review (ACL and Sentinel)

**The token is the source of truth.** There is no flag to turn the review on.
vault-tools tries to read ACL and Sentinel policy bodies, and the token's
policies decide what it gets:

| Token carries | ACL permissions (VT-POL) | Sentinel (VT-SNT) |
| --- | --- | --- |
| `policies/audit-policy.hcl` only | Names only | Names only |
| plus [`policies/audit-policy-acl-reader.hcl`](../policies/audit-policy-acl-reader.hcl) | Assessed | Names only |
| plus [`policies/audit-policy-sentinel-reader.hcl`](../policies/audit-policy-sentinel-reader.hcl) | Names only | Assessed |
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
