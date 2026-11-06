"""Remediation catalogue: what each rule means, what to do, what to watch for.

Copied from the vault-ops skill's ``references/rules.json`` (the source of
truth; ``tests/test_rules_parity.py`` fails when this copy drifts). Commands are drafted
**for an operator to run** — vault-tools never runs them, and the report says so.
Templates are filled from a finding by ``fill_commands``:

- ``{nsflag}``: ``-namespace=<ns> `` for a child namespace, empty for root
- ``{path}`` / ``{name}``: the finding's object path (a mount, policy or entity)
- ``{cli}``: ``auth`` or ``secrets`` for a mount finding
- ``{kind}``: ``egp``/``rgp`` (Sentinel) or ``dr``/``performance`` (replication)
- ``{parent_flag}`` / ``{leaf}``: a namespace split into parent and last segment
- any evidence key, e.g. ``{entity_id}``, ``{secondary_id}``, ``{baseline}``

A ``<name>`` (e.g. ``<file>``, ``<prefix>``) and ``[paths=...]`` are left for the
operator to choose.

A rule with no ``commands`` has no catalogue command: the report describes the
change in words and tells the operator to confirm it in the Vault docs. Never
invent endpoints or flags here: change the skill first, then copy the entry.

Pure data and string formatting only.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from src.common.findings import SEVERITY_ORDER, Finding, format_ttl


@dataclass(frozen=True)
class Remediation:
    meaning: str
    commands: tuple[str, ...] = ()
    # Shown when there is no command, or before it: the change in words.
    action: str = ""
    watch_out: str = ""


CATALOGUE: dict[str, Remediation] = {
    "VT-AUD-001": Remediation(
        meaning="No audit device is enabled (`sys/audit` readable and empty).",
        action="Enable at least one audit device (file, syslog or socket) with the operator's log pipeline. The operator should confirm the device options in the Vault audit device docs.",
        watch_out="Not judged when `health.audit_devices` is `null` (DR secondary, or the token lacks `read`+`sudo` on `sys/audit`; check coverage). Enable a second device at the same time (see VT-AUD-002).",
    ),
    "VT-AUD-002": Remediation(
        meaning="Exactly one audit device is enabled (`evidence.device_path`, `evidence.device_type`). If Vault cannot write to it (disk full, socket down), Vault refuses every request.",
        action="Add a second device of a different type or target, so one failing sink doesn't block requests.",
        watch_out="Vault only blocks when every enabled device fails. Two devices on the same disk share the same failure.",
    ),
    "VT-AUD-003": Remediation(
        meaning="Audit device writes sensitive values in clear (`evidence.log_raw: true`) or token accessors unhashed (`evidence.hmac_accessor: false`).",
        commands=("vault audit disable {path}",),
        action="Options can't be changed in place: enable a replacement device with safe options first, then disable this one.",
        watch_out="Disable the old device only after the new one is writing, or the cluster can briefly lose its only device (VT-AUD-001/002). Existing log files still hold the clear values; treat them as sensitive and rotate per policy.",
    ),
    "VT-AUTH-001": Remediation(
        meaning="Auth mount is listed in the UI login page for unauthenticated callers.",
        commands=("vault auth tune {nsflag}-listing-visibility=hidden {path}",),
        watch_out="Harmless for public login methods (e.g. OIDC) that users must see; confirm intent before changing.",
    ),
    "VT-CLI-001": Remediation(
        meaning="Most clients in a namespace are token-only (`non_entity_clients` > 50%, at least 50 clients). Each token without an entity counts as its own client.",
        action="Move workloads from direct token creation (orphan tokens, token roles) to an auth method that maps to entities (AppRole, Kubernetes, JWT). Where token roles must stay, set `allowed_entity_aliases` on the role and create tokens with `entity_alias=<alias>`.",
        watch_out='`evidence.source == "current_month"` means the billing period was empty and the month in progress was judged instead.',
    ),
    "VT-CLI-002": Remediation(
        meaning="The latest month's clients exceed the average of up to 3 previous months by more than 50% (at least 100 clients). `evidence.month` may be the month in progress.",
        action="Compare `top_namespaces` between `usage` runs to find where the growth is. Look for CI jobs logging in per step, apps without token caching (Vault Agent), or a new per-run identity (see VT-CLI-003).",
        watch_out="Real onboarding also causes growth; confirm with the namespace owners. A partial current month understates the real growth.",
    ),
    "VT-CLI-003": Remediation(
        meaning="At least 90% of a mount's clients in the latest full month were new, and the mount already had clients the month before (at least 50 clients). Identities are created per login or run instead of reused.",
        action="For an auth mount, an operator reads its roles (`auth/<mount>/role/<role>`; the token mount uses `auth/token/roles/<role>`) and makes the identity stable: JWT/OIDC `user_claim` per workload (not per run), one AppRole per application (not per instance), Kubernetes `alias_name_source` set to the service account. For a secrets mount, find which workloads authenticate to use it.",
        watch_out="Uses billing-period months only: the first month of any window reports every client as new, so it is never judged.",
    ),
    "VT-CLI-004": Remediation(
        meaning="On Enterprise, more than 80% of clients are in the root namespace (at least 50 clients); with a child-namespace token, in the token's namespace, the top of what it can see.",
        action="Plan tenant namespaces and move teams' auth and secrets into them over time.",
        watch_out="Fine for single-team clusters; only a finding when tenants share root (or the token's namespace).",
    ),
    "VT-CLI-005": Remediation(
        meaning="`sys/internal/counters/config` reports the activity log disabled (`evidence.enabled`: `disable` or `default-disabled`), so Vault records no client activity and every client count reads zero.",
        commands=(
            "vault read sys/internal/counters/config",
            "vault write sys/internal/counters/config enabled=enable",
        ),
        action="Confirm the setting. Enabling it is a write an operator decides on (licence reporting, retention).",
        watch_out="Community dev servers keep it off by default. With it off, VT-CLI-001..004 and VT-ID-004 cannot be judged. Zero counts with the log on can also just mean the cluster started less than about 10 minutes ago.",
    ),
    "VT-HLTH-001": Remediation(
        meaning="Node sealed, or HA enabled with no active leader.",
        commands=("vault operator raft list-peers",),
        action="Sealed: unseal per runbook (auto-unseal: check KMS reachability; Shamir: `health.seal.progress` of `t` keys shows an unseal in progress). No leader: check the raft peers and the server logs.",
        watch_out="Run checks against each node; one sealed standby may be fine behind a load balancer.",
    ),
    "VT-HLTH-002": Remediation(
        meaning="DR or performance replication is enabled but its state is not healthy (`evidence.state`), or a peer is not `connected` (`evidence.disconnected_peers`).",
        commands=("vault read sys/replication/{kind}/status",),
        action="Read the status on both clusters; check the peer is up and unsealed, the cluster port (8201) path between them, and WAL gaps (`last_remote_wal` vs the primary's `last_wal`).",
        watch_out="Read-only investigation only. Never suggest `demote`/`promote`/`failover` without an incident runbook. A secondary that is restarting shows as disconnected briefly.",
    ),
    "VT-HLTH-003": Remediation(
        meaning="Vault version older than the supported window (`evidence.min_supported`).",
        action="Plan an upgrade path following HashiCorp's upgrade guides (step through required intermediate versions).",
        watch_out="`min_supported` is a constant in the script and may be stale.",
    ),
    "VT-HLTH-004": Remediation(
        meaning="Raft autopilot reports the cluster unhealthy, or a server unhealthy (`evidence.unhealthy_servers`, `evidence.failure_tolerance`).",
        commands=(
            "vault operator raft list-peers",
            "vault operator raft autopilot state",
        ),
        action="Check the unhealthy node is up and unsealed, its `last_contact` and trailing logs against `last_contact_threshold` and `max_trailing_logs`, and the cluster port (8201) path to the leader.",
        watch_out="Read-only investigation only; never suggest `remove-peer` without an incident runbook. A node that just joined or restarted is unhealthy until `server_stabilization_time` passes.",
    ),
    "VT-HLTH-005": Remediation(
        meaning="The queried node reports irrevocable leases (`evidence.irrevocable_leases`): Vault tried to revoke them and gave up, so the credentials may still be valid at the backend (database, cloud, PKI).",
        commands=(
            "vault read sys/leases/count type=irrevocable",
            "vault read sys/leases",
            "vault lease revoke -force -prefix <prefix>",
        ),
        action="Read-only investigation: count the irrevocable leases and list them with their error, then fix the backend cause (connection, deleted role, permissions). Only once the credentials are cleaned up at the backend can an operator drop the leases with `-force`.",
        watch_out="`-force` removes leases from Vault without revoking anything at the backend: only after manual cleanup, per runbook. From `health.metrics` (`sys/metrics`): the lease gauges exist on the active node only, so a standby is not judged.",
    ),
    "VT-HLTH-006": Remediation(
        meaning="The queried node reports more outstanding leases than the review threshold (`evidence.leases`, `evidence.threshold`, 100,000). Large lease counts slow unseal, leader election and lease expiration.",
        commands=(
            "vault read sys/leases/count type=all include_child_namespaces=true",
            "vault list sys/leases/lookup/<prefix>",
            "vault write sys/quotas/lease-count/<quota_name> path=<mount> max_leases=<n>",
        ),
        action="Find where the leases come from, then shorten TTLs on the busiest mounts (see VT-MOUNT-004), move high-volume short-lived clients to batch tokens, and cap growth with a lease count quota (Enterprise).",
        watch_out="The threshold is a heuristic; large clusters run more. Judged from the active node only. Revoking leases in bulk can overload backends: never suggest it as the fix.",
    ),
    "VT-ID-001": Remediation(
        meaning="Identity entity has no aliases: no login maps to it (orphaned, or created by hand and never linked).",
        commands=(
            "vault delete {nsflag}identity/entity/id/{entity_id}",
            "vault write {nsflag}identity/entity-alias name=<login> canonical_id={entity_id} mount_accessor=<accessor>",
        ),
        action="Confirm with the owner. If unused, delete the entity; if it should be used, link a login to it.",
        watch_out="Groups or policies on an orphan grant nothing until an alias exists. Check `group_count` before deleting.",
    ),
    "VT-ID-002": Remediation(
        meaning="Policies attached directly to an entity (`evidence.policies`).",
        commands=('vault write {nsflag}identity/entity/id/{entity_id} policies=""',),
        action="Move the policies to an identity group and add the entity as a member, then clear the entity's direct policies.",
        watch_out="Removing direct policies before the group grant exists cuts access; do it in that order.",
    ),
    "VT-ID-003": Remediation(
        meaning="Entity is disabled: tokens tied to it are refused.",
        action="If the identity is gone for good, delete the entity; if temporary, record why and when it should be re-enabled.",
        watch_out="Disabling is a common offboarding step. It isn't a problem by itself, only stale.",
    ),
    "VT-ID-004": Remediation(
        meaning="A namespace has at least 100 entities and more than 3x its active entity clients (`evidence.entities`, `evidence.active_entity_clients`). Active = the higher of the billing period and the current month.",
        commands=("vault delete {nsflag}identity/entity/id/<id>",),
        action="Run `entities --list` for this namespace to see which alias mounts the entities come from. Check those auth roles for a per-run identity (a JWT/OIDC `user_claim` that changes per job, one AppRole per instance) and fix it at the source. Then remove stale entities after owner review.",
        watch_out="Not judged when no activity is recorded (activity log disabled or new cluster). A recently created namespace or a long billing period can skew the ratio.",
    ),
    "VT-ID-005": Remediation(
        meaning="The same alias name is on several entities in one namespace through different auth mounts (`evidence.shared_alias_names`, `evidence.entities_affected`). Each entity is a separate billable client.",
        commands=("vault write {nsflag}identity/entity/merge from_entity_ids=<id> to_entity_id=<id>",),
        action="Merge the duplicates into one entity. Entity IDs come from `entities --list` for this namespace.",
        watch_out="The finding gives counts only; names appear only in `--list` output. Same name is not proof of the same person (e.g. `admin` on two mounts): confirm before merging. Merging moves aliases and can fail on conflicting aliases from one mount.",
    ),
    "VT-LEASE-001": Remediation(
        meaning="Cluster `default_lease_ttl` is above 768h (`evidence.default_lease_ttl_seconds`): every mount that inherits it issues leases this long.",
        action="Lower `default_lease_ttl` in the server configuration on every node, then reload or restart. The operator should confirm the exact steps in the Vault configuration docs.",
        watch_out="Not reported for a DR secondary or when `sys/config/state/sanitized` is unreadable. An unset default (Vault's built-in 768h) does not fire. Existing leases keep their TTL.",
    ),
    "VT-LIC-001": Remediation(
        meaning="License expires within 90 days (`evidence.days_remaining`).",
        commands=("vault write -f sys/config/reload/license",),
        action="Obtain a renewed license, update it on every node (`license_path`, `VAULT_LICENSE_PATH` or `VAULT_LICENSE`), then reload it (or restart).",
        watch_out="After expiry there is a grace period before termination; check `termination_time` in health output.",
    ),
    "VT-MOUNT-001": Remediation(
        meaning="Mount runs a plugin marked `deprecated`, `pending-removal` or `removed` (`evidence.deprecation_status`).",
        commands=("vault {cli} disable {nsflag}{path}",),
        action="Plan migration to the replacement engine: enable it alongside, migrate clients, then disable the old mount in a change window.",
        watch_out="`removed` plugins stop working on upgrade: check before any Vault upgrade.",
    ),
    "VT-MOUNT-002": Remediation(
        meaning="Mount `max_lease_ttl` exceeds the cluster ceiling (`evidence.baseline_source`: `cluster`, or `fallback` 768h).",
        commands=("vault {cli} tune {nsflag}-max-lease-ttl={baseline} {path}",),
        watch_out="Existing leases keep their TTL; lowering it affects new leases and renewals only. If `baseline_source=fallback`, the token could not read `sys/config/state/sanitized`: say so (with a child-namespace token that is by design).",
    ),
    "VT-MOUNT-003": Remediation(
        meaning="Mount is `local`: not replicated to performance secondaries or DR.",
        action="Usually intentional (per-cluster data). If not, the data must be recreated on a replicated mount: `local` cannot be changed after enable.",
        watch_out="Only meaningful when replication is in use (see health). On a performance secondary (`health.performance_secondary`) local mounts are that cluster's own data and expected.",
    ),
    "VT-MOUNT-004": Remediation(
        meaning="Mount explicitly sets `default_lease_ttl` above 768h (`evidence.default_lease_ttl_seconds`, `evidence.threshold_seconds`). Mounts that inherit the cluster default are not flagged.",
        commands=("vault {cli} tune {nsflag}-default-lease-ttl=<value> {path}",),
        watch_out="Existing leases keep their TTL; only new leases and renewals change. Usually fires with VT-MOUNT-002 (a default above 768h needs a raised max); fix both in one change. Clients can still ask for a TTL up to the max.",
    ),
    "VT-MOUNT-005": Remediation(
        meaning="More than 20 non-built-in mounts of one type in a namespace (`evidence.mounts_by_type`). One finding per namespace and mount kind (auth/secrets).",
        action="Consolidate into fewer mounts with per-path ACL policies (for KV, one mount with a path per app). Moving data means re-writing secrets into the new mount; the operator should plan it per engine.",
        watch_out="Some sprawl is deliberate (per-team PKI, per-tenant transit keys). Large mount tables slow namespace operations and replication.",
    ),
    "VT-MOUNT-006": Remediation(
        meaning="KV mount is version 1 (`options.version` missing or `1`): no versioning, soft delete or check-and-set.",
        commands=("vault kv enable-versioning {nsflag}{path}",),
        watch_out="The mount is unavailable while it upgrades, and v2 API paths gain `data/` and `metadata/`: update ACL policies and any client that calls the API directly first. Cannot be reverted.",
    ),
    "VT-NS-001": Remediation(
        meaning="Namespace has only the token auth backend.",
        commands=("vault auth enable {nsflag}oidc",),
        action="If users or apps should log in here, enable an auth method; otherwise accept it: child namespaces often rely on parent auth and entity groups.",
        watch_out="Normal for admin-boundary namespaces (e.g. tenant roots).",
    ),
    "VT-NS-002": Remediation(
        meaning="Leaf namespace with only built-in engines and no children: appears unused.",
        commands=("vault namespace delete {parent_flag}{leaf}",),
        action="Confirm with the owner; if unused, delete it in a change window.",
        watch_out="Deletion is irreversible and removes everything inside; never suggest it without owner confirmation.",
    ),
    "VT-POL-001": Remediation(
        meaning="A rule on a path that matches everything in the namespace (`*`, `+/*`, ...) grants `create`/`update`/`patch`/`delete` or `sudo` (`evidence.paths`): effectively admin there, including child namespaces under the glob.",
        commands=(
            "vault policy read {nsflag}{name}",
            "vault policy write {nsflag}{name} <file>",
        ),
        action="Review the policy. Replace the wildcard with the specific mounts and paths the holders need, then re-apply from source. Keep a separate break-glass admin policy with tight token TTLs if one is needed.",
        watch_out="Find who holds it first (groups, entities, auth roles); narrowing it can lock out operators. Read-only wildcards (`read`/`list` on `*`) are not flagged but still expose every secret.",
    ),
    "VT-POL-002": Remediation(
        meaning="Write access to an area that controls access (`evidence.areas`, `evidence.paths`): ACL policies, auth methods, secrets engines, namespaces, token creation or token roles, identity entities, aliases or groups. A holder can grant itself or others more access.",
        commands=(
            "vault policy read {nsflag}{name}",
            "vault policy write {nsflag}{name} <file>",
        ),
        action="Review the policy. Limit the rule to the exact paths needed (e.g. one token role instead of `auth/token/create`, specific policy names instead of `sys/policies/acl/*`) and use `allowed_parameters` to restrict values such as `policies`. Re-apply from source.",
        watch_out="Some of these are the policy's purpose (a policy-admin or IAM role); then confirm the holders are few and audited rather than removing it. `auth/token/create` without parameter limits can mint tokens with any policy the caller holds.",
    ),
    "VT-POL-003": Remediation(
        meaning="The policy grants `sudo` (`evidence.sudo_paths`), which unlocks root-protected endpoints on those paths.",
        commands=(
            "vault policy read {nsflag}{name}",
            "vault policy write {nsflag}{name} <file>",
        ),
        action="Review the policy. Remove `sudo` unless the path is root-protected and the holder needs it; re-apply from source.",
        watch_out="`sudo` on exact read-only list paths (e.g. `vault-ops-readonly` on `sys/audit` and `sys/storage/raft/snapshot-auto/config`) is expected and low risk. `sudo` on a wildcard is also VT-POL-001.",
    ),
    "VT-POL-004": Remediation(
        meaning="A policy name exists in several namespaces with different bodies (`evidence.variants`, `evidence.outliers`, `evidence.examples`): copies have drifted.",
        commands=(
            "vault policy read -namespace=<ns> {name}",
            "vault policy write -namespace=<ns> {name} <file>",
        ),
        action="Compare an outlier (`evidence.examples`) with a typical copy, reading it in each namespace. Decide which is right, update the source and re-apply it to every namespace.",
        watch_out="Differences can be deliberate (per-environment paths). The finding gives namespaces only; bodies are not compared in the output.",
    ),
    "VT-POL-005": Remediation(
        meaning="A policy body could not be parsed, so it was not assessed.",
        commands=("vault policy read {nsflag}{name}",),
        action="Review it by hand.",
        watch_out="Usually unusual HCL (heredocs, odd quoting). Vault accepted it, so it is valid; the skill's parser is the limit.",
    ),
    "VT-REPL-001": Remediation(
        meaning="A connected replication peer is lagging: the primary's canary is older than 60s (`evidence.canary_age_ms`), or its last heartbeat is older than 60s (`evidence.heartbeat_age_seconds`).",
        commands=("vault read sys/replication/{kind}/status",),
        action="Read-only investigation: read the status on both clusters; compare the primary's `last_wal` with the secondary's `last_remote_wal`, and check cluster port (8201) latency, bandwidth and load on both sides.",
        watch_out="Bulk writes (a big seed or migration) lag briefly and catch up. A disconnected peer is VT-HLTH-002, not lag. Never suggest `demote`/`promote`/`failover`.",
    ),
    "VT-REPL-002": Remediation(
        meaning="The primary lists a secondary with no heartbeat since the primary started (`disconnected`, `evidence.secondary_id`). Either it never connected (an activation token that was never used, or a secondary torn down without `revoke-secondary`) or it has been down since the primary last restarted: the primary keeps heartbeats in memory, so the two look the same. VT-HLTH-002 also reports it as disconnected.",
        commands=(
            "vault read sys/replication/{kind}/status",
            "vault write sys/replication/{kind}/primary/revoke-secondary id={secondary_id}",
        ),
        action="First check the secondary itself (read the status on it, if it exists). Only if the owner confirms it should not exist does an operator revoke it on the primary.",
        watch_out="Never revoke on this finding alone: a production secondary that is down after a primary restart looks identical. Don't revoke one that is still being built.",
    ),
    "VT-REPL-003": Remediation(
        meaning="Clock skew between replication peers is above 2000 ms (`evidence.clock_skew_ms`).",
        action="Check NTP/chrony on every node of both clusters.",
        watch_out="Skew affects token and lease expiry and replication timing. Vault reports the skew from the peer it measured: check both sides.",
    ),
    "VT-REPL-004": Remediation(
        meaning="Replication reports `corrupted_merkle_tree: true`: the merkle index of replicated data is damaged, so the clusters can drift apart.",
        commands=(
            "vault read sys/replication/{kind}/status",
            "vault write -f sys/replication/reindex",
        ),
        action="Read-only investigation first: read the status on both clusters and the server logs. The usual fix is a reindex by an operator, per runbook, in a change window.",
        watch_out="A reindex is heavy on large clusters. Never suggest `demote`/`promote`/`failover` as the fix.",
    ),
    "VT-REPL-005": Remediation(
        meaning="A performance paths filter is set for a secondary (`evidence.mode` allow/deny, `evidence.paths`, `evidence.dynamic_filtered_mounts`): those namespaces and mounts don't replicate to it.",
        commands=("vault read sys/replication/performance/primary/paths-filter/{secondary_id}",),
        action="Usually intentional (data residency). Confirm the filter matches the intended data placement.",
        watch_out="Explains inventory differences between the primary and that secondary (fewer namespaces or mounts there): not a fault. Only judged on a performance primary whose token can read the filters.",
    ),
    "VT-SNAP-001": Remediation(
        meaning="Enterprise cluster on integrated storage has no automated snapshot config.",
        action="Create an automated snapshot config (`sys/storage/raft/snapshot-auto/config/<config_name>`) writing to storage off the cluster nodes (object storage). The operator should confirm the storage options in the Vault docs.",
        watch_out="Judged only on Enterprise with raft readable; CE and other storage backends are skipped. Manual or externally scheduled `vault operator raft snapshot save` jobs aren't visible to this check, so ask before assuming there are no backups.",
    ),
    "VT-SNAP-002": Remediation(
        meaning="Automated snapshot is failing (`evidence.consecutive_errors` > 0) or overdue: no run for more than max(interval, 25h) past `evidence.next_snapshot_start` (`evidence.overdue_seconds`).",
        commands=("vault read sys/storage/raft/snapshot-auto/status/{name}",),
        action="Read-only investigation: read the status (the error text is deliberately not in the findings), then check storage target reachability, credentials and free space.",
        watch_out="The status's `next_snapshot_start` stays stale after a config change until the next run, so an interval changed to longer than a day can fire falsely until then. A config that has never run isn't judged.",
    ),
    "VT-SNAP-003": Remediation(
        meaning="Automated snapshots are written to the node's local disk (`file` URL scheme).",
        action="Move the config to object storage, or confirm the local path is copied off the node.",
        watch_out="A lost or rebuilt node takes its local snapshots with it. Fine for dev and test clusters. Judged from the last run's URL, so a config that has never run isn't judged.",
    ),
    "VT-SNT-001": Remediation(
        meaning="Sentinel policy is `advisory`: logs, never blocks.",
        commands=("vault write {nsflag}sys/policies/{kind}/{name} enforcement_level=soft-mandatory policy=@<file> [paths=...]",),
        action="Raise the enforcement level after testing.",
        watch_out="Raising enforcement can block traffic; test in a lower environment first.",
    ),
    "VT-SNT-002": Remediation(
        meaning="Sentinel policy is `soft-mandatory`: a sudo token can override it.",
        action="Consider `hard-mandatory` if overrides are not part of the operating model.",
        watch_out="Raising enforcement can block traffic; test in a lower environment first.",
    ),
    "VT-SNT-003": Remediation(
        meaning="EGP path is `*`: applies to every request in the namespace.",
        action="Narrow `paths` to the endpoints the policy governs.",
        watch_out="A hard-mandatory wildcard EGP that can evaluate false locks out everyone, including admins.",
    ),
    "VT-SNT-004": Remediation(
        meaning="Sentinel policy body always evaluates true (`main = rule { true }`).",
        commands=("vault delete {nsflag}sys/policies/{kind}/{name}",),
        action="Replace it with a real rule or delete the policy.",
        watch_out="It looks like a control in policy lists but enforces nothing.",
    ),
    "VT-SNT-005": Remediation(
        meaning="An EGP or RGP name exists in several namespaces with different bodies (`evidence.variants`, `evidence.outliers`, `evidence.examples`): copies have drifted.",
        commands=(
            "vault read -namespace=<ns> sys/policies/{kind}/{name}",
            "vault write -namespace=<ns> sys/policies/{kind}/{name} enforcement_level=<level> policy=@<file> [paths=...]",
        ),
        action="Compare an outlier (`evidence.examples`) with a typical copy, reading it in each namespace. Decide which is right, update the source and re-apply it to every namespace.",
        watch_out="Differences can be deliberate (a stricter copy in a regulated namespace). Re-applying a body with a stricter rule can start blocking requests.",
    ),
    "VT-SNT-006": Remediation(
        meaning="A `hard-mandatory` policy whose `main` is always false (`evidence.paths` for an EGP): it denies every request it applies to, and nothing can override it.",
        commands=(
            "vault read {nsflag}sys/policies/{kind}/{name}",
            "vault write {nsflag}sys/policies/{kind}/{name} enforcement_level=advisory policy=@<file> [paths=...]",
            "vault delete {nsflag}sys/policies/{kind}/{name}",
        ),
        action="Review the policy. If callers are locked out, an operator whose own requests the policy doesn't cover (or a root token) relaxes it to `advisory` first, then fixes or deletes it.",
        watch_out="An EGP applies to root tokens too, so on wildcard paths it can block the fix itself; check `paths` before any change. The rule only spots a literal `false` main, not one that is false in practice.",
    ),
    "VT-SNT-007": Remediation(
        meaning="The policy imports `http` (`evidence.imports`): each request it applies to can wait on an outbound call, so that endpoint's availability and latency gate Vault requests.",
        commands=("vault read {nsflag}sys/policies/{kind}/{name}",),
        action="Review the policy. Prefer data Vault already has (request, identity, time); if the call is needed, narrow EGP `paths` and confirm the endpoint's timeout and failure behaviour.",
        watch_out="The import alone is flagged, even when `main` never calls it; a failing call can deny requests under `hard-mandatory`.",
    ),
}

# The skill's `rank_order` (rules.json), earlier is more urgent: cluster-wide
# availability, lifecycle, audit trail and recoverability; access that grants
# admin or escalation; narrower risks; hygiene with a cost; then info rules.
RANK_ORDER = (
    "VT-REPL-004",
    "VT-HLTH-001",
    "VT-HLTH-002",
    "VT-LIC-001",
    "VT-AUD-001",
    "VT-SNAP-001",
    "VT-SNAP-002",
    "VT-POL-001",
    "VT-POL-002",
    "VT-SNT-006",
    "VT-HLTH-004",
    "VT-REPL-001",
    "VT-REPL-003",
    "VT-HLTH-006",
    "VT-POL-003",
    "VT-MOUNT-001",
    "VT-SNT-004",
    "VT-SNT-001",
    "VT-SNT-005",
    "VT-AUD-003",
    "VT-AUD-002",
    "VT-AUTH-001",
    "VT-MOUNT-002",
    "VT-MOUNT-004",
    "VT-LEASE-001",
    "VT-HLTH-005",
    "VT-POL-004",
    "VT-ID-004",
    "VT-ID-005",
    "VT-CLI-001",
    "VT-CLI-002",
    "VT-CLI-003",
    "VT-CLI-005",
    "VT-ID-001",
    "VT-REPL-002",
    "VT-HLTH-003",
    "VT-MOUNT-003",
    "VT-MOUNT-005",
    "VT-MOUNT-006",
    "VT-NS-001",
    "VT-NS-002",
    "VT-SNT-002",
    "VT-SNT-003",
    "VT-SNT-007",
    "VT-REPL-005",
    "VT-SNAP-003",
    "VT-ID-002",
    "VT-ID-003",
    "VT-CLI-004",
    "VT-POL-005",
)
_RANK = {rule_id: i for i, rule_id in enumerate(RANK_ORDER)}


def _namespace_flag(namespace: str) -> str:
    ns = namespace.strip("/")
    return f"-namespace={ns}/ " if ns else ""


def _placeholders(f: Finding) -> dict[str, Any]:
    ns = f.namespace.strip("/")
    parent, _, leaf = ns.rpartition("/")
    values: dict[str, Any] = {k: v for k, v in f.evidence.items() if isinstance(v, str | int)}
    values.update(
        nsflag=_namespace_flag(ns),
        path=f.object_path or "<path>",
        name=f.object_path or "<name>",
        cli="auth" if f.object_kind == "auth_mount" else "secrets",
        kind=f.object_type or "<kind>",
        parent_flag=_namespace_flag(parent),
        leaf=leaf or "<namespace>",
    )
    if isinstance(f.evidence.get("baseline_seconds"), int):
        values["baseline"] = format_ttl(f.evidence["baseline_seconds"])
    values.setdefault("baseline", "<baseline>")
    values.setdefault("entity_id", f.object_path or "<entity_id>")
    values.setdefault("secondary_id", (f.object_path or "").split(":", 1)[-1] or "<secondary_id>")
    return values


class _Missing(dict):
    def __missing__(self, key: str) -> str:
        return f"<{key}>"


def fill_commands(f: Finding) -> list[str]:
    """The catalogue commands for one finding, placeholders filled from it."""
    remediation = CATALOGUE.get(f.rule_id)
    if remediation is None:
        return []
    values = _Missing(_placeholders(f))
    return [template.format_map(values) for template in remediation.commands]


def rank_key(rule_id: str, severity: str, count: int) -> tuple[int, int, int, int]:
    """High first; then the catalogue order; then severity; then the larger group."""
    return (0 if severity == "High" else 1, _RANK.get(rule_id, len(RANK_ORDER)), SEVERITY_ORDER.index(severity), -count)
