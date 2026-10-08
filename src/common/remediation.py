"""Remediation catalogue: what each rule means, what to do, what to watch for.

Ported from the vault-ops skill's ``references/rules.md``. Commands are drafted
**for an operator to run** — vault-tools never runs them, and the report says so.
Templates are filled from a finding by ``fill_commands``:

- ``{nsflag}``: ``-namespace=<ns> `` for a child namespace, empty for root
- ``{path}`` / ``{name}``: the finding's object path (a mount, policy or entity)
- ``{cli}``: ``auth`` or ``secrets`` for a mount finding
- ``{kind}``: ``egp``/``rgp`` (Sentinel) or ``dr``/``performance`` (replication)
- ``{paths_arg}``: `` paths=<paths>`` for an EGP, empty otherwise
- ``{parent_flag}`` / ``{leaf}``: a namespace split into parent and last segment
- any evidence key, e.g. ``{entity_id}``, ``{secondary_id}``, ``{baseline}``

A rule with no ``commands`` has no catalogue command: the report describes the
change in words and tells the operator to confirm it in the Vault docs. Never
invent endpoints or flags here.

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
    "VT-MOUNT-001": Remediation(
        "The mount runs a plugin marked `deprecated`, `pending-removal` or `removed`.",
        ("vault {cli} disable {nsflag}{path}",),
        "Enable the replacement engine alongside, migrate clients, then disable the old mount in a change window.",
        "`removed` plugins stop working on upgrade — check before any Vault upgrade.",
    ),
    "VT-AUTH-001": Remediation(
        "The auth mount is listed on the UI login page for callers who are not logged in.",
        ("vault auth tune {nsflag}-listing-visibility=hidden {path}",),
        watch_out="Harmless for public login methods (e.g. OIDC) that users must see; confirm intent before changing.",
    ),
    "VT-MOUNT-002": Remediation(
        "The mount's `max_lease_ttl` exceeds the cluster ceiling.",
        ("vault {cli} tune {nsflag}-max-lease-ttl={baseline} {path}",),
        watch_out="Existing leases keep their TTL; only new leases and renewals change. A `fallback` baseline means `sys/config/state/sanitized` was unreadable.",
    ),
    "VT-MOUNT-003": Remediation(
        "The mount is `local`: it is not replicated to performance secondaries or DR.",
        action="Usually intentional (per-cluster data). If not, the data must be recreated on a replicated mount — `local` cannot be changed after enable.",
        watch_out="Only meaningful when replication is in use.",
    ),
    "VT-MOUNT-004": Remediation(
        "The mount explicitly sets `default_lease_ttl` above 768h, so new leases get it by default.",
        ("vault {cli} tune {nsflag}-default-lease-ttl=<value> {path}",),
        watch_out="Usually fires with VT-MOUNT-002; fix both in one change. Existing leases keep their TTL.",
    ),
    "VT-MOUNT-005": Remediation(
        "More than 20 non-built-in mounts of one type in a namespace.",
        action="Consolidate into fewer mounts with per-path ACL policies (for KV, one mount with a path per app). Moving data means re-writing secrets; plan it per engine.",
        watch_out="Some sprawl is deliberate (per-team PKI, per-tenant transit keys). Large mount tables slow namespace operations and replication.",
    ),
    "VT-MOUNT-006": Remediation(
        "KV version 1: no secret versioning, soft delete or check-and-set.",
        ("vault kv enable-versioning {nsflag}{path}",),
        watch_out="The mount is unavailable while it upgrades and API paths gain `data/` and `metadata/`: update ACL policies and direct API clients first. Cannot be reverted.",
    ),
    "VT-NS-001": Remediation(
        "The namespace has only the token auth backend.",
        ("vault auth enable {nsflag}oidc",),
        "If users or apps should log in here, enable an auth method; otherwise accept it.",
        "Normal for admin-boundary namespaces (tenant roots) where logins happen lower down.",
    ),
    "VT-NS-002": Remediation(
        "A leaf namespace with only built-in engines and no children — it appears unused.",
        ("vault namespace delete {parent_flag}{leaf}",),
        "Confirm with the owner first; delete only if it is truly unused, in a change window.",
        "Deletion is irreversible and removes everything inside.",
    ),
    "VT-SNT-001": Remediation(
        "The Sentinel policy is `advisory`: it logs violations but never blocks.",
        ("vault write {nsflag}sys/policies/{kind}/{name} enforcement_level=soft-mandatory policy=@<file>{paths_arg}",),
        "Raise the enforcement level after testing.",
        "Raising enforcement can block traffic; test in a lower environment first.",
    ),
    "VT-SNT-002": Remediation(
        "The Sentinel policy is `soft-mandatory`: a sudo token can override it.",
        action="Consider `hard-mandatory` if overrides are not part of the operating model.",
        watch_out="Raising enforcement can block traffic.",
    ),
    "VT-SNT-003": Remediation(
        "The EGP path is `*`: it applies to every request in the namespace.",
        action="Narrow `paths` to the endpoints the policy governs.",
        watch_out="A hard-mandatory wildcard EGP that can evaluate false locks out everyone, admins included.",
    ),
    "VT-SNT-004": Remediation(
        "The Sentinel policy body always evaluates true: it looks like a control but enforces nothing.",
        ("vault delete {nsflag}sys/policies/{kind}/{name}",),
        "Replace it with a real rule, or delete it.",
    ),
    "VT-SNT-005": Remediation(
        "A same-named EGP/RGP exists in several namespaces with different bodies: copies have drifted.",
        ("vault read -namespace=<ns> sys/policies/{kind}/{name}",),
        "Compare an outlier with a typical copy, decide which is right, update the source and re-apply it everywhere.",
        "Differences can be deliberate (a stricter copy in a regulated namespace).",
    ),
    "VT-SNT-006": Remediation(
        "A `hard-mandatory` policy whose `main` is always false: it denies every request it applies to, and nothing can override it.",
        ("vault read {nsflag}sys/policies/{kind}/{name}",),
        "If callers are locked out, an operator whose own requests it doesn't cover (or a root token) sets it to `advisory`, then fixes or deletes it.",
        "An EGP applies to root tokens too, so on wildcard paths it can block the fix itself; check `paths` first.",
    ),
    "VT-SNT-007": Remediation(
        "The policy imports `http`: each request it applies to can wait on an outbound call.",
        ("vault read {nsflag}sys/policies/{kind}/{name}",),
        "Prefer data Vault already has; if the call is needed, narrow EGP `paths` and confirm the endpoint's timeout and failure behaviour.",
    ),
    "VT-LIC-001": Remediation(
        "The licence expires within 90 days (or has expired).",
        ("vault license reload",),
        "Obtain the renewed licence, put it on every node (`license_path` / `VAULT_LICENSE_PATH` / `VAULT_LICENSE`), then reload on each node.",
        "After expiry there is a grace period until `termination_time`; when the two are the same date there is none.",
    ),
    "VT-HLTH-001": Remediation(
        "The node is sealed, or HA is enabled with no active leader.",
        ("vault operator raft list-peers",),
        "Sealed: unseal per runbook (auto-unseal: check KMS reachability). No leader: check the raft peers and server logs.",
        "One sealed standby behind a load balancer may be fine; check every node.",
    ),
    "VT-HLTH-002": Remediation(
        "Replication is enabled but unhealthy, or a peer is disconnected.",
        ("vault read sys/replication/{kind}/status",),
        "Run it on both clusters; check the peer is up and unsealed, the cluster port (8201) path, and WAL gaps.",
        "Read-only investigation; never `demote`/`promote`/`failover` without an incident runbook.",
    ),
    "VT-HLTH-003": Remediation(
        "Vault is older than the supported window.",
        action="Plan an upgrade path with HashiCorp's upgrade guides, stepping through required intermediate versions.",
        watch_out="The minimum version is a constant in vault-tools and may be stale.",
    ),
    "VT-HLTH-004": Remediation(
        "Raft autopilot reports the cluster or a server unhealthy.",
        ("vault operator raft list-peers", "vault operator raft autopilot state"),
        "Check the unhealthy node is up and unsealed, its last contact and trailing logs, and the cluster port path to the leader.",
        "A node that just joined is unhealthy until `server_stabilization_time` passes. Never `remove-peer` without a runbook.",
    ),
    "VT-HLTH-005": Remediation(
        "The node reports irrevocable leases: the credentials may still be valid at the backend.",
        ("vault read sys/leases/count type=irrevocable", "vault read sys/leases"),
        "Fix the backend cause (connection, deleted role, permissions); only after cleaning up at the backend drop the leases with `vault lease revoke -force -prefix <prefix>`.",
        "`-force` removes leases from Vault without revoking anything at the backend.",
    ),
    "VT-HLTH-006": Remediation(
        "The node reports more outstanding leases than the review threshold.",
        ("vault read sys/leases/count type=all include_child_namespaces=true",),
        "Find the busiest mounts, shorten their TTLs, move high-volume short-lived clients to batch tokens, and cap growth with a lease count quota (Enterprise).",
        "The threshold is a heuristic. Revoking leases in bulk can overload backends.",
    ),
    "VT-REPL-001": Remediation(
        "A connected replication peer is lagging.",
        ("vault read sys/replication/{kind}/status",),
        "Compare the primary's `last_wal` with the secondary's `last_remote_wal`; check cluster port latency and load.",
        "Bulk writes lag briefly and catch up. Never `demote`/`promote`/`failover`.",
    ),
    "VT-REPL-002": Remediation(
        "The primary lists a secondary with no heartbeat since the primary started: never connected, or down since the restart.",
        ("vault read sys/replication/{kind}/status", "vault write sys/replication/{kind}/primary/revoke-secondary id={secondary_id}"),
        "First check the secondary itself. Revoke on the primary only once the owner confirms it should not exist.",
        "Never revoke on this finding alone: a production secondary that is down after a primary restart looks identical.",
    ),
    "VT-REPL-003": Remediation(
        "Clock skew between replication peers is above 2 seconds.",
        action="Check NTP/chrony on every node of both clusters.",
        watch_out="Skew affects token and lease expiry and replication timing.",
    ),
    "VT-REPL-004": Remediation(
        "Replication reports a corrupted merkle tree: the clusters can drift apart.",
        ("vault read sys/replication/{kind}/status", "vault write -f sys/replication/reindex"),
        "Investigate on both clusters first; the usual fix is a reindex, per runbook, in a change window.",
        "A reindex is heavy on large clusters. Never `demote`/`promote`/`failover` as the fix.",
    ),
    "VT-REPL-005": Remediation(
        "A performance paths filter is set for a secondary: those namespaces/mounts don't replicate to it.",
        ("vault read sys/replication/performance/primary/paths-filter/{secondary_id}",),
        "Usually intentional (data residency); confirm it matches the intended placement.",
    ),
    "VT-LEASE-001": Remediation(
        "The cluster `default_lease_ttl` is above 768h, so every inheriting mount issues leases this long.",
        action="Lower `default_lease_ttl` in the server configuration on every node, then reload or restart. Confirm the exact steps in the Vault configuration docs.",
        watch_out="Existing leases keep their TTL.",
    ),
    "VT-AUD-001": Remediation(
        "No audit device is enabled: requests leave no audit trail.",
        action="Enable at least one audit device (file, syslog or socket) with the log pipeline, and a second at the same time. Confirm the options in the Vault audit device docs.",
    ),
    "VT-AUD-002": Remediation(
        "Exactly one audit device is enabled: if Vault cannot write to it, Vault refuses every request.",
        action="Add a second device of a different type or target.",
        watch_out="Vault only blocks when every device fails; two devices on the same disk share the same failure.",
    ),
    "VT-AUD-003": Remediation(
        "An audit device writes sensitive values in clear (`log_raw`) or token accessors unhashed (`hmac_accessor=false`).",
        ("vault audit disable {path}",),
        "Options can't be changed in place: enable a replacement device with safe options, confirm it's writing, then disable the old one.",
        "Existing log output still holds the clear values; treat it as sensitive.",
    ),
    "VT-SNAP-001": Remediation(
        "An Enterprise cluster on integrated storage has no automated snapshot config.",
        action="Create an automated snapshot config writing to storage off the cluster nodes (object storage). Confirm the storage options in the Vault docs.",
        watch_out="Externally scheduled `vault operator raft snapshot save` jobs aren't visible here; ask before assuming there are no backups.",
    ),
    "VT-SNAP-002": Remediation(
        "An automated snapshot is failing or overdue.",
        ("vault read sys/storage/raft/snapshot-auto/status/{name}",),
        "Check storage target reachability, credentials and free space.",
        "A config change leaves `next_snapshot_start` stale until the next run.",
    ),
    "VT-SNAP-003": Remediation(
        "Automated snapshots are written to the node's local disk.",
        action="Move the config to object storage, or confirm the local path is copied off the node.",
        watch_out="A lost or rebuilt node takes its local snapshots with it.",
    ),
    "VT-ID-001": Remediation(
        "The entity has no aliases: no login maps to it.",
        ("vault delete {nsflag}identity/entity/id/{entity_id}",),
        "Confirm with the owner; delete if unused, or link a login with an entity alias.",
        "Check group membership before deleting.",
    ),
    "VT-ID-002": Remediation(
        "Policies are attached directly to the entity.",
        ('vault write {nsflag}identity/entity/id/{entity_id} policies=""',),
        "Move the policies to an identity group, add the entity as a member, then clear the direct policies.",
        "Removing direct policies before the group grant exists cuts access.",
    ),
    "VT-ID-003": Remediation(
        "The entity is disabled: tokens tied to it are refused.",
        action="If the identity is gone for good, delete it; if temporary, record why and when it should be re-enabled.",
    ),
    "VT-ID-004": Remediation(
        "Far more entities than active entity clients: identities are created per login or run, or never cleaned up.",
        ("python main.py identity-audit --list",),
        "See which alias mounts the entities come from, fix per-run identities at the source (JWT `user_claim`, one AppRole per app), then remove stale entities after owner review.",
        "A new namespace or a long billing period can skew the ratio.",
    ),
    "VT-ID-005": Remediation(
        "The same alias name is on several entities through different auth mounts; each is a separate client.",
        ("vault write {nsflag}identity/entity/merge from_entity_ids=<id> to_entity_id=<id>",),
        "Merge the duplicates; get the IDs from `identity-audit --list`.",
        "The same name is not proof of the same person; confirm before merging.",
    ),
    "VT-CLI-001": Remediation(
        "Most clients in the namespace are token-only: each token without an entity is its own client.",
        action="Move workloads from direct token creation to an auth method that maps to entities (AppRole, Kubernetes, JWT), or set `allowed_entity_aliases` on token roles.",
    ),
    "VT-CLI-002": Remediation(
        "The latest month's clients are well above the recent average.",
        action="Compare namespaces between runs to find the growth; look for CI jobs logging in per step, apps without token caching, or per-run identities.",
        watch_out="Real onboarding also causes growth; confirm with the owners.",
    ),
    "VT-CLI-003": Remediation(
        "Most of a mount's clients were new this month: identities are created per run instead of reused.",
        action="Make the identity stable: JWT `user_claim` per workload, one AppRole per application, Kubernetes `alias_name_source` set to the service account.",
    ),
    "VT-CLI-004": Remediation(
        "Most clients are in the root namespace.",
        action="Plan tenant namespaces and move teams' auth and secrets into them over time.",
        watch_out="Fine for single-team clusters.",
    ),
    "VT-CLI-005": Remediation(
        "The activity log is disabled: client counts read zero because nothing is recorded.",
        ("vault write sys/internal/counters/config enabled=enable",),
        "Enabling it is a decision for an operator (licence reporting, retention).",
        "With it off, the client checks and VT-ID-004 cannot be judged.",
    ),
    "VT-POL-001": Remediation(
        "A rule on a path matching everything grants write or `sudo`: effectively admin in the namespace.",
        ("vault policy read {nsflag}{name}",),
        "Replace the wildcard with the specific mounts and paths the holders need, then re-apply from source with `vault policy write`.",
        "Find who holds it first; narrowing it can lock out operators.",
    ),
    "VT-POL-002": Remediation(
        "Write access to something that controls access: a holder can grant itself or others more access.",
        ("vault policy read {nsflag}{name}",),
        "Limit the rule to the exact paths needed and use `allowed_parameters` to restrict values such as `policies`, then re-apply from source.",
        "Some of these are the policy's purpose (a policy admin); then confirm the holders are few and audited.",
    ),
    "VT-POL-003": Remediation(
        "The policy grants `sudo`, unlocking root-protected endpoints on those paths.",
        ("vault policy read {nsflag}{name}",),
        "Remove `sudo` unless the path is root-protected and the holder needs it.",
        "`sudo` on exact read-only paths (vault-tools' own `policies/audit-policy.hcl`) is expected and low risk.",
    ),
    "VT-POL-004": Remediation(
        "A policy name exists in several namespaces with different bodies: copies have drifted.",
        ("vault policy read -namespace=<ns> {name}",),
        "Compare an outlier with a typical copy, decide which is right, update the source and re-apply everywhere.",
        "Differences can be deliberate (per-environment paths).",
    ),
    "VT-POL-005": Remediation(
        "A policy body could not be parsed, so it was not assessed.",
        ("vault policy read {nsflag}{name}",),
        "Review it by hand.",
    ),
}

# The skill's ranking guidance, as an ordered list: earlier is more urgent.
# Cluster-wide availability, lifecycle, audit trail and recoverability come
# first, licence expiry leading as the one time-bound item; then access that
# grants admin or lets holders raise their own; then narrower risks; then
# hygiene with a cost. Anything unlisted (the info rules) ranks last.
RANK_ORDER = (
    # cluster-wide
    "VT-LIC-001",
    "VT-HLTH-001",
    "VT-REPL-004",
    "VT-HLTH-002",
    "VT-HLTH-004",
    "VT-AUD-001",
    "VT-SNAP-002",
    "VT-SNAP-001",
    "VT-REPL-001",
    "VT-REPL-003",
    # access that grants admin or escalation, and Sentinel lockout
    "VT-POL-001",
    "VT-POL-002",
    "VT-SNT-006",
    # narrower risks
    "VT-HLTH-006",
    "VT-AUD-003",
    "VT-AUD-002",
    "VT-POL-003",
    "VT-MOUNT-001",
    "VT-SNT-004",
    "VT-SNT-001",
    "VT-SNT-005",
    # hygiene with a cost
    "VT-AUTH-001",
    "VT-MOUNT-002",
    "VT-MOUNT-004",
    "VT-LEASE-001",
    "VT-HLTH-005",
    "VT-POL-004",
    "VT-REPL-002",
    "VT-ID-001",
    "VT-ID-004",
    "VT-ID-005",
    "VT-CLI-005",
    "VT-CLI-001",
    "VT-CLI-002",
    "VT-CLI-003",
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
        paths_arg=" paths=<paths>" if f.object_type == "egp" else "",
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
