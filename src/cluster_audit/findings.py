"""Cluster-level finding checks: health, replication, raft, audit, snapshots, metrics, license, lease.

Pure functions over the dict ``collect_cluster_health`` returns. A block that is
``None`` (unreadable, not applicable, or a DR secondary) is never judged — no
finding is ever raised from missing data.

Thresholds come from the vault-ops skill and are heuristics: tune them per
cluster rather than treating a finding as a verdict.
"""

from __future__ import annotations

import re
from datetime import UTC, datetime
from typing import Any

from src.cluster_audit.collector import parse_time
from src.common.findings import Finding, finding, format_ttl

# Days before license expiration at which a finding is raised.
LICENSE_EXPIRY_WARNING_DAYS = 90

# A cluster default lease TTL above Vault's stock 768h (VT-LEASE-001).
DEFAULT_LEASE_TTL_WARNING_SECONDS = 768 * 3600

# Oldest release treated as supported (VT-HLTH-003). A constant, so it goes
# stale: bump it as HashiCorp's support window moves.
MIN_SUPPORTED_VERSION = (1, 19)

HEALTHY_REPLICATION_STATES = frozenset({"running", "stream-wals", "idle"})
# VT-REPL-001/003. The canary age is how stale the newest replicated write is on
# the peer; heartbeats arrive every few seconds on a healthy link.
REPL_CANARY_AGE_MS = 60_000
REPL_HEARTBEAT_AGE_S = 60
REPL_CLOCK_SKEW_MS = 2_000

# VT-HLTH-006: outstanding leases on the active node. Large counts slow unseal,
# leader election and expiration; large clusters legitimately run more.
LEASE_COUNT_WARNING = 100_000

# VT-SNAP-002: never judge a snapshot overdue sooner than this past its
# scheduled start. A config write leaves next_snapshot_start stale until the
# next run; 25h covers a daily schedule.
SNAPSHOT_OVERDUE_MIN_GRACE_SECONDS = 25 * 3600


def parse_version(version: str) -> tuple[int, int] | None:
    match = re.match(r"v?(\d+)\.(\d+)", version or "")
    return (int(match[1]), int(match[2])) if match else None


def parse_license_time(value: Any) -> datetime | None:
    """Parse a sys/license/status timestamp as an aware UTC datetime.

    A timestamp with no offset is taken as UTC: subtracting a naive datetime
    from an aware one raises TypeError, which would sink the whole report.
    """
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (ValueError, TypeError, AttributeError):
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


def license_expiry_days(expiration_time: Any, now: datetime | None = None) -> int | None:
    """Days until the license soft-expiry, negative once it has passed; None if unparseable."""
    expiry = parse_license_time(expiration_time)
    if expiry is None:
        return None
    reference = now or datetime.now(UTC)
    if reference.tzinfo is None:
        reference = reference.replace(tzinfo=UTC)
    return (expiry - reference).days


def license_findings(license_status: dict[str, Any] | None, now: datetime | None) -> list[Finding]:
    """VT-LIC-001, counted from ``now`` so it agrees with the report date.

    Past the soft expiry the rule escalates to High and cites the termination
    date, when Vault actually stops serving.
    """
    if not isinstance(license_status, dict):
        return []
    expiry_str = license_status.get("expiration_time", "")
    days = license_expiry_days(expiry_str, now)
    if days is None or days > LICENSE_EXPIRY_WARNING_DAYS:
        return []
    if days >= 0:
        detail = f"License expires on {expiry_str[:10]} ({days} day{'s' if days != 1 else ''} remaining) — renew before the grace period ends."
        return [finding("VT-LIC-001", "", "cluster", None, "license", detail, days_remaining=days, expiration_time=expiry_str)]

    ago = -days
    detail = f"License expired on {expiry_str[:10]} ({ago} day{'s' if ago != 1 else ''} ago)"
    termination_time = license_status.get("termination_time")
    termination = parse_license_time(termination_time)
    if termination is not None:
        detail += f"; Vault stops at termination on {termination.strftime('%Y-%m-%d')}"
    # Same rule, escalated: a diff then shows this finding worsening rather
    # than an "expires soon" resolving as an "expired" appears.
    evidence: dict[str, Any] = {"days_remaining": days, "expiration_time": expiry_str}
    if termination_time:
        evidence["termination_time"] = termination_time
    return [finding("VT-LIC-001", "", "cluster", None, "license", detail + " — renew now.", severity="High", **evidence)]


def cluster_lease_findings(system_default_lease_ttl: int | None) -> list[Finding]:
    """VT-LEASE-001: the cluster default every inheriting mount gets. 0/None means unset."""
    if not isinstance(system_default_lease_ttl, int) or system_default_lease_ttl <= DEFAULT_LEASE_TTL_WARNING_SECONDS:
        return []
    return [
        finding(
            "VT-LEASE-001",
            "",
            "cluster",
            None,
            "lease_ttl",
            f"Cluster `default_lease_ttl` is {format_ttl(system_default_lease_ttl)}, above the {format_ttl(DEFAULT_LEASE_TTL_WARNING_SECONDS)} review threshold — mounts without their own default inherit it.",
            default_lease_ttl_seconds=system_default_lease_ttl,
            threshold_seconds=DEFAULT_LEASE_TTL_WARNING_SECONDS,
        )
    ]


def never_connected(peer: dict[str, Any]) -> bool:
    """A secondary the primary lists with no heartbeat since the primary started.

    Either it never connected or it has been down since the primary restarted:
    the primary keeps heartbeats in memory only, so the two look the same.
    """
    return "node_id" in peer and peer.get("connection_status") != "connected" and not peer.get("last_heartbeat")


def replication_link_findings(kind: str, status: dict[str, Any], peers: list[dict[str, Any]], now: datetime) -> list[Finding]:
    """VT-REPL-001..005 for one replication kind (dr/performance)."""
    findings: list[Finding] = []
    mode = status.get("mode")
    label = kind.upper() if kind == "dr" else kind
    if status.get("corrupted_merkle_tree") is True:
        findings.append(
            finding(
                "VT-REPL-004",
                "",
                "cluster",
                # The path carries the kind: fingerprints ignore object_type, so DR and performance must differ here.
                kind,
                kind,
                f"{label} replication (`{mode}`) reports a corrupted merkle tree — replicated data may diverge until it is reindexed.",
                mode=mode,
            )
        )
    for peer in peers:
        peer_id = peer.get("node_id") or "primary"
        object_path = f"{kind}:{peer_id}"
        if never_connected(peer):
            findings.append(
                finding(
                    "VT-REPL-002",
                    "",
                    "cluster",
                    object_path,
                    kind,
                    f"Known {label} secondary `{peer_id}` has no heartbeat since this primary started: either it never connected "
                    "(an unused activation token, or a secondary removed without `revoke-secondary`) or it has been down since the primary "
                    "restarted. Confirm which with the team before revoking anything.",
                    secondary_id=peer_id,
                    connection_status=peer.get("connection_status"),
                )
            )
            continue
        skew = peer.get("clock_skew_ms")
        if isinstance(skew, int) and abs(skew) > REPL_CLOCK_SKEW_MS:
            findings.append(
                finding(
                    "VT-REPL-003",
                    "",
                    "cluster",
                    object_path,
                    kind,
                    f"{label} peer `{peer_id}` clock skew is {skew} ms (threshold {REPL_CLOCK_SKEW_MS} ms) — check NTP on both clusters.",
                    peer=peer_id,
                    clock_skew_ms=skew,
                    threshold_ms=REPL_CLOCK_SKEW_MS,
                )
            )
        if peer.get("connection_status") != "connected":
            continue
        canary = peer.get("replication_primary_canary_age_ms")
        heartbeat = parse_time(peer.get("last_heartbeat")) if peer.get("last_heartbeat") else None
        heartbeat_age = int((now - heartbeat).total_seconds()) if heartbeat else None
        lagging_canary = isinstance(canary, int) and canary > REPL_CANARY_AGE_MS
        stale_heartbeat = heartbeat_age is not None and heartbeat_age > REPL_HEARTBEAT_AGE_S
        if lagging_canary or stale_heartbeat:
            reasons = []
            if lagging_canary:
                reasons.append(f"newest replicated write is {canary // 1000}s old (threshold {REPL_CANARY_AGE_MS // 1000}s)")
            if stale_heartbeat:
                reasons.append(f"last heartbeat {heartbeat_age}s ago (threshold {REPL_HEARTBEAT_AGE_S}s)")
            findings.append(
                finding(
                    "VT-REPL-001",
                    "",
                    "cluster",
                    object_path,
                    kind,
                    f"{label} peer `{peer_id}` is lagging: {'; '.join(reasons)}.",
                    peer=peer_id,
                    canary_age_ms=canary,
                    heartbeat_age_seconds=heartbeat_age,
                )
            )
    for flt in status.get("paths_filters") or []:
        paths = ", ".join(flt.get("paths") or []) or "no paths"
        findings.append(
            finding(
                "VT-REPL-005",
                "",
                "cluster",
                f"{kind}:{flt.get('secondary_id')}",
                kind,
                f"Paths filter (`{flt.get('mode')}`) on secondary `{flt.get('secondary_id')}`: {paths} — these namespaces/mounts differ between the clusters by design.",
                secondary_id=flt.get("secondary_id"),
                mode=flt.get("mode"),
                paths=flt.get("paths") or [],
                dynamic_filtered_mounts=flt.get("dynamic_filtered_mounts"),
            )
        )
    return findings


def metric_findings(metrics: dict[str, Any] | None) -> list[Finding]:
    """VT-HLTH-005/006. An absent gauge (standby node) is not judged."""
    metrics = metrics or {}
    findings: list[Finding] = []
    irrevocable = metrics.get("irrevocable_leases")
    if isinstance(irrevocable, int) and irrevocable > 0:
        findings.append(
            finding(
                "VT-HLTH-005",
                "",
                "cluster",
                None,
                "metrics",
                f"{irrevocable} irrevocable lease(s): Vault could not revoke them at their backend, so the credentials may still be valid there.",
                irrevocable_leases=irrevocable,
            )
        )
    leases = metrics.get("leases")
    if isinstance(leases, int) and leases > LEASE_COUNT_WARNING:
        findings.append(
            finding(
                "VT-HLTH-006",
                "",
                "cluster",
                None,
                "metrics",
                f"{leases:,} outstanding leases, above the {LEASE_COUNT_WARNING:,} review threshold: large lease counts slow unseal, leader election and expiration.",
                leases=leases,
                threshold=LEASE_COUNT_WARNING,
            )
        )
    return findings


def audit_device_findings(devices: list[dict[str, Any]] | None) -> list[Finding]:
    """VT-AUD-001..003. None means unreadable and is not judged."""
    if devices is None:
        return []
    findings: list[Finding] = []
    if not devices:
        findings.append(finding("VT-AUD-001", "", "cluster", None, "audit", "No audit device is enabled — requests to this cluster leave no audit trail.", devices=0))
    elif len(devices) == 1:
        only = devices[0]
        findings.append(
            finding(
                "VT-AUD-002",
                "",
                "cluster",
                None,
                "audit",
                f"Only one audit device (`{only['path']}`) is enabled — if it cannot write, Vault refuses every request.",
                devices=1,
                device_path=only["path"],
                device_type=only.get("type"),
            )
        )
    for device in devices:
        options = device.get("options") or {}
        problems = [p for p, bad in (("log_raw", options.get("log_raw") is True), ("hmac_accessor", options.get("hmac_accessor") is False)) if bad]
        if problems:
            what = {"log_raw": "`log_raw=true` writes secrets in clear text", "hmac_accessor": "`hmac_accessor=false` writes token accessors unhashed"}
            findings.append(
                finding(
                    "VT-AUD-003",
                    "",
                    "audit_device",
                    device["path"],
                    device.get("type"),
                    f"Audit device `{device['path']}`: {'; '.join(what[p] for p in problems)}.",
                    log_raw=options.get("log_raw", False),
                    hmac_accessor=options.get("hmac_accessor", True),
                )
            )
    return findings


def snapshot_findings(snapshots: dict[str, Any] | None, now: datetime) -> list[Finding]:
    """VT-SNAP-001..003. None (CE, no raft, unreadable) and never-run configs are not judged."""
    if snapshots is None:
        return []
    configs = snapshots.get("configs") or []
    if not configs:
        return [finding("VT-SNAP-001", "", "cluster", None, "raft", "No automated Raft snapshot is configured — recovery depends on manual snapshots.", configs=0)]
    findings: list[Finding] = []
    for cfg in configs:
        errors = cfg.get("consecutive_errors") or 0
        last_start = parse_time(cfg.get("last_snapshot_start")) if cfg.get("last_snapshot_start") else None
        next_start = parse_time(cfg.get("next_snapshot_start")) if cfg.get("next_snapshot_start") else None
        overdue = 0
        if last_start and next_start:
            grace = max((next_start - last_start).total_seconds(), SNAPSHOT_OVERDUE_MIN_GRACE_SECONDS)
            late = (now - next_start).total_seconds()
            overdue = int(late) // 60 * 60 if late > grace else 0
        if errors or overdue:
            reason = f"the last {errors} attempt(s) failed" if errors else f"no snapshot has started for {format_ttl(overdue)} past its scheduled time"
            findings.append(
                finding(
                    "VT-SNAP-002",
                    "",
                    "snapshot_config",
                    cfg["name"],
                    cfg.get("storage_scheme"),
                    f"Automated snapshot `{cfg['name']}`: {reason} — check the status and the storage target.",
                    consecutive_errors=errors,
                    overdue_seconds=overdue,
                    last_snapshot_end=cfg.get("last_snapshot_end"),
                    next_snapshot_start=cfg.get("next_snapshot_start"),
                )
            )
        if cfg.get("storage_scheme") == "file":
            findings.append(
                finding(
                    "VT-SNAP-003",
                    "",
                    "snapshot_config",
                    cfg["name"],
                    "file",
                    f"Automated snapshot `{cfg['name']}` writes to the node's local disk — a lost node takes its snapshots with it.",
                    storage_scheme="file",
                )
            )
    return findings


def reference_time(health: dict[str, Any]) -> datetime:
    """The node's clock at collection, so neither a long namespace walk nor host
    clock skew reads as replication lag."""
    server_time = health.get("server_time_utc")
    return datetime.fromtimestamp(server_time, UTC) if isinstance(server_time, int) and server_time > 0 else datetime.now(UTC)


def health_findings(health: dict[str, Any] | None, now: datetime | None = None) -> list[Finding]:
    """Every cluster health rule except license and lease, which have their own sources."""
    if not health:
        return []
    now = now or reference_time(health)
    findings: list[Finding] = []
    leader = health.get("leader") or {}
    no_leader = leader.get("ha_enabled") is True and not leader.get("leader_address_present")
    if health.get("sealed") is True or no_leader:
        reason = "sealed" if health.get("sealed") else "no active leader"
        findings.append(
            finding(
                "VT-HLTH-001",
                "",
                "cluster",
                None,
                None,
                f"Node reports `{reason}` — requests to this node will fail until it is resolved.",
                sealed=bool(health.get("sealed")),
                active_leader=not no_leader,
            )
        )
    for kind, status in sorted((health.get("replication") or {}).items()):
        if not isinstance(status, dict):
            continue
        mode, state = status.get("mode"), status.get("state")
        if not mode or mode in ("disabled", "unknown"):
            continue
        peers = status.get("secondaries") or status.get("primaries") or []
        findings += replication_link_findings(kind, status, peers, now)
        # A peer with no heartbeat since the primary started is VT-REPL-002 alone:
        # listing it here too reported one dead secondary twice, the second time
        # at a higher severity than the rule written for it.
        disconnected = sorted(p.get("node_id") or "primary" for p in peers if p.get("connection_status") != "connected" and not never_connected(p))
        if state not in HEALTHY_REPLICATION_STATES:
            detail = f"{kind.upper()} replication is `{mode}` but its state is `{state}` — check the replication link."
        elif disconnected:
            detail = f"{kind.upper()} replication `{mode}` has disconnected peer(s): {', '.join(disconnected)} — check the cluster port (8201) path and the peer's status."
        else:
            continue
        findings.append(finding("VT-HLTH-002", "", "cluster", kind, kind, detail, mode=mode, state=state, disconnected_peers=disconnected))
    autopilot = ((health.get("raft") or {}).get("autopilot") or {}).get("state") or {}
    unhealthy = sorted(s["id"] for s in autopilot.get("servers") or [] if s.get("healthy") is False)
    if autopilot.get("healthy") is False or unhealthy:
        servers = f"unhealthy server(s): {', '.join(unhealthy)}" if unhealthy else "the cluster is unhealthy"
        findings.append(
            finding(
                "VT-HLTH-004",
                "",
                "cluster",
                None,
                "raft",
                f"Raft autopilot reports {servers} (failure tolerance {autopilot.get('failure_tolerance')}) — check node status, last contact and trailing logs.",
                healthy=autopilot.get("healthy"),
                failure_tolerance=autopilot.get("failure_tolerance"),
                unhealthy_servers=unhealthy,
            )
        )
    version = parse_version(health.get("version") or "")
    if version and version < MIN_SUPPORTED_VERSION:
        minimum = ".".join(map(str, MIN_SUPPORTED_VERSION))
        findings.append(
            finding(
                "VT-HLTH-003",
                "",
                "cluster",
                None,
                None,
                f"Vault {health.get('version')} is older than {minimum}, the oldest release this tool treats as supported.",
                version=health.get("version"),
                min_supported=minimum,
            )
        )
    findings += metric_findings(health.get("metrics"))
    findings += audit_device_findings(health.get("audit_devices"))
    findings += snapshot_findings(health.get("snapshots"), now)
    return findings
