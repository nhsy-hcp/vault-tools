"""Markdown and findings.json rendering for the cluster health checks.

Pure functions: no Vault calls, no filesystem. ``render_cluster_health`` is
shared with the namespace audit report, which embeds the same section.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from src.cluster_audit.collector import ClusterCoverage
from src.cluster_audit.findings import cluster_lease_findings, health_findings, license_findings
from src.common.findings import Finding, build_findings_document, coverage_block, format_ttl, get_tool_version, run_block, sort_findings
from src.common.markdown import md_escape, md_table, render_findings_table

# Why a whole family of reads was skipped by design rather than denied.
_UNAVAILABLE_NOTES = {
    "sealed": "The node is **sealed**, so it answers only `sys/health` and `sys/seal-status`. Every other block below is empty by design, not missing permissions.",
    "uninitialized": "The node is **not initialized**, so it answers only `sys/health` and `sys/seal-status`.",
    "dr_secondary": "The node is a **DR secondary**: only unauthenticated status is readable. Raft, audit device, snapshot, metrics and license data are empty by design.",
}

_NOT_READ = "_Not read — see **Cluster-level reads** under the access gaps._"


_LICENSE_UNAVAILABLE_NOTES = {
    "denied": "_License data unavailable — the token was denied read on `sys/license/status`._",
    "unexpected response": "_License data unavailable — `sys/license/status` returned a response with no `autoloaded` license._",
}


def render_license(
    license_status: dict[str, Any] | None,
    is_enterprise: bool | None,
    unavailable_reason: str | None = None,
) -> str:
    """Render the ## License section.

    Returns an empty string when there is nothing to say — Community Edition,
    or an unknown edition where the probe recorded no failure — so the caller
    can omit the section entirely. Otherwise returns a note worded from
    ``unavailable_reason``, so a 5xx is not reported as a token problem.
    """
    if license_status is None:
        if unavailable_reason is None and not is_enterprise:
            return ""
        if unavailable_reason and unavailable_reason.startswith("error: "):
            return f"_License data unavailable — reading `sys/license/status` failed: {md_escape(unavailable_reason.removeprefix('error: '))}_"
        return _LICENSE_UNAVAILABLE_NOTES.get(unavailable_reason or "", "_License data unavailable — `sys/license/status` was not read._")

    rows: list[list[Any]] = []
    rows.append(["License ID", license_status.get("license_id", "—")])
    rows.append(["Issuer", license_status.get("issuer", "—")])
    edition = license_status.get("edition", "")
    if edition:
        rows.append(["Edition", edition])
    expiry = license_status.get("expiration_time", "")
    if expiry:
        rows.append(["Expires (soft)", expiry[:10]])
    termination = license_status.get("termination_time", "")
    if termination:
        rows.append(["Terminates (hard)", termination[:10]])
    perf_standbys = license_status.get("performance_standby_count")
    if perf_standbys is not None:
        rows.append(["Perf. standbys", perf_standbys])

    features = license_status.get("features") or []
    features_line = ", ".join(sorted(features)) if features else "—"

    table = md_table(["Field", "Value"], rows)
    return f"{table}\n\n**Features:** {features_line}"


def _value(value: Any) -> Any:
    if value is None:
        return "—"
    if isinstance(value, bool):
        return "yes" if value else "no"
    return value


def _node_rows(health: dict[str, Any]) -> list[list[Any]]:
    leader = health.get("leader") or {}
    rows: list[list[Any]] = [
        ["Initialized", _value(health.get("initialized"))],
        ["Sealed", _value(health.get("sealed"))],
        ["Standby", _value(health.get("standby"))],
        ["Performance standby", _value(health.get("performance_standby"))],
    ]
    if leader:
        rows.append(["HA enabled", _value(leader.get("ha_enabled"))])
        rows.append(["This node is the leader", _value(leader.get("is_self"))])
        rows.append(["Active leader present", _value(leader.get("leader_address_present"))])
    rows.append(["DR replication mode", _value(health.get("replication_dr_mode"))])
    rows.append(["Performance replication mode", _value(health.get("replication_performance_mode"))])
    return rows


def _render_seal(seal: dict[str, Any] | None) -> str:
    if not seal:
        return ""
    rows = [
        ["Seal type", _value(seal.get("type"))],
        ["Unseal threshold", f"{seal.get('t')} of {seal.get('n')} key shares" if seal.get("t") is not None else "—"],
        ["Unseal progress", _value(seal.get("progress"))],
        ["Seal migration", _value(seal.get("migration"))],
        ["Recovery seal", _value(seal.get("recovery_seal"))],
    ]
    return "### Seal\n\n" + md_table(["Field", "Value"], rows)


def _render_replication(replication: dict[str, Any] | None) -> str:
    if replication is None:
        return _NOT_READ
    if isinstance(replication.get("mode"), str):
        return f"Replication is `{md_escape(replication['mode'])}` on this storage backend."
    rows: list[list[Any]] = []
    peers: list[list[Any]] = []
    for kind in ("dr", "performance"):
        status = replication.get(kind) or {}
        rows.append([kind.upper() if kind == "dr" else "Performance", _value(status.get("mode")), _value(status.get("state")), _value(status.get("corrupted_merkle_tree"))])
        for peer in status.get("secondaries") or status.get("primaries") or []:
            peers.append(
                [
                    kind.upper() if kind == "dr" else "Performance",
                    peer.get("node_id") or "primary",
                    _value(peer.get("connection_status")),
                    _value(peer.get("last_heartbeat")),
                    _value(peer.get("clock_skew_ms")),
                    _value(peer.get("replication_primary_canary_age_ms")),
                ]
            )
    parts = [md_table(["Kind", "Mode", "State", "Corrupted merkle tree"], rows)]
    if peers:
        parts.append(md_table(["Kind", "Peer", "Connection", "Last heartbeat", "Clock skew (ms)", "Canary age (ms)"], peers))
    filters = (replication.get("performance") or {}).get("paths_filters")
    if filters:
        parts.append(
            md_table(
                ["Secondary", "Filter mode", "Paths", "Dynamic filtered mounts"],
                [[f["secondary_id"], f["mode"], ", ".join(f["paths"]) or "—", _value(f.get("dynamic_filtered_mounts"))] for f in filters],
            )
        )
    return "\n\n".join(parts)


def _render_raft(raft: dict[str, Any] | None, dr_secondary: bool) -> str:
    if raft is None:
        return "_Not applicable on a DR secondary._" if dr_secondary else "_Integrated storage (raft) is not in use, or its endpoints were not readable._"
    parts: list[str] = []
    state = (raft.get("autopilot") or {}).get("state")
    servers = {s["id"]: s for s in (state or {}).get("servers") or []}
    if raft.get("peers") is not None:
        rows = []
        for peer in raft["peers"]:
            server = servers.get(peer.get("node_id")) or {}
            rows.append(
                [
                    peer.get("node_id"),
                    _value(peer.get("leader")),
                    _value(peer.get("voter")),
                    _value(server.get("status")),
                    _value(server.get("healthy")),
                    _value(server.get("last_contact")),
                ]
            )
        parts.append(md_table(["Node", "Leader", "Voter", "Autopilot status", "Healthy", "Last contact"], rows))
    if state:
        parts.append(f"**Autopilot:** healthy {_value(state.get('healthy'))}, failure tolerance {_value(state.get('failure_tolerance'))}.")
    config = (raft.get("autopilot") or {}).get("configuration")
    if config:
        parts.append("**Autopilot configuration:** " + ", ".join(f"`{k}`={v}" for k, v in config.items()))
    return "\n\n".join(parts) or _NOT_READ


def _render_audit_devices(devices: list[dict[str, Any]] | None) -> str:
    if devices is None:
        return _NOT_READ
    if not devices:
        return "_No audit device is enabled._"
    rows = []
    for device in devices:
        options = device.get("options") or {}
        extras = ", ".join(f"{k}={_value(v)}" for k, v in options.items() if k not in ("sink",))
        rows.append([device["path"], device.get("type"), options.get("sink", "—"), _value(device.get("local")), extras or "—"])
    return md_table(["Path", "Type", "Sink", "Local", "Options"], rows)


def _render_snapshots(snapshots: dict[str, Any] | None, enterprise: bool | None, raft: Any) -> str:
    if snapshots is None:
        if not enterprise or raft is None:
            return "_Not judged — automated snapshots need Vault Enterprise on integrated storage._"
        return _NOT_READ
    configs = snapshots.get("configs") or []
    if not configs:
        return "_No automated snapshot is configured._"
    rows = [
        [
            c["name"],
            _value(c.get("last_snapshot_end")),
            _value(c.get("next_snapshot_start")),
            _value(c.get("consecutive_errors")),
            _value(c.get("storage_scheme")),
        ]
        for c in configs
    ]
    return md_table(["Config", "Last run", "Next run", "Consecutive errors", "Storage"], rows)


_METRIC_LABELS = {
    "leases": ("Outstanding leases", "active node only"),
    "irrevocable_leases": ("Irrevocable leases", "active node only"),
    "in_flight_requests": ("In-flight requests", ""),
    "raft_fsm_pending": ("Raft FSM pending", ""),
    "raft_oldest_log_age_ms": ("Raft oldest log age (ms)", "leader only"),
    "goroutines": ("Goroutines", ""),
    "alloc_bytes": ("Allocated bytes", ""),
    "sys_bytes": ("System bytes", ""),
    "token_count": ("Tokens", ""),
}


def _render_metrics(metrics: dict[str, Any] | None) -> str:
    if metrics is None:
        return _NOT_READ
    rows = []
    for key, (label, note) in _METRIC_LABELS.items():
        value = metrics.get(key)
        rows.append([label, f"{value:,}" if isinstance(value, int) else ("not reported" if value is None else value), note])
    when = f" at {metrics['timestamp']}" if metrics.get("timestamp") else ""
    return f"Gauges from **the queried node only**{when} — never cluster-wide totals.\n\n" + md_table(["Metric", "Value", "Notes"], rows)


def render_cluster_health(health: dict[str, Any] | None, heading_level: int = 2) -> str:
    """The cluster health section; empty string when nothing was collected."""
    if not health:
        return ""
    h = "#" * heading_level
    sub = "#" * (heading_level + 1)
    reason = "sealed" if health.get("sealed") else "uninitialized" if health.get("initialized") is False else "dr_secondary" if health.get("dr_secondary") else None
    parts = [f"{h} Cluster health"]
    if reason:
        parts.append(_UNAVAILABLE_NOTES[reason])
    parts.append(md_table(["Field", "Value"], _node_rows(health)))
    if seal := _render_seal(health.get("seal")):
        parts.append(seal)
    if reason in ("sealed", "uninitialized"):
        return "\n\n".join(parts)
    parts += [
        f"{sub} Replication",
        _render_replication(health.get("replication")),
        f"{sub} Integrated storage (raft)",
        _render_raft(health.get("raft"), bool(health.get("dr_secondary"))),
    ]
    if not health.get("dr_secondary"):
        parts += [
            f"{sub} Audit devices",
            _render_audit_devices(health.get("audit_devices")),
            f"{sub} Automated snapshots",
            _render_snapshots(health.get("snapshots"), health.get("enterprise"), health.get("raft")),
            f"{sub} Node metrics",
            _render_metrics(health.get("metrics")),
        ]
    return "\n\n".join(parts)


def render_cluster_reads(coverage: ClusterCoverage | None, license_unavailable_reason: str | None = None) -> str:
    """The "Cluster-level reads" line: what the token could not read outside the namespace walk."""
    denied = list(coverage.denied) if coverage else []
    if license_unavailable_reason == "denied":
        denied.append("sys/license/status")
    parts = []
    if denied:
        parts.append(
            "**Cluster-level reads:** denied " + ", ".join(f"`{d}`" for d in sorted(set(denied))) + " — the matching sections are incomplete. Check `audit-policy.hcl` is attached to the token."
        )
    if coverage and coverage.errors:
        parts.append("**Cluster-level errors:** " + "; ".join(f"`{scope}`: {md_escape(msg)}" for scope, msg in coverage.errors))
    return "\n\n".join(parts)


def collect_cluster_findings(
    health: dict[str, Any] | None,
    *,
    license_status: dict[str, Any] | None = None,
    system_lease_ttls: tuple[int, int] | None = None,
    now: datetime | None = None,
) -> list[Finding]:
    findings = health_findings(health)
    findings += license_findings(license_status, now)
    findings += cluster_lease_findings(system_lease_ttls[0] if system_lease_ttls else None)
    return sort_findings(findings)


def build_cluster_findings_json(
    cluster_name: str,
    health: dict[str, Any],
    coverage: ClusterCoverage,
    findings: list[Finding],
    *,
    vault_addr: str,
    started_at: datetime,
    finished_at: datetime,
    system_lease_ttls: tuple[int, int] | None = None,
    license_unavailable_reason: str | None = None,
) -> dict[str, Any]:
    denied = [("", scope) for scope in coverage.denied]
    if license_unavailable_reason == "denied":
        denied.append(("", "sys/license/status"))
    return build_findings_document(
        findings,
        run=run_block(cluster_name, vault_addr, "", started_at, finished_at),
        cluster_context={
            "vault_version": health.get("version"),
            "enterprise": health.get("enterprise"),
            "system_max_lease_ttl_seconds": system_lease_ttls[1] if system_lease_ttls else None,
            "system_default_lease_ttl_seconds": system_lease_ttls[0] if system_lease_ttls else None,
            # cluster-audit never reads Sentinel; namespace-audit does.
            "sentinel": "skipped",
        },
        coverage=coverage_block(0, denied, coverage.error_rows()),
        tool_version=get_tool_version(),
    )


def build_cluster_report(
    cluster_name: str,
    health: dict[str, Any],
    coverage: ClusterCoverage,
    findings: list[Finding],
    *,
    vault_addr: str = "",
    generated_at: datetime | None = None,
    license_status: dict[str, Any] | None = None,
    license_unavailable_reason: str | None = None,
    system_lease_ttls: tuple[int, int] | None = None,
    output_files: list[str] | None = None,
) -> str:
    generated = generated_at or datetime.now(UTC)
    header = [
        ["Cluster", cluster_name],
        ["Generated", generated.strftime("%Y-%m-%d %H:%M:%S UTC")],
        ["Tool version", f"vault-tools {get_tool_version()}"],
    ]
    if vault_addr:
        header.insert(1, ["Vault address", vault_addr])
    if health.get("version"):
        edition = health.get("enterprise")
        header.append(["Vault version", health["version"] + ("" if edition is None else " (Enterprise)" if edition else " (Community Edition)")])
    if system_lease_ttls:
        header.append(["System lease TTL", f"{format_ttl(system_lease_ttls[0])} default / {format_ttl(system_lease_ttls[1])} max"])

    sections = [f"# Vault Cluster Audit — {cluster_name}", "", md_table(["Field", "Value"], header), "", render_cluster_health(health), ""]
    if license_content := render_license(license_status, health.get("enterprise"), license_unavailable_reason):
        sections += ["## License", "", license_content, ""]
    sections += [
        "## Access gaps",
        "",
        render_cluster_reads(coverage, license_unavailable_reason) or "None — every cluster-level read succeeded or was not applicable to this node.",
        "",
        "## Security observations",
        "",
        "Prompts for review, not a compliance verdict. Thresholds are heuristics from the vault-ops skill's rule catalogue.",
        "",
        render_findings_table(findings, "_No observations — the node is unsealed with a leader, replication and raft are healthy, and audit devices, snapshots and lease counts raised nothing._"),
        "",
        "## Output files",
        "",
        md_table(["File"], [[f] for f in (output_files or [])]),
        "",
    ]
    return "\n".join(sections)
