"""Client-count anti-patterns from the activity log (VT-CLI-001..005), ported from the vault-ops skill.

Pure functions over the ``sys/internal/counters/activity`` response the export
already fetched, plus the month in progress (``activity/monthly``) and the
activity-log configuration (``counters/config``). They point at how workloads
authenticate rather than at one setting, so most are prompts to investigate.
"""

from __future__ import annotations

from typing import Any

from src.common.findings import Finding, finding

# Namespaces and mounts below this many clients are never judged: a ratio over
# a handful of clients is noise.
CLIENT_RULE_MIN_CLIENTS = 50
NON_ENTITY_SHARE_WARNING = 0.5  # VT-CLI-001
CLIENT_GROWTH_WARNING = 0.5  # VT-CLI-002: latest month above the recent average by this fraction
CLIENT_GROWTH_MIN_CLIENTS = 100
CLIENT_CHURN_WARNING = 0.9  # VT-CLI-003: share of a mount's clients that are new this month
ROOT_NAMESPACE_SHARE_WARNING = 0.8  # VT-CLI-004

# counters/config "enabled" values. "default-*" is what an unconfigured cluster
# reports: Community dev servers ship with the log off.
ACTIVITY_LOG_RECORDING = {"enable": True, "default-enabled": True, "disable": False, "default-disabled": False}


def client_count(block: dict[str, Any] | None, key: str = "clients") -> int:
    return int((block or {}).get(key) or 0)


def _share(part: int, whole: int) -> str:
    return f"{part / whole:.0%}" if whole else "n/a"


def _namespace(path: Any) -> str:
    return (path or "").strip().strip("/")


def parse_activity_config(data: dict[str, Any] | None) -> dict[str, Any] | None:
    """Allowlisted counters/config fields. ``recording`` is None for an unknown value."""
    if data is None:
        return None
    enabled = data.get("enabled")
    retention = data.get("retention_months")
    return {
        "enabled": enabled,
        "recording": ACTIVITY_LOG_RECORDING.get(enabled) if isinstance(enabled, str) else None,
        "retention_months": int(retention) if isinstance(retention, int | str) and str(retention).isdigit() else None,
        "reporting_enabled": data.get("reporting_enabled") if isinstance(data.get("reporting_enabled"), bool) else None,
    }


def _mount_clients(namespaces: list[dict[str, Any]] | None) -> dict[tuple[str, str], tuple[int, str | None]]:
    return {(_namespace(ns.get("namespace_path")), m.get("mount_path") or ""): (client_count(m.get("counts")), m.get("mount_type")) for ns in namespaces or [] for m in ns.get("mounts") or []}


def usage_findings(
    activity: dict[str, Any],
    current: dict[str, Any] | None = None,
    enterprise: bool | None = False,
    activity_log: dict[str, Any] | None = None,
) -> list[Finding]:
    """Client-count anti-patterns for the requested window, falling back to the month in progress."""
    findings: list[Finding] = []
    if activity_log and activity_log.get("recording") is False:
        findings.append(
            finding(
                "VT-CLI-005",
                "",
                "cluster",
                None,
                "activity_log",
                f"The activity log is `{activity_log.get('enabled')}`: Vault records no client activity, so client counts read as zero "
                "and the client-count checks (VT-CLI-001..004, VT-ID-004) cannot be judged.",
                enabled=activity_log.get("enabled"),
            )
        )
    # A new cluster has no completed billing period yet: judge the month in progress instead.
    if client_count(activity.get("total")):
        source, rows = "billing_period", activity.get("by_namespace") or []
    else:
        source, rows = "current_month", (current or {}).get("by_namespace") or []

    total = sum(client_count(row.get("counts")) for row in rows)
    for row in rows:
        counts = row.get("counts") or {}
        clients, non_entity = client_count(counts), client_count(counts, "non_entity_clients")
        if clients >= CLIENT_RULE_MIN_CLIENTS and non_entity / clients > NON_ENTITY_SHARE_WARNING:
            findings.append(
                finding(
                    "VT-CLI-001",
                    _namespace(row.get("namespace_path")),
                    "namespace",
                    None,
                    None,
                    f"{non_entity} of {clients} clients ({_share(non_entity, clients)}) are token-only — every token without an entity counts as a separate client.",
                    clients=clients,
                    non_entity_clients=non_entity,
                    source=source,
                )
            )
    root = sum(client_count(row.get("counts")) for row in rows if not _namespace(row.get("namespace_path")))
    if enterprise and total >= CLIENT_RULE_MIN_CLIENTS and root / total > ROOT_NAMESPACE_SHARE_WARNING:
        findings.append(
            finding(
                "VT-CLI-004",
                "",
                "namespace",
                None,
                None,
                f"{root} of {total} clients ({_share(root, total)}) are in the root namespace — tenants share one policy and identity space.",
                root_clients=root,
                clients=total,
                namespaces_reported=len(rows),
                source=source,
            )
        )

    months = sorted((m for m in activity.get("months") or [] if m.get("timestamp")), key=lambda m: m["timestamp"])
    series = [(m["timestamp"], client_count(m.get("counts"))) for m in months]
    if current is not None:
        current_ts = ((current.get("months") or [{}])[0] or {}).get("timestamp") or "current"
        series = [s for s in series if s[0] != current_ts] + [(current_ts, client_count(current))]
    if len(series) >= 2:
        latest_ts, latest = series[-1]
        prior = [c for _, c in series[:-1] if c > 0][-3:]
        baseline = sum(prior) / len(prior) if prior else 0
        if baseline and latest >= CLIENT_GROWTH_MIN_CLIENTS and latest > baseline * (1 + CLIENT_GROWTH_WARNING):
            findings.append(
                finding(
                    "VT-CLI-002",
                    "",
                    "cluster",
                    None,
                    None,
                    f"{latest} clients in {latest_ts[:7]} against an average of {baseline:.0f} over the previous {len(prior)} month(s) — check for login loops or identities created per run.",
                    month=latest_ts[:7],
                    clients=latest,
                    baseline_clients=round(baseline),
                    months_compared=len(prior),
                )
            )

    # Churn needs consecutive months from one query: the first month of any
    # window reports every client as new, so the current-month response (its
    # own window) is never used here.
    if len(months) >= 2:
        prev, last = months[-2], months[-1]
        before = _mount_clients(prev.get("namespaces"))
        new = _mount_clients((last.get("new_clients") or {}).get("namespaces"))
        for (ns, mount_path), (clients, mtype) in sorted(_mount_clients(last.get("namespaces")).items()):
            if not mount_path.endswith("/") or clients < CLIENT_RULE_MIN_CLIENTS or not before.get((ns, mount_path), (0, None))[0]:
                continue
            fresh = new.get((ns, mount_path), (0, None))[0]
            if fresh / clients >= CLIENT_CHURN_WARNING:
                kind, path = ("auth_mount", mount_path[len("auth/") :]) if mount_path.startswith("auth/") else ("secrets_mount", mount_path)
                findings.append(
                    finding(
                        "VT-CLI-003",
                        ns,
                        kind,
                        path,
                        mtype,
                        f"{fresh} of {clients} clients on this mount in {last['timestamp'][:7]} were new ({_share(fresh, clients)}) — identities are created per login or run instead of reused.",
                        month=last["timestamp"][:7],
                        clients=clients,
                        new_clients=fresh,
                    )
                )
    return findings
