"""Cluster-level reads: seal, HA, replication, raft, audit devices, snapshots, metrics.

Ported from the vault-ops skill's ``collect_health``. Every read is optional
enrichment: a denial or an error is recorded on ``ClusterCoverage`` and the
block stays ``None``, so "denied", "not applicable" and "empty" remain
distinguishable in the report. Nothing here raises.

What is collected is allowlisted rather than copied: addresses, cluster IDs,
file paths, snapshot URLs, storage credentials and metric labels never leave
this module.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

import hvac
import requests

from src.common.exceptions import VaultPermissionError
from src.common.vault_client import VaultClient

logger = logging.getLogger(__name__)

# sys/health query that answers 200 with a body for every node state, so a
# sealed, standby or DR-secondary node still describes itself.
HEALTH_PARAMS = {
    "standbyok": "true",
    "perfstandbyok": "true",
    "sealedcode": "200",
    "uninitcode": "200",
    "drsecondarycode": "200",
    "performancestandbycode": "200",
    "standbycode": "200",
}

# Allowlisted sys/metrics gauges: output key -> (metric name, aggregation over
# label sets). Labels are dropped because their values carry cluster names and
# addresses. These are the queried node's own values, never cluster totals.
METRIC_GAUGES = {
    "leases": ("vault.expire.num_leases", "max"),
    "irrevocable_leases": ("vault.expire.num_irrevocable_leases", "max"),
    "in_flight_requests": ("vault.core.in_flight_requests", "sum"),
    "raft_fsm_pending": ("vault.raft_storage.stats.fsm_pending", "max"),
    "raft_oldest_log_age_ms": ("vault.raft.leader.oldestLogAge", "max"),
    "goroutines": ("vault.runtime.num_goroutines", "max"),
    "alloc_bytes": ("vault.runtime.alloc_bytes", "max"),
    "sys_bytes": ("vault.runtime.sys_bytes", "max"),
    "token_count": ("vault.token.count", "sum"),
}

AUTOPILOT_CONFIG_KEYS = (
    "cleanup_dead_servers",
    "dead_server_last_contact_threshold",
    "last_contact_threshold",
    "max_trailing_logs",
    "min_quorum",
    "server_stabilization_time",
    "disable_upgrade_migration",
)
AUTOPILOT_SERVER_KEYS = ("status", "node_type", "node_status", "healthy", "last_contact", "last_term", "last_index", "stable_since", "version")

AUDIT_OPTION_FLAGS = ("hmac_accessor", "log_raw", "elide_list_responses", "fallback")
AUDIT_FORMATS = frozenset({"json", "jsonx"})
# A file device's path is only reported when it is one of these sentinels;
# anything else is a real path on the node and is reduced to "file".
AUDIT_FILE_SINKS = frozenset({"stdout", "discard"})
SNAPSHOT_TIME_KEYS = ("last_snapshot_start", "last_snapshot_end", "next_snapshot_start")
URL_SCHEME = re.compile(r"^([a-z][a-z0-9+.-]{0,15}):")

# Hard cap on a recorded error message, before the schema's own limit.
MAX_ERROR_LENGTH = 200


@dataclass
class ClusterCoverage:
    """What the cluster reads could not see. Scopes are endpoint paths."""

    denied: list[str] = field(default_factory=list)
    errors: list[tuple[str, str]] = field(default_factory=list)

    def deny(self, scope: str) -> None:
        if scope not in self.denied:
            self.denied.append(scope)

    def error(self, scope: str, exc: BaseException) -> None:
        self.errors.append((scope, sanitise_error(exc)))

    @property
    def complete(self) -> bool:
        return not self.denied and not self.errors


def sanitise_error(exc: BaseException) -> str:
    """Exception class plus HTTP status only: hvac messages can echo request URLs."""
    status = getattr(getattr(exc, "response", None), "status_code", None)
    return (type(exc).__name__ + (f" (HTTP {status})" if status else ""))[:MAX_ERROR_LENGTH]


def as_bool(value: Any) -> bool:
    """Vault stores audit options as strings ("true"/"false"); parse like Go's ParseBool."""
    return value is True or str(value).strip().lower() in ("1", "t", "true")


def parse_time(timestamp: Any) -> datetime | None:
    try:
        parsed = datetime.fromisoformat(str(timestamp).replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


def _iso(ts: datetime) -> str:
    return ts.astimezone(UTC).isoformat().replace("+00:00", "Z")


def unauthenticated_only(health: dict[str, Any]) -> str | None:
    """Why this node rejects authenticated reads, or None when it serves them."""
    if health.get("initialized") is False:
        return "uninitialized"
    if health.get("sealed") is True:
        return "sealed"
    if health.get("replication_dr_mode") == "secondary":
        return "dr_secondary"
    return None


class _Reader:
    """GET-only helper over one hvac client; raises hvac exceptions unchanged."""

    def __init__(self, client: Any):
        self.client = client

    def get(self, path: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        response = self.client.adapter.get(f"/v1/{path}", params=params)
        return response if isinstance(response, dict) else {}

    def data(self, path: str) -> dict[str, Any]:
        payload = self.get(path)
        return payload["data"] if isinstance(payload.get("data"), dict) else payload

    def list(self, path: str) -> list[str]:
        return list((self.get(path, params={"list": "true"}).get("data") or {}).get("keys") or [])


def read_health(vault_client: VaultClient) -> dict[str, Any] | None:
    """Unauthenticated sys/health, answering for every node state. None if unreachable."""
    try:
        with vault_client.get_client() as client:
            return _Reader(client).get("sys/health", params=HEALTH_PARAMS)
    except Exception as e:
        logger.debug(f"Could not read sys/health: {e}")
        return None


def collect_cluster_health(
    vault_client: VaultClient,
    health_status: dict[str, Any] | None = None,
    coverage: ClusterCoverage | None = None,
) -> tuple[dict[str, Any], ClusterCoverage]:
    """Read every cluster-level block. Never raises.

    ``health_status`` is a sys/health response already in hand (cluster-audit
    reads it first to decide whether the token can be validated at all).

    A sealed or uninitialised node answers only sys/health and sys/seal-status;
    a DR secondary answers only the unauthenticated endpoints. Both are
    reported by design, not as denials.
    """
    coverage = coverage or ClusterCoverage()
    try:
        with vault_client.get_client() as client:
            return _collect(_Reader(client), health_status, coverage), coverage
    except Exception as e:  # pragma: no cover - defensive: never sink the caller's run
        logger.debug(f"Cluster health collection failed: {e}")
        coverage.error("cluster health", e)
        return empty_health(health_status or {}), coverage


def empty_health(health: dict[str, Any]) -> dict[str, Any]:
    version = health.get("version")
    return {
        "cluster_name": health.get("cluster_name") or "vault",
        "version": version,
        # None when sys/health was unreadable, matching ConnectionInfo.
        "enterprise": ("+ent" in version) if isinstance(version, str) else None,
        "initialized": health.get("initialized"),
        "sealed": health.get("sealed"),
        "standby": health.get("standby"),
        "performance_standby": health.get("performance_standby"),
        "replication_dr_mode": health.get("replication_dr_mode"),
        "replication_performance_mode": health.get("replication_performance_mode"),
        "dr_secondary": health.get("replication_dr_mode") == "secondary",
        "performance_secondary": health.get("replication_performance_mode") == "secondary",
        # The node's clock when sys/health answered: the reference for heartbeat ages.
        "server_time_utc": health.get("server_time_utc") if isinstance(health.get("server_time_utc"), int) else None,
        "seal": None,
        "leader": None,
        "replication": None,
        "raft": None,
        "audit_devices": None,
        "snapshots": None,
        "metrics": None,
    }


def _optional(reader: _Reader, coverage: ClusterCoverage, path: str) -> dict[str, Any] | None:
    try:
        return reader.data(path)
    except hvac.exceptions.Forbidden:
        coverage.deny(path)
    except hvac.exceptions.InvalidPath:
        pass
    except (hvac.exceptions.VaultError, requests.exceptions.RequestException) as e:
        coverage.error(path, e)
    return None


def _collect(reader: _Reader, health_status: dict[str, Any] | None, coverage: ClusterCoverage) -> dict[str, Any]:
    health = health_status
    if health is None:
        try:
            health = reader.get("sys/health", params=HEALTH_PARAMS)
        except hvac.exceptions.InvalidPath:
            health = {}
        except (hvac.exceptions.VaultError, requests.exceptions.RequestException) as e:
            coverage.error("sys/health", e)
            health = {}
    result = empty_health(health)
    dr_secondary = result["dr_secondary"]

    if health.get("sealed") is True or health.get("initialized") is False:
        # Every other endpoint answers 503 "Vault is sealed"; seal-status is unauthenticated.
        if (seal := _optional(reader, coverage, "sys/seal-status")) is not None:
            result["seal"] = {k: seal.get(k) for k in ("type", "t", "n", "progress", "migration", "recovery_seal")}
        return result

    if (leader := _optional(reader, coverage, "sys/leader")) is not None:
        result["leader"] = {
            "ha_enabled": leader.get("ha_enabled"),
            "is_self": leader.get("is_self"),
            # Presence only: the address itself is internal topology.
            "leader_address_present": bool(leader.get("leader_address")),
            "raft_committed_index": leader.get("raft_committed_index"),
        }
    if (repl := _optional(reader, coverage, "sys/replication/status")) is not None:
        if isinstance(repl.get("mode"), str):
            # e.g. {"mode": "unsupported"} on storage that cannot replicate (dev/inmem).
            result["replication"] = {"mode": repl["mode"]}
        else:
            result["replication"] = {kind: replication_summary(repl.get(kind) or {}) for kind in ("dr", "performance")}
            perf = result["replication"]["performance"]
            if perf.get("mode") == "primary" and not dr_secondary:
                perf["paths_filters"] = collect_paths_filters(reader, coverage, perf.get("known_secondaries") or [])
    if dr_secondary:
        return result
    result["raft"] = collect_raft(reader, coverage)
    result["audit_devices"] = collect_audit_devices(reader, coverage)
    # Automated snapshots are Enterprise and raft only; elsewhere the endpoint 404s like "none configured".
    if result["enterprise"] and result["raft"] is not None:
        result["snapshots"] = collect_snapshots(reader, coverage)
    result["metrics"] = collect_metrics(reader, coverage)
    return result


def collect_metrics(reader: _Reader, coverage: ClusterCoverage) -> dict[str, Any] | None:
    try:
        payload = reader.get("sys/metrics")
    except hvac.exceptions.Forbidden:
        coverage.deny("sys/metrics")
        return None
    except hvac.exceptions.InvalidPath:
        return None
    except (hvac.exceptions.VaultError, requests.exceptions.RequestException) as e:
        coverage.error("sys/metrics", e)
        return None
    gauges = payload.get("Gauges")
    if not isinstance(gauges, list):
        coverage.error("sys/metrics", ValueError("unrecognised sys/metrics payload"))
        return None
    values: dict[str, list[float]] = {}
    for gauge in gauges:
        value = gauge.get("Value") if isinstance(gauge, dict) else None
        if isinstance(value, int | float) and not isinstance(value, bool):
            values.setdefault(str(gauge.get("Name")), []).append(value)
    metrics: dict[str, Any] = {"timestamp": metrics_timestamp(payload.get("Timestamp"))}
    for key, (name, agg) in METRIC_GAUGES.items():
        found = values.get(name)
        value = (sum(found) if agg == "sum" else max(found)) if found else None
        metrics[key] = int(value) if isinstance(value, float) and value.is_integer() else value
    return metrics


def metrics_timestamp(value: Any) -> str | None:
    """sys/metrics uses Go's time format ("2026-10-05 14:53:30 +0000 UTC"); return RFC 3339."""
    try:
        return _iso(datetime.strptime(str(value)[:25], "%Y-%m-%d %H:%M:%S %z"))
    except ValueError:
        return None


def collect_raft(reader: _Reader, coverage: ClusterCoverage) -> dict[str, Any] | None:
    """Integrated storage peers and autopilot; None when the cluster does not use raft."""

    def read(path: str) -> dict[str, Any] | None:
        try:
            return reader.data(path)
        except hvac.exceptions.Forbidden:
            coverage.deny(path)
        except hvac.exceptions.InvalidPath:
            pass
        except hvac.exceptions.InvalidRequest as e:
            if "raft storage is not in use" not in str(e):
                coverage.error(path, e)
        except (hvac.exceptions.VaultError, requests.exceptions.RequestException) as e:
            coverage.error(path, e)
        return None

    config = read("sys/storage/raft/configuration")
    autopilot_config = read("sys/storage/raft/autopilot/configuration")
    state = read("sys/storage/raft/autopilot/state")
    if config is None and autopilot_config is None and state is None:
        return None
    raft: dict[str, Any] = {"peers": None, "autopilot": {"configuration": None, "state": None}}
    if config is not None:
        servers = (config.get("config") or {}).get("servers") or []
        raft["peers"] = [{"node_id": s.get("node_id"), "leader": bool(s.get("leader")), "voter": bool(s.get("voter"))} for s in servers]
    if autopilot_config is not None:
        raft["autopilot"]["configuration"] = {k: autopilot_config.get(k) for k in AUTOPILOT_CONFIG_KEYS if k in autopilot_config}
    if state is not None:
        servers = state.get("servers") or {}
        raft["autopilot"]["state"] = {
            "healthy": state.get("healthy"),
            "failure_tolerance": state.get("failure_tolerance"),
            "leader": state.get("leader"),
            "voters": sorted(state.get("voters") or []),
            "upgrade_status": (state.get("upgrade_info") or {}).get("status"),
            "servers": [{"id": sid, **{k: s.get(k) for k in AUTOPILOT_SERVER_KEYS}} for sid, s in sorted(servers.items())],
        }
    return raft


def collect_audit_devices(reader: _Reader, coverage: ClusterCoverage) -> list[dict[str, Any]] | None:
    """Enabled audit devices (sys/audit needs read+sudo); None when unreadable."""
    try:
        devices = reader.data("sys/audit")
    except hvac.exceptions.Forbidden:
        coverage.deny("sys/audit")
        return None
    except hvac.exceptions.InvalidPath:
        return None
    except (hvac.exceptions.VaultError, requests.exceptions.RequestException) as e:
        coverage.error("sys/audit", e)
        return None
    rows = []
    for path, device in sorted(devices.items()):
        if not isinstance(device, dict) or "type" not in device:
            continue
        raw = device.get("options") if isinstance(device.get("options"), dict) else {}
        options: dict[str, Any] = {k: as_bool(raw[k]) for k in AUDIT_OPTION_FLAGS if k in raw}
        if raw.get("format") in AUDIT_FORMATS:
            options["format"] = raw["format"]
        if device.get("type") == "file":
            options["sink"] = raw.get("file_path") if raw.get("file_path") in AUDIT_FILE_SINKS else "file"
        rows.append({"path": path, "type": device.get("type"), "local": bool(device.get("local")), "options": options})
    return rows


def snapshot_status(status: dict[str, Any]) -> dict[str, Any]:
    """Allowlisted automated-snapshot status: no snapshot URL and no error text."""
    errors = status.get("consecutive_errors")
    times = {k: _iso(t) if (t := parse_time(status[k])) else None for k in SNAPSHOT_TIME_KEYS if status.get(k)}
    scheme = URL_SCHEME.match(str(status.get("last_snapshot_url") or "").lower())
    return {
        "consecutive_errors": errors if isinstance(errors, int) else None,
        **{k: times.get(k) for k in SNAPSHOT_TIME_KEYS},
        "in_progress": bool(status.get("snapshot_start")),
        "storage_scheme": scheme[1] if scheme else None,
    }


def collect_snapshots(reader: _Reader, coverage: ClusterCoverage) -> dict[str, Any] | None:
    """Automated snapshot config names plus each one's status.

    The configs themselves are never read: they return storage credentials in plaintext.
    """
    base = "sys/storage/raft/snapshot-auto"
    try:
        names = reader.list(f"{base}/config")
    except hvac.exceptions.Forbidden:
        coverage.deny(f"{base}/config")
        return None
    except hvac.exceptions.InvalidPath:
        names = []
    except (hvac.exceptions.VaultError, requests.exceptions.RequestException) as e:
        coverage.error(f"{base}/config", e)
        return None
    configs = []
    for name in sorted(names):
        status: dict[str, Any] | None = None
        try:
            status = reader.data(f"{base}/status/{name}")
        except hvac.exceptions.Forbidden:
            coverage.deny(f"{base}/status")
        except hvac.exceptions.InvalidPath:
            status = {}
        except (hvac.exceptions.VaultError, requests.exceptions.RequestException) as e:
            coverage.error(f"{base}/status", e)
        configs.append({"name": name, "status_readable": status is not None, **snapshot_status(status or {})})
    return {"configs": configs}


def _int_or_none(value: Any) -> int | None:
    """Vault returns replication counters as strings ("463")."""
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _peer_summary(peer: dict[str, Any], with_id: bool) -> dict[str, Any]:
    summary: dict[str, Any] = {"node_id": peer.get("node_id")} if with_id else {}
    summary["connection_status"] = peer.get("connection_status")
    if "last_heartbeat" in peer:
        summary["last_heartbeat"] = peer.get("last_heartbeat") or None
    for key in ("clock_skew_ms", "replication_primary_canary_age_ms"):
        if key in peer:
            summary[key] = _int_or_none(peer.get(key))
    return summary


def replication_summary(status: dict[str, Any]) -> dict[str, Any]:
    """Mode, state and per-peer link status; addresses, cluster IDs and merkle roots are dropped."""
    summary: dict[str, Any] = {"mode": status.get("mode"), "state": status.get("state")}
    if status.get("connection_state"):
        summary["connection_state"] = status["connection_state"]
    if "corrupted_merkle_tree" in status:
        summary["corrupted_merkle_tree"] = bool(status["corrupted_merkle_tree"])
    if status.get("mode") == "primary":
        if "last_wal" in status:
            summary["last_wal"] = _int_or_none(status["last_wal"])
        if "known_secondaries" in status:
            summary["known_secondaries"] = list(status.get("known_secondaries") or [])
        summary["secondaries"] = [_peer_summary(s, True) for s in status.get("secondaries") or []]
    elif status.get("mode") == "secondary":
        if "last_remote_wal" in status:
            summary["last_remote_wal"] = _int_or_none(status["last_remote_wal"])
        summary["primaries"] = [_peer_summary(p, False) for p in status.get("primaries") or []]
    return summary


def collect_paths_filters(reader: _Reader, coverage: ClusterCoverage, secondary_ids: list[str]) -> list[dict[str, Any]] | None:
    """Performance paths filters per known secondary; a denial makes the whole list None."""
    base = "sys/replication/performance/primary"
    filters: list[dict[str, Any]] = []
    dynamic_denied = False
    for secondary_id in sorted(secondary_ids):
        try:
            data = reader.data(f"{base}/paths-filter/{secondary_id}")
        except hvac.exceptions.Forbidden:
            coverage.deny(f"{base}/paths-filter")
            return None
        except hvac.exceptions.InvalidPath:
            continue
        except (hvac.exceptions.VaultError, requests.exceptions.RequestException) as e:
            coverage.error(f"{base}/paths-filter", e)
            continue
        if not data or not data.get("mode"):
            continue
        dynamic: int | None = None
        try:
            if not dynamic_denied:
                dynamic = len((reader.data(f"{base}/dynamic-filter/{secondary_id}") or {}).get("dynamic_filtered_mounts") or [])
        except hvac.exceptions.Forbidden:
            dynamic_denied = True
            coverage.deny(f"{base}/dynamic-filter")
        except hvac.exceptions.InvalidPath:
            dynamic = 0
        except (hvac.exceptions.VaultError, requests.exceptions.RequestException) as e:
            coverage.error(f"{base}/dynamic-filter", e)
        filters.append({"secondary_id": secondary_id, "mode": data.get("mode"), "paths": sorted(data.get("paths") or []), "dynamic_filtered_mounts": dynamic})
    return filters


def fetch_system_lease_ttls(vault_client: VaultClient) -> tuple[int, int] | None:
    """(default_lease_ttl, max_lease_ttl) from sys/config/state/sanitized, or None.

    None also when max is 0: that means "unset", and treating it as a baseline
    would make every mount an override.
    """
    try:
        response = vault_client.get("sys/config/state/sanitized")
        payload = response.get("data", response) if isinstance(response, dict) else {}
        default_ttl = payload.get("default_lease_ttl")
        max_ttl = payload.get("max_lease_ttl")
        if isinstance(default_ttl, int) and isinstance(max_ttl, int) and max_ttl > 0:
            logger.debug(f"System lease TTLs: default={default_ttl}s max={max_ttl}s")
            return default_ttl, max_ttl
        logger.debug(f"Unexpected sys/config/state/sanitized payload; lease TTLs unavailable: {payload!r}")
    except Exception as e:
        logger.debug(f"Could not read sys/config/state/sanitized ({e}); lease findings will use the fixed threshold")
    return None


@dataclass
class LicenseResult:
    status: dict[str, Any] | None
    # "denied", "unexpected response" or "error: <message>"; None when collected
    # or when the cluster has no license endpoint at all.
    unavailable_reason: str | None
    # The edition as settled by the probe: a 404 on an unknown edition means
    # Community, a successful read means Enterprise.
    is_enterprise: bool | None


def fetch_license_status(vault_client: VaultClient, is_enterprise: bool | None) -> LicenseResult:
    """Read the active license's "autoloaded" block from sys/license/status.

    An unknown edition is probed rather than skipped: a 404 then identifies
    Community and records nothing. A 404 on a known-Enterprise cluster is an
    error, not a Community signal.
    """
    if is_enterprise is False:
        return LicenseResult(None, None, False)
    try:
        response = vault_client.get("sys/license/status")
    except VaultPermissionError as e:
        logger.debug(f"Permission denied reading sys/license/status ({e}); license data unavailable")
        return LicenseResult(None, "denied", is_enterprise)
    except Exception as e:
        if is_enterprise is None and isinstance(e.__cause__, hvac.exceptions.InvalidPath):
            logger.debug("sys/license/status not found; treating the cluster as Community Edition")
            return LicenseResult(None, None, False)
        logger.debug(f"Could not read sys/license/status ({e}); license data unavailable")
        return LicenseResult(None, f"error: {e}", is_enterprise)

    payload = response.get("data", response) if isinstance(response, dict) else {}
    autoloaded = payload.get("autoloaded") if isinstance(payload, dict) else None
    if isinstance(autoloaded, dict):
        logger.debug("License status collected from sys/license/status")
        return LicenseResult(autoloaded, None, True)
    logger.debug(f"Unexpected sys/license/status payload shape; license data unavailable: {payload!r}")
    return LicenseResult(None, "unexpected response", is_enterprise)
