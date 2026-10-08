"""A fake Vault for the cluster collector: each path maps to a response or an exception."""

from contextlib import contextmanager
from typing import Any
from unittest.mock import Mock

import hvac

HEALTHY = {
    "initialized": True,
    "sealed": False,
    "standby": False,
    "performance_standby": False,
    "replication_dr_mode": "disabled",
    "replication_performance_mode": "disabled",
    "server_time_utc": 1790000000,
    "version": "1.20.1+ent",
    "cluster_name": "vault-cluster-test",
}


class FakeAdapter:
    def __init__(self, routes: dict[str, Any]):
        self.routes = routes
        self.calls: list[str] = []

    def get(self, url: str, params: dict | None = None):
        path = url.removeprefix("/v1/")
        self.calls.append(path)
        if path not in self.routes:
            raise hvac.exceptions.InvalidPath()
        value = self.routes[path]
        if isinstance(value, BaseException):
            raise value
        return value


def fake_vault_client(routes: dict[str, Any], vault_addr: str = "https://vault.example.com:8200") -> Mock:
    """A VaultClient whose get_client() yields an hvac client backed by ``routes``."""
    adapter = FakeAdapter(routes)
    hvac_client = Mock()
    hvac_client.adapter = adapter

    @contextmanager
    def get_client(*_args, **_kwargs):
        yield hvac_client

    client = Mock()
    client.vault_addr = vault_addr
    client.get_client.side_effect = get_client
    client.adapter = adapter
    return client


def enterprise_routes(**overrides: Any) -> dict[str, Any]:
    """A healthy Enterprise raft cluster with two audit devices and a working snapshot."""
    routes: dict[str, Any] = {
        "sys/health": dict(HEALTHY),
        "sys/leader": {"ha_enabled": True, "is_self": True, "leader_address": "https://10.0.0.1:8200", "raft_committed_index": 42},
        "sys/replication/status": {
            "data": {
                "dr": {"mode": "disabled"},
                "performance": {"mode": "disabled"},
            }
        },
        "sys/storage/raft/configuration": {"data": {"config": {"servers": [{"node_id": "node1", "address": "10.0.0.1:8201", "leader": True, "voter": True}]}}},
        "sys/storage/raft/autopilot/configuration": {"data": {"cleanup_dead_servers": False, "last_contact_threshold": "10s"}},
        "sys/storage/raft/autopilot/state": {
            "data": {
                "healthy": True,
                "failure_tolerance": 0,
                "leader": "node1",
                "voters": ["node1"],
                "servers": {"node1": {"status": "leader", "healthy": True, "last_contact": "0s", "address": "10.0.0.1:8201"}},
            }
        },
        "sys/audit": {
            "data": {
                "file/": {"type": "file", "options": {"file_path": "/var/log/vault/audit.log", "format": "json"}, "local": False},
                "socket/": {"type": "socket", "options": {"address": "10.0.0.9:9090", "hmac_accessor": "true"}, "local": False},
            }
        },
        "sys/storage/raft/snapshot-auto/config": {"data": {"keys": ["daily"]}},
        "sys/storage/raft/snapshot-auto/status/daily": {
            "data": {
                "consecutive_errors": 0,
                "last_snapshot_start": "2026-09-21T12:00:00Z",
                "last_snapshot_end": "2026-09-21T12:00:05Z",
                "next_snapshot_start": "2026-09-22T12:00:00Z",
                "last_snapshot_url": "s3://bucket/path/snap.db",
                "last_snapshot_error": "secret error text",
            }
        },
        "sys/metrics": {
            "Timestamp": "2026-09-21 12:00:00 +0000 UTC",
            "Gauges": [
                {"Name": "vault.expire.num_leases", "Value": 120.0, "Labels": {"cluster": "secret-name"}},
                {"Name": "vault.core.in_flight_requests", "Value": 2, "Labels": {}},
                {"Name": "vault.core.in_flight_requests", "Value": 3, "Labels": {}},
            ],
        },
    }
    routes.update(overrides)
    return routes
