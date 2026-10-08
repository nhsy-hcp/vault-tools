"""Cluster health rules: one case that fires, the nearest one that must not, and None/unread."""

from datetime import UTC, datetime, timedelta

import pytest

from src.cluster_audit.findings import (
    LEASE_COUNT_WARNING,
    REPL_CLOCK_SKEW_MS,
    audit_device_findings,
    cluster_lease_findings,
    health_findings,
    metric_findings,
    snapshot_findings,
)

NOW = datetime(2026, 9, 21, 12, 0, tzinfo=UTC)


def _ids(findings):
    return sorted(f.rule_id for f in findings)


def _health(**overrides):
    base = {"version": "1.20.1+ent", "sealed": False, "leader": {"ha_enabled": True, "leader_address_present": True}, "server_time_utc": int(NOW.timestamp())}
    base.update(overrides)
    return base


class TestNodeAndVersion:
    def test_sealed_node(self):
        assert _ids(health_findings(_health(sealed=True))) == ["VT-HLTH-001"]

    def test_ha_without_leader(self):
        [f] = health_findings(_health(leader={"ha_enabled": True, "leader_address_present": False}))
        assert f.rule_id == "VT-HLTH-001" and "no active leader" in f.detail

    def test_healthy_node_raises_nothing(self):
        assert health_findings(_health()) == []

    def test_old_version(self):
        [f] = health_findings(_health(version="1.15.2"))
        assert f.rule_id == "VT-HLTH-003"

    def test_none_and_empty_health_are_not_judged(self):
        assert health_findings(None) == [] and health_findings({}) == []


class TestReplication:
    def _repl(self, **dr):
        return _health(replication={"dr": {"mode": "primary", "state": "running", **dr}, "performance": {"mode": "disabled"}})

    def test_unhealthy_state(self):
        assert _ids(health_findings(self._repl(state="idle-ish", secondaries=[]))) == ["VT-HLTH-002"]

    def test_never_connected_secondary(self):
        found = health_findings(self._repl(secondaries=[{"node_id": "dr-1", "connection_status": "disconnected"}]))
        assert _ids(found) == ["VT-HLTH-002", "VT-REPL-002"]

    def test_lagging_canary(self):
        peer = {"node_id": "dr-1", "connection_status": "connected", "last_heartbeat": NOW.isoformat(), "replication_primary_canary_age_ms": 120_000}
        assert _ids(health_findings(self._repl(secondaries=[peer]))) == ["VT-REPL-001"]

    def test_stale_heartbeat_uses_the_node_clock(self):
        peer = {"node_id": "dr-1", "connection_status": "connected", "last_heartbeat": (NOW - timedelta(minutes=5)).isoformat()}
        [f] = health_findings(self._repl(secondaries=[peer]))
        assert f.rule_id == "VT-REPL-001" and f.evidence["heartbeat_age_seconds"] == 300

    def test_clock_skew(self):
        peer = {"node_id": "dr-1", "connection_status": "connected", "last_heartbeat": NOW.isoformat(), "clock_skew_ms": REPL_CLOCK_SKEW_MS + 1}
        assert _ids(health_findings(self._repl(secondaries=[peer]))) == ["VT-REPL-003"]

    def test_corrupted_merkle_tree_is_high(self):
        [f] = health_findings(self._repl(corrupted_merkle_tree=True, secondaries=[]))
        assert (f.rule_id, f.severity) == ("VT-REPL-004", "High")

    def test_paths_filter(self):
        flt = {"secondary_id": "pr-1", "mode": "deny", "paths": ["team-a/"], "dynamic_filtered_mounts": 0}
        health = _health(replication={"dr": {"mode": "disabled"}, "performance": {"mode": "primary", "state": "running", "secondaries": [], "paths_filters": [flt]}})
        assert _ids(health_findings(health)) == ["VT-REPL-005"]

    def test_dr_and_performance_findings_have_distinct_fingerprints(self):
        health = _health(
            replication={
                "dr": {"mode": "primary", "state": "running", "corrupted_merkle_tree": True},
                "performance": {"mode": "primary", "state": "running", "corrupted_merkle_tree": True},
            }
        )
        prints = {f.fingerprint for f in health_findings(health)}
        assert len(prints) == 2


class TestRaft:
    def test_unhealthy_server(self):
        raft = {"autopilot": {"state": {"healthy": True, "failure_tolerance": 1, "servers": [{"id": "n2", "healthy": False}]}}}
        [f] = health_findings(_health(raft=raft))
        assert f.rule_id == "VT-HLTH-004" and f.evidence["unhealthy_servers"] == ["n2"]


class TestMetrics:
    def test_irrevocable_and_lease_count(self):
        assert _ids(metric_findings({"irrevocable_leases": 3, "leases": LEASE_COUNT_WARNING + 1})) == ["VT-HLTH-005", "VT-HLTH-006"]

    def test_standby_without_gauges_is_not_judged(self):
        assert metric_findings({"irrevocable_leases": None, "leases": None}) == []
        assert metric_findings(None) == []

    def test_threshold_itself_does_not_fire(self):
        assert metric_findings({"leases": LEASE_COUNT_WARNING}) == []


class TestAuditDevices:
    def test_none_enabled(self):
        assert _ids(audit_device_findings([])) == ["VT-AUD-001"]

    def test_single_device(self):
        [f] = audit_device_findings([{"path": "file/", "type": "file", "options": {}}])
        assert f.rule_id == "VT-AUD-002" and f.evidence["device_path"] == "file/"

    def test_two_devices_are_fine(self):
        assert audit_device_findings([{"path": "a/", "type": "file", "options": {}}, {"path": "b/", "type": "socket", "options": {}}]) == []

    @pytest.mark.parametrize("options", [{"log_raw": True}, {"hmac_accessor": False}])
    def test_unsafe_options(self, options):
        devices = [{"path": "a/", "type": "file", "options": options}, {"path": "b/", "type": "socket", "options": {}}]
        assert _ids(audit_device_findings(devices)) == ["VT-AUD-003"]

    def test_unreadable_is_not_judged(self):
        assert audit_device_findings(None) == []


class TestSnapshots:
    def _cfg(self, **overrides):
        cfg = {"name": "daily", "consecutive_errors": 0, "last_snapshot_start": "2026-09-20T12:00:00Z", "next_snapshot_start": "2026-09-21T12:00:00Z", "storage_scheme": "s3"}
        cfg.update(overrides)
        return cfg

    def test_none_configured(self):
        assert _ids(snapshot_findings({"configs": []}, NOW)) == ["VT-SNAP-001"]

    def test_failing(self):
        assert _ids(snapshot_findings({"configs": [self._cfg(consecutive_errors=2)]}, NOW)) == ["VT-SNAP-002"]

    def test_overdue_past_the_grace_period(self):
        [f] = snapshot_findings({"configs": [self._cfg()]}, NOW + timedelta(hours=30))
        assert f.rule_id == "VT-SNAP-002" and f.evidence["overdue_seconds"] > 0

    def test_late_within_grace_is_fine(self):
        assert snapshot_findings({"configs": [self._cfg()]}, NOW + timedelta(hours=20)) == []

    def test_local_disk(self):
        assert _ids(snapshot_findings({"configs": [self._cfg(storage_scheme="file")]}, NOW)) == ["VT-SNAP-003"]

    def test_not_judged_when_none(self):
        assert snapshot_findings(None, NOW) == []


def test_cluster_lease_finding():
    assert _ids(cluster_lease_findings(2000 * 3600)) == ["VT-LEASE-001"]
    assert cluster_lease_findings(None) == [] and cluster_lease_findings(0) == []
