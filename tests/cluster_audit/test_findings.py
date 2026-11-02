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

    def test_never_connected_secondary_is_reported_once(self):
        """VT-REPL-002 alone: a second, higher-severity VT-HLTH-002 for the same peer double-counted it."""
        found = health_findings(self._repl(secondaries=[{"node_id": "dr-1", "connection_status": "disconnected"}]))
        assert _ids(found) == ["VT-REPL-002"]

    def test_a_down_secondary_with_a_heartbeat_is_still_unhealthy(self):
        peer = {"node_id": "dr-1", "connection_status": "disconnected", "last_heartbeat": NOW.isoformat()}
        [f] = health_findings(self._repl(secondaries=[peer]))
        assert f.rule_id == "VT-HLTH-002" and f.evidence["disconnected_peers"] == ["dr-1"]

    def test_lagging_canary(self):
        peer = {"node_id": "dr-1", "connection_status": "connected", "last_heartbeat": NOW.isoformat(), "replication_primary_canary_age_ms": 120_000}
        assert _ids(health_findings(self._repl(secondaries=[peer]))) == ["VT-REPL-001"]

    @pytest.mark.parametrize("canary_ms", [15, 1007])
    def test_idle_primary_canary_is_not_lag(self, canary_ms):
        """Measured on the dev stack (Vault 2.1, 2026-11-02): Vault refreshes the canary
        itself about once a second, so on an idle primary its age cycles 0-1,007 ms and the
        primary's last_wal keeps climbing with no client writes. A canary past 60s
        therefore means the stream is not arriving, not that nobody wrote."""
        peer = {"node_id": "dr-1", "connection_status": "connected", "last_heartbeat": (NOW - timedelta(seconds=5)).isoformat(), "replication_primary_canary_age_ms": canary_ms}
        assert health_findings(self._repl(secondaries=[peer])) == []

    @pytest.mark.parametrize(("mode", "state"), [("primary", "running"), ("secondary", "stream-wals")])
    def test_states_seen_through_a_reindex_are_healthy(self, mode, state):
        """Measured on the dev stack: reindexing the primary or a performance secondary left
        every node in running/stream-wals; merkle-diff/merkle-sync did not appear there."""
        replication = {"dr": {"mode": mode, "state": state, "secondaries": [], "primaries": []}, "performance": {"mode": "disabled"}}
        assert health_findings(_health(replication=replication)) == []

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

    def test_running_snapshot_is_not_overdue(self):
        """A long run has started; judging it overdue was a false alarm."""
        assert snapshot_findings({"configs": [self._cfg(in_progress=True)]}, NOW + timedelta(hours=30)) == []

    def test_failing_snapshot_fires_while_running(self):
        [f] = snapshot_findings({"configs": [self._cfg(in_progress=True, consecutive_errors=1)]}, NOW + timedelta(hours=30))
        assert f.rule_id == "VT-SNAP-002" and f.evidence["consecutive_errors"] == 1

    def test_local_disk(self):
        assert _ids(snapshot_findings({"configs": [self._cfg(storage_scheme="file")]}, NOW)) == ["VT-SNAP-003"]

    def test_not_judged_when_none(self):
        assert snapshot_findings(None, NOW) == []


def test_cluster_lease_finding():
    assert _ids(cluster_lease_findings(2000 * 3600)) == ["VT-LEASE-001"]
    assert cluster_lease_findings(None) == [] and cluster_lease_findings(0) == []


@pytest.mark.parametrize("value", [0, -1, True, "1793620800", None])
def test_unusable_server_time_falls_back_to_our_clock(value):
    """bool is an int: True must not become 1970-01-01T00:00:01."""
    from src.cluster_audit.findings import reference_time, server_time

    assert server_time({"server_time_utc": value}) is None
    assert reference_time({"server_time_utc": value}).year >= 2026
