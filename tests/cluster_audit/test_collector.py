"""collect_cluster_health against a fake Vault: node states, denials and the allowlists."""

import json

import hvac

from src.cluster_audit.collector import collect_cluster_health, fetch_license_status, unauthenticated_only
from tests.cluster_audit.fakes import HEALTHY, enterprise_routes, fake_vault_client


def _collect(routes, health_status=None):
    client = fake_vault_client(routes)
    health, coverage = collect_cluster_health(client, health_status)
    return health, coverage, client.adapter.calls


class TestNodeStates:
    def test_healthy_enterprise_cluster_fills_every_block(self):
        health, coverage, _ = _collect(enterprise_routes())
        assert coverage.complete
        assert health["enterprise"] is True
        assert health["leader"]["leader_address_present"] is True
        assert health["raft"]["peers"] == [{"node_id": "node1", "leader": True, "voter": True}]
        assert health["audit_devices"] and health["snapshots"] and health["metrics"]

    def test_sealed_node_reads_only_seal_status(self):
        routes = {
            "sys/health": {**HEALTHY, "sealed": True},
            "sys/seal-status": {"type": "shamir", "t": 3, "n": 5, "progress": 1, "migration": False, "recovery_seal": False, "nonce": "x"},
        }
        health, coverage, calls = _collect(routes)
        assert calls == ["sys/health", "sys/seal-status"]
        assert health["seal"] == {"type": "shamir", "t": 3, "n": 5, "progress": 1, "migration": False, "recovery_seal": False}
        assert health["audit_devices"] is None and health["leader"] is None
        assert coverage.complete

    def test_dr_secondary_skips_authenticated_reads(self):
        routes = enterprise_routes()
        routes["sys/health"] = {**HEALTHY, "replication_dr_mode": "secondary"}
        health, _, calls = _collect(routes)
        assert health["dr_secondary"] is True
        assert "sys/audit" not in calls and "sys/metrics" not in calls
        assert health["raft"] is None and health["audit_devices"] is None

    def test_unauthenticated_only_reasons(self):
        assert unauthenticated_only({"initialized": False}) == "uninitialized"
        assert unauthenticated_only({"sealed": True}) == "sealed"
        assert unauthenticated_only({"replication_dr_mode": "secondary"}) == "dr_secondary"
        assert unauthenticated_only(HEALTHY) is None

    def test_community_without_raft_skips_snapshots(self):
        routes = {"sys/health": {**HEALTHY, "version": "2.1.1"}, "sys/audit": {"data": {}}}
        health, coverage, calls = _collect(routes)
        assert health["enterprise"] is False
        assert health["raft"] is None and health["snapshots"] is None
        assert not any("snapshot-auto" in c for c in calls)
        assert health["audit_devices"] == []
        assert coverage.complete

    def test_health_status_in_hand_is_not_re_read(self):
        _, _, calls = _collect(enterprise_routes(), health_status=dict(HEALTHY))
        assert "sys/health" not in calls


class TestCoverage:
    def test_denials_are_recorded_by_endpoint_and_leave_the_block_none(self):
        routes = enterprise_routes(**{"sys/audit": hvac.exceptions.Forbidden(), "sys/metrics": hvac.exceptions.Forbidden()})
        health, coverage, _ = _collect(routes)
        assert health["audit_devices"] is None and health["metrics"] is None
        assert coverage.denied == ["sys/audit", "sys/metrics"]

    def test_errors_keep_only_the_class_and_status(self):
        routes = enterprise_routes(**{"sys/leader": hvac.exceptions.InternalServerError("boom at https://internal-host:8200/v1/sys/leader")})
        _, coverage, _ = _collect(routes)
        assert coverage.errors == [("sys/leader", "InternalServerError")]

    def test_raft_not_in_use_is_not_an_error(self):
        routes = enterprise_routes()
        for path in ("sys/storage/raft/configuration", "sys/storage/raft/autopilot/configuration", "sys/storage/raft/autopilot/state"):
            routes[path] = hvac.exceptions.InvalidRequest("raft storage is not in use")
        health, coverage, _ = _collect(routes)
        assert health["raft"] is None
        assert coverage.complete

    def test_collector_never_raises(self):
        client = fake_vault_client({})
        client.get_client.side_effect = RuntimeError("no client")
        health, coverage = collect_cluster_health(client)
        assert health["audit_devices"] is None
        assert coverage.errors


class TestAllowlists:
    def test_no_address_path_or_secret_reaches_the_output(self):
        health, _, _ = _collect(enterprise_routes())
        dumped = json.dumps(health)
        for leaked in ("10.0.0.1", "10.0.0.9", "/var/log/vault", "s3://bucket", "secret error text", "secret-name"):
            assert leaked not in dumped

    def test_audit_options_are_reduced(self):
        health, _, _ = _collect(enterprise_routes())
        by_path = {d["path"]: d for d in health["audit_devices"]}
        assert by_path["file/"]["options"] == {"format": "json", "sink": "file"}
        assert by_path["socket/"]["options"] == {"hmac_accessor": True}

    def test_snapshot_configs_are_listed_never_read(self):
        health, _, calls = _collect(enterprise_routes())
        assert "sys/storage/raft/snapshot-auto/config/daily" not in calls
        assert health["snapshots"]["configs"][0]["storage_scheme"] == "s3"

    def test_metrics_aggregate_and_drop_labels(self):
        health, _, _ = _collect(enterprise_routes())
        metrics = health["metrics"]
        assert metrics["leases"] == 120
        assert metrics["in_flight_requests"] == 5
        assert metrics["irrevocable_leases"] is None
        assert metrics["timestamp"] == "2026-09-21T12:00:00Z"

    def test_replication_peers_keep_link_status_only(self):
        routes = enterprise_routes(
            **{
                "sys/replication/status": {
                    "data": {
                        "dr": {
                            "mode": "primary",
                            "state": "running",
                            "cluster_id": "secret-cluster-id",
                            "last_wal": "463",
                            "known_secondaries": ["dr-1"],
                            "secondaries": [{"node_id": "dr-1", "api_address": "https://10.1.1.1:8200", "connection_status": "connected", "clock_skew_ms": "12"}],
                        },
                        "performance": {"mode": "disabled"},
                    }
                }
            }
        )
        health, _, _ = _collect(routes)
        dr = health["replication"]["dr"]
        assert dr["last_wal"] == 463
        assert dr["secondaries"] == [{"node_id": "dr-1", "connection_status": "connected", "clock_skew_ms": 12}]
        assert "secret-cluster-id" not in json.dumps(health)


class TestLicense:
    def _client(self, response=None, error=None):
        client = fake_vault_client({})
        client.get = lambda path: (_ for _ in ()).throw(error) if error else response
        return client

    def test_community_is_not_probed(self):
        client = fake_vault_client({})
        assert fetch_license_status(client, False).status is None
        client.get.assert_not_called()

    def test_success_settles_enterprise(self):
        result = fetch_license_status(self._client({"data": {"autoloaded": {"license_id": "x"}}}), None)
        assert (result.status, result.is_enterprise, result.unavailable_reason) == ({"license_id": "x"}, True, None)

    def test_unexpected_shape_is_reported(self):
        assert fetch_license_status(self._client({"data": {}}), True).unavailable_reason == "unexpected response"


class TestPathsFilters:
    def _routes(self, **extra):
        routes = enterprise_routes(
            **{
                "sys/replication/status": {
                    "data": {
                        "dr": {"mode": "disabled"},
                        "performance": {"mode": "primary", "state": "running", "known_secondaries": ["pr-1", "pr-2"], "secondaries": []},
                    }
                },
                "sys/replication/performance/primary/paths-filter/pr-1": {"data": {"mode": "deny", "paths": ["team-b/", "team-a/"]}},
                "sys/replication/performance/primary/dynamic-filter/pr-1": {"data": {"dynamic_filtered_mounts": ["a", "b"]}},
            }
        )
        routes.update(extra)
        return routes

    def test_filters_are_read_per_known_secondary(self):
        health, coverage, _ = _collect(self._routes())
        assert health["replication"]["performance"]["paths_filters"] == [{"secondary_id": "pr-1", "mode": "deny", "paths": ["team-a/", "team-b/"], "dynamic_filtered_mounts": 2}]
        assert coverage.complete

    def test_denied_filter_read_makes_the_list_none(self):
        health, coverage, _ = _collect(self._routes(**{"sys/replication/performance/primary/paths-filter/pr-1": hvac.exceptions.Forbidden()}))
        assert health["replication"]["performance"]["paths_filters"] is None
        assert coverage.denied == ["sys/replication/performance/primary/paths-filter"]

    def test_denied_dynamic_filter_is_recorded_once(self):
        health, coverage, _ = _collect(self._routes(**{"sys/replication/performance/primary/dynamic-filter/pr-1": hvac.exceptions.Forbidden()}))
        assert health["replication"]["performance"]["paths_filters"][0]["dynamic_filtered_mounts"] is None
        assert coverage.denied == ["sys/replication/performance/primary/dynamic-filter"]


class TestLicenseFailures:
    def _raising(self, exc):
        client = fake_vault_client({})
        client.get.side_effect = exc
        return client

    def test_denied(self):
        from src.common.exceptions import VaultPermissionError

        result = fetch_license_status(self._raising(VaultPermissionError("no")), True)
        assert (result.status, result.unavailable_reason, result.is_enterprise) == (None, "denied", True)

    def test_404_on_unknown_edition_means_community(self):
        from src.common.exceptions import VaultAPIError

        error = VaultAPIError("Invalid path")
        error.__cause__ = hvac.exceptions.InvalidPath()
        result = fetch_license_status(self._raising(error), None)
        assert (result.unavailable_reason, result.is_enterprise) == (None, False)

    def test_404_on_known_enterprise_is_an_error(self):
        from src.common.exceptions import VaultAPIError

        error = VaultAPIError("Invalid path")
        error.__cause__ = hvac.exceptions.InvalidPath()
        result = fetch_license_status(self._raising(error), True)
        assert result.unavailable_reason.startswith("error: ")


class TestLeaseTtls:
    def test_unset_max_is_none(self):
        from src.cluster_audit.collector import fetch_system_lease_ttls

        client = fake_vault_client({})
        client.get.return_value = {"data": {"default_lease_ttl": 0, "max_lease_ttl": 0}}
        assert fetch_system_lease_ttls(client) is None
        client.get.return_value = {"data": {"default_lease_ttl": 3600, "max_lease_ttl": 7200}}
        assert fetch_system_lease_ttls(client) == (3600, 7200)
