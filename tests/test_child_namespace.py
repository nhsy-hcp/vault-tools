"""Child-namespace tokens and HCP Vault Dedicated, as the vault-ops skill handles them.

A token created in a child namespace (HCP Vault Dedicated issues only ``admin/``
tokens) cannot read root-only cluster data. Those blocks are skipped by design:
never denials, never findings, and the reports say why.
"""

from datetime import UTC, datetime
from unittest.mock import Mock, patch

import pytest

from src.activity_export.findings import activity_paths_are_full, scope_activity, usage_findings
from src.activity_export.main import _read_optional
from src.cluster_audit.collector import CHILD_NAMESPACE_REASON, collect_cluster_health, fetch_license_status, fetch_system_lease_ttls
from src.cluster_audit.report import render_cluster_health, render_license, scoped_note
from src.common import vault_http
from src.common.exceptions import VaultPermissionError
from src.common.findings import run_block
from src.common.vault_client import VaultClient, detect_platform
from tests.cluster_audit.fakes import enterprise_routes, fake_vault_client
from tests.common.test_vault_client import make_response, route

NOW = datetime(2026, 11, 6, tzinfo=UTC)


def _scoped(routes, token_ns="admin/", platform="enterprise"):
    client = fake_vault_client(routes)
    client.token_namespace = token_ns
    client.platform = platform
    client.scoped = bool(token_ns)
    return client


class TestDetectPlatform:
    @pytest.mark.parametrize(
        ("addr", "version", "expected"),
        [
            ("https://vault-cluster-public-vault-abc123.def456.z1.hashicorp.cloud:8200", "1.20.1+ent", "hcp"),
            ("https://VAULT.Z1.HASHICORP.CLOUD", None, "hcp"),
            ("https://vault.example.com:8200", "1.20.1+ent", "enterprise"),
            ("https://vault.example.com:8200", "1.20.1", "community"),
            ("https://vault.example.com:8200", None, None),
            ("https://hashicorp.cloud.example.com", "1.20.1", "community"),
            ("not a url", "", None),
        ],
    )
    def test_host_decides_first_then_edition(self, addr, version, expected):
        assert detect_platform(addr, version) == expected


class TestTokenNamespace:
    @pytest.fixture
    def client(self):
        return VaultClient("https://vault.example.com", "tok", namespace="admin")

    def _validate(self, client, namespace_path):
        health = {"cluster_name": "c", "cluster_id": "d33099d9", "sealed": False, "initialized": True, "version": "1.20.1+ent"}
        responses = {
            "/v1/sys/health": make_response(200, health),
            "/v1/auth/token/lookup-self": make_response(200, {"data": {"namespace_path": namespace_path}}),
        }
        with patch.object(client.session, "request", side_effect=route(responses)) as request:
            return client.validate_connection(), request

    def test_start_namespace_is_normalised(self, client):
        assert client.namespace == "admin/"
        assert VaultClient("https://v", "t", namespace="/").namespace == ""
        assert VaultClient("https://v", "t").namespace == ""

    def test_lookup_self_runs_in_the_start_namespace(self, client):
        _, request = self._validate(client, "admin/")
        lookup = [c for c in request.call_args_list if c.kwargs["url"].endswith("lookup-self")][0]
        assert lookup.kwargs["headers"]["X-Vault-Namespace"] == "admin/"

    def test_token_namespace_and_platform_are_recorded(self, client):
        info, _ = self._validate(client, "admin/")
        assert info.token_namespace == "admin/" and client.token_namespace == "admin/" and client.scoped
        assert info.platform == "enterprise" == client.platform

    def test_root_token_is_not_scoped(self, client):
        info, _ = self._validate(client, "")
        assert info.token_namespace == "" and not client.scoped

    def test_rejected_token_names_vault_namespace(self, client):
        responses = {
            "/v1/sys/health": make_response(200, {"initialized": True, "sealed": False, "version": "1.20.1+ent"}),
            "/v1/auth/token/lookup-self": make_response(403, {"errors": ["permission denied"]}),
        }
        from src.common.exceptions import VaultConnectionError

        with patch.object(client.session, "request", side_effect=route(responses)), pytest.raises(VaultConnectionError, match="VAULT_NAMESPACE"):
            client.validate_connection()


class TestScopedClusterHealth:
    def test_root_only_blocks_are_skipped_without_gaps(self):
        client = _scoped(enterprise_routes())
        health, coverage = collect_cluster_health(client)
        for block in ("raft", "audit_devices", "snapshots", "metrics"):
            assert health[block] is None, block
        assert health["leader"] is not None and health["replication"] is not None
        assert coverage.complete
        assert not {c for c in client.fake.calls if c.startswith(("sys/storage", "sys/audit", "sys/metrics"))}
        assert health["token_namespace"] == "admin/"

    def test_denied_cluster_status_is_not_a_gap_when_scoped(self):
        denied = vault_http.Forbidden()
        client = _scoped(enterprise_routes(**{"sys/leader": denied, "sys/replication/status": denied}))
        health, coverage = collect_cluster_health(client)
        assert health["leader"] is None and coverage.complete

    def test_denied_cluster_status_is_still_a_gap_for_a_root_token(self):
        client = fake_vault_client(enterprise_routes(**{"sys/leader": vault_http.Forbidden()}))
        _, coverage = collect_cluster_health(client)
        assert "sys/leader" in coverage.denied

    def test_hcp_reads_seal_status_in_the_token_namespace(self):
        routes = enterprise_routes(**{"sys/seal-status": {"type": "awskms", "t": 1, "n": 1, "progress": 0, "migration": False, "recovery_seal": True, "nonce": "x"}})
        client = _scoped(routes, platform="hcp")
        health, coverage = collect_cluster_health(client)
        assert health["seal"] == {"type": "awskms", "t": 1, "n": 1, "progress": 0, "migration": False, "recovery_seal": True}
        assert health["metrics"] is None and coverage.complete
        assert any(c.args and c.args[0] == "admin/" for c in client.get_client.call_args_list)

    def test_hcp_seal_status_denial_is_not_a_gap(self):
        client = _scoped(enterprise_routes(**{"sys/seal-status": vault_http.Forbidden()}), platform="hcp")
        health, coverage = collect_cluster_health(client)
        assert health["seal"] is None and coverage.complete

    def test_licence_and_lease_ttls_are_not_read(self):
        client = _scoped({})
        client.get = Mock(side_effect=AssertionError("must not be read"))
        result = fetch_license_status(client, True)
        assert result.status is None and result.unavailable_reason == CHILD_NAMESPACE_REASON
        assert fetch_system_lease_ttls(client) is None


class TestReports:
    def test_scoped_note_is_never_about_permissions(self):
        note = scoped_note({"token_namespace": "admin/", "platform": "enterprise"})
        assert "root-namespace administrators" in note and "permission" not in note.lower()

    def test_hcp_note_points_at_the_portal(self):
        assert "HCP portal" in scoped_note({"token_namespace": "admin/", "platform": "hcp"})

    def test_root_token_has_no_note(self):
        assert scoped_note({"token_namespace": ""}) == "" and scoped_note(None) == ""

    def test_health_section_replaces_root_only_blocks_with_the_note(self):
        health, _ = collect_cluster_health(_scoped(enterprise_routes()))
        section = render_cluster_health(health)
        assert "Not reviewed" in section and "Audit devices" not in section and "Replication" in section

    def test_licence_note(self):
        assert "child namespace" in render_license(None, True, CHILD_NAMESPACE_REASON)


class TestRunBlock:
    def test_new_fields(self):
        block = run_block("c", "https://v", "admin/", NOW, NOW, token_namespace="admin/", platform="hcp")
        assert block["start_namespace"] == "admin/" and block["token_namespace"] == "admin/" and block["platform"] == "hcp"

    def test_root_and_unvalidated(self):
        assert run_block("c", "https://v", "", NOW, NOW, token_namespace="")["token_namespace"] == "/"
        assert run_block("c", "https://v", "", NOW, NOW)["token_namespace"] is None


class TestActivityScope:
    def _payload(self, *paths):
        return {"by_namespace": [{"namespace_path": p, "counts": {"clients": 10}} for p in paths]}

    def test_relative_rows_are_made_full(self):
        scoped = scope_activity(self._payload("", "team-a/"), "admin/")
        assert [r["namespace_path"] for r in scoped["by_namespace"]] == ["admin/", "admin/team-a/"]

    def test_full_rows_are_kept(self):
        payload = self._payload("admin/", "admin/team-a/")
        assert activity_paths_are_full(payload, "admin/")
        assert [r["namespace_path"] for r in scope_activity(payload, "admin/")["by_namespace"]] == ["admin/", "admin/team-a/"]

    def test_a_namesake_descendant_is_not_merged(self):
        """`admin/admin/` read as relative (a root row is present) stays a descendant."""
        scoped = scope_activity(self._payload("", "admin/"), "admin/")
        assert [r["namespace_path"] for r in scoped["by_namespace"]] == ["admin/", "admin/admin/"]

    def test_months_and_new_clients_are_scoped(self):
        payload = {"months": [{"namespaces": [{"namespace_path": "x/"}], "new_clients": {"namespaces": [{"namespace_path": ""}]}}]}
        month = scope_activity(payload, "admin/")["months"][0]
        assert month["namespaces"][0]["namespace_path"] == "admin/x/"
        assert month["new_clients"]["namespaces"][0]["namespace_path"] == "admin/"

    def test_root_is_a_no_op(self):
        payload = self._payload("", "a/")
        assert scope_activity(payload, "") is payload

    def test_cli_004_judges_the_token_namespace_as_the_top(self):
        activity = {"total": {"clients": 100}, "by_namespace": [{"namespace_path": "admin/", "counts": {"clients": 90}}, {"namespace_path": "admin/a/", "counts": {"clients": 10}}]}
        [f] = [f for f in usage_findings(activity, None, True, None, "admin/") if f.rule_id == "VT-CLI-004"]
        assert f.namespace == "admin/" and "the top namespace this token sees" in f.detail


class TestActivityConfig:
    def _client(self, error):
        client = Mock()
        client.token_namespace = "admin/"
        client.get.side_effect = error
        return client

    def test_scoped_config_denial_is_not_a_gap(self):
        denied, errors = [], []
        assert _read_optional(self._client(VaultPermissionError("no")), "sys/internal/counters/config", denied, errors) is None
        assert denied == [] and errors == []

    def test_scoped_monthly_denial_is_a_gap_in_the_token_namespace(self):
        denied, errors = [], []
        _read_optional(self._client(VaultPermissionError("no")), "sys/internal/counters/activity/monthly", denied, errors)
        assert denied == [("admin/", "sys/internal/counters/activity/monthly")]

    def test_reads_in_the_token_namespace(self):
        client = self._client(None)
        client.get.side_effect = None
        client.get.return_value = {"data": {"enabled": "enable"}}
        _read_optional(client, "sys/internal/counters/config", [], [])
        assert client.get.call_args.kwargs["namespace"] == "admin/"


class TestSentinelNotLicensed:
    def test_401_feature_not_enabled_means_unsupported(self):
        from src.namespace_audit.main import NamespaceAuditor
        from tests.namespace_audit.fixtures import make_vault_client_mock

        fake = make_vault_client_mock()
        fake.at("list", "sys/policies/egp").side_effect = vault_http.Unauthorized("1 error occurred:\n\t* feature not enabled\n\n")
        auditor = NamespaceAuditor(Mock(spec=VaultClient), worker_threads=1, output_dir="unused")
        assert auditor._list_and_read(fake, "egp", "root") == {}
        assert auditor.sentinel_supported is False
        assert auditor.stats.errors == []

    def test_other_401_is_an_error(self):
        from src.namespace_audit.main import NamespaceAuditor
        from tests.namespace_audit.fixtures import make_vault_client_mock

        fake = make_vault_client_mock()
        fake.at("list", "sys/policies/egp").side_effect = vault_http.Unauthorized("missing client token")
        auditor = NamespaceAuditor(Mock(spec=VaultClient), worker_threads=1, output_dir="unused")
        assert auditor._list_and_read(fake, "egp", "root") == {}
        assert auditor.sentinel_supported is None and len(auditor.stats.errors) == 1


class TestCli:
    def test_flag_wins_over_vault_namespace(self, monkeypatch):
        import main as cli

        monkeypatch.setenv("VAULT_ADDR", "https://v")
        monkeypatch.setenv("VAULT_TOKEN", "t")
        monkeypatch.setenv("VAULT_NAMESPACE", "env-ns")
        assert cli.create_vault_client(Mock()).namespace == "env-ns/"
        assert cli.create_vault_client(Mock(), "flag-ns").namespace == "flag-ns/"
        assert cli.create_vault_client(Mock(), "").namespace == ""

    def test_every_vault_subcommand_takes_namespace(self):
        import main as cli

        parser = cli.build_parser()
        for command in ("namespace-audit", "cluster-audit", "identity-audit", "activity-export", "entity-export", "full-audit"):
            assert parser.parse_args([command, "--namespace", "admin"]).namespace == "admin", command
