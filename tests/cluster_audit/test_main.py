"""run_cluster_audit end to end against the fake Vault, with file writes patched."""

import json
from pathlib import Path
from unittest.mock import patch

import jsonschema
from rich.console import Console

from src.cluster_audit.main import run_cluster_audit
from src.common.vault_client import ConnectionInfo, VaultConnectionError
from tests.cluster_audit.fakes import HEALTHY, enterprise_routes, fake_vault_client

SCHEMA = json.loads((Path(__file__).parents[2] / "schemas" / "findings.schema.json").read_text())


def _run(client, tmp_path):
    with (
        patch("src.cluster_audit.main.write_json") as write_json,
        patch("src.cluster_audit.main.write_markdown") as write_markdown,
    ):
        document = run_cluster_audit(client, str(tmp_path), console=Console(quiet=True))
    written = {call.args[0]: call.args[1] for call in write_json.call_args_list}
    markdown = write_markdown.call_args.args[1] if write_markdown.called else None
    return document, written, markdown


def _connected(routes):
    client = fake_vault_client(routes)
    client.validate_connection.return_value = ConnectionInfo("vault-cluster-test", "1.20.1+ent", True, "id")
    client.get.side_effect = lambda path: (
        {"data": {"default_lease_ttl": 0, "max_lease_ttl": 0}} if "sanitized" in path else {"data": {"autoloaded": {"license_id": "x", "expiration_time": "2099-01-01T00:00:00Z"}}}
    )
    return client


def test_healthy_cluster_writes_three_files_and_a_valid_document(tmp_path):
    document, written, markdown = _run(_connected(enterprise_routes()), tmp_path)
    jsonschema.validate(document, SCHEMA)
    assert {Path(p).name.split("-2")[0] for p in written} == {"vault-cluster-test-cluster-health", "vault-cluster-test-cluster-findings"}
    # Two audit devices, healthy raft and a working snapshot: nothing to report.
    assert document["summary"]["total"] == 0
    assert document["coverage"]["complete"] is True
    assert "## Cluster health" in markdown and "## License" in markdown


def test_sealed_node_is_reported_without_validating_the_token(tmp_path):
    client = fake_vault_client({"sys/health": {**HEALTHY, "sealed": True, "cluster_name": None}, "sys/seal-status": {"type": "shamir", "t": 3, "n": 5, "progress": 0}})
    document, written, markdown = _run(client, tmp_path)
    client.validate_connection.assert_not_called()
    client.get.assert_not_called()
    assert document["summary"]["by_rule"] == {"VT-HLTH-001": 1}
    assert all(Path(p).name.startswith("vault-cluster-health") or Path(p).name.startswith("vault-cluster-findings") for p in written)
    assert "**sealed**" in markdown


def test_unreachable_vault_returns_none(tmp_path):
    client = fake_vault_client({})
    client.get_client.side_effect = ConnectionError("refused")
    assert _run(client, tmp_path)[0] is None


def test_bad_token_returns_none(tmp_path):
    client = fake_vault_client(enterprise_routes())
    client.validate_connection.side_effect = VaultConnectionError("not authenticated")
    assert _run(client, tmp_path)[0] is None


def test_denied_reads_make_coverage_incomplete(tmp_path):
    import hvac

    routes = enterprise_routes(**{"sys/audit": hvac.exceptions.Forbidden()})
    document, _, markdown = _run(_connected(routes), tmp_path)
    assert document["coverage"]["denied"] == [{"namespace": "/", "scope": "sys/audit"}]
    assert document["coverage"]["complete"] is False
    assert "`sys/audit`" in markdown
