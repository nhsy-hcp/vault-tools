"""identity-audit: discovery, collection, rules, outputs and the privacy guarantee."""

import json
from pathlib import Path
from unittest.mock import patch

import hvac
import jsonschema
from rich.console import Console

from src.identity_audit.collector import active_entity_clients, collect_entities, discover_namespaces
from src.identity_audit.findings import ENTITY_ACTIVE_RATIO_WARNING, ENTITY_RULE_MIN_ENTITIES, entity_findings
from src.identity_audit.main import run_identity_audit
from tests.identity_audit.fakes import entity, fake_identity_client

SCHEMA = json.loads((Path(__file__).parents[2] / "schemas" / "findings.schema.json").read_text())


def _ids(findings):
    return sorted(f.rule_id for f in findings)


class TestDiscovery:
    def test_walks_the_tree_from_root(self):
        vault = fake_identity_client({"": ["team-a", "team-b"], "team-a/": ["sub"]}, {})
        assert discover_namespaces(vault) == ["", "team-a", "team-b", "team-a/sub"]

    def test_denied_listing_is_a_gap_not_an_error(self):
        from src.identity_audit.collector import IdentityCoverage

        coverage = IdentityCoverage()
        vault = fake_identity_client({"": ["team-a"], "team-a/": hvac.exceptions.Forbidden()}, {})
        assert discover_namespaces(vault, coverage=coverage) == ["", "team-a"]
        assert coverage.denied == [("team-a", "child namespaces (subtree not audited)")]


class TestCollection:
    def test_entities_are_read_per_namespace_with_the_namespace_header(self):
        vault = fake_identity_client({}, {"": [entity("e1")], "team-a/": [entity("e2", aliases=())]})
        entities, coverage = collect_entities(vault, ["", "team-a"])
        assert [e.id for e in entities[""]] == ["e1"] and [e.id for e in entities["team-a"]] == ["e2"]
        assert ("team-a/", "identity/entity/id/e2") in vault.calls
        assert coverage.complete and coverage.namespaces_processed == 2

    def test_denied_body_counts_the_entity_and_records_one_gap(self):
        bodies = [entity("e1"), entity("e2")]
        extra = {("", "identity/entity/id/e1"): hvac.exceptions.Forbidden(), ("", "identity/entity/id/e2"): hvac.exceptions.Forbidden()}
        vault = fake_identity_client({}, {"": bodies}, extra)
        entities, coverage = collect_entities(vault, [""])
        assert [e.disabled for e in entities[""]] == [None, None]
        assert coverage.denied == [("", "identity entity details")]

    def test_denied_listing(self):
        vault = fake_identity_client({}, {}, {("", "identity/entity/id"): hvac.exceptions.Forbidden()})
        entities, coverage = collect_entities(vault, [""])
        assert entities == {"": []} and coverage.denied == [("", "identity entities")]


class TestRules:
    def _collect(self, items, active=None):
        vault = fake_identity_client({}, {"": items})
        entities, _ = collect_entities(vault, [""])
        return entity_findings(entities, active)

    def test_orphan_direct_policy_and_disabled(self):
        found = self._collect([entity("e1", aliases=()), entity("e2", policies=["admin"]), entity("e3", disabled=True), entity("ok")])
        assert _ids(found) == ["VT-ID-001", "VT-ID-002", "VT-ID-003"]

    def test_unread_body_is_not_an_orphan(self):
        vault = fake_identity_client({}, {"": [entity("e1", aliases=())]}, {("", "identity/entity/id/e1"): hvac.exceptions.Forbidden()})
        entities, _ = collect_entities(vault, [""])
        assert entity_findings(entities) == []

    def test_shared_alias_names_count_only(self):
        found = self._collect([entity("e1", aliases=(("Alice@example.com", "oidc/", "oidc"),)), entity("e2", aliases=(("alice@example.com", "userpass/", "userpass"),))])
        [f] = found
        assert f.rule_id == "VT-ID-005" and f.evidence == {"shared_alias_names": 1, "entities_affected": 2}
        assert "alice" not in f.detail.lower()

    def test_entity_sprawl_against_active_clients(self):
        items = [entity(f"e{i}") for i in range(ENTITY_RULE_MIN_ENTITIES)]
        assert _ids(self._collect(items, {"": 10})) == ["VT-ID-004"]
        assert self._collect(items, {"": ENTITY_RULE_MIN_ENTITIES // ENTITY_ACTIVE_RATIO_WARNING + 1}) == []

    def test_sprawl_not_judged_without_activity(self):
        items = [entity(f"e{i}") for i in range(ENTITY_RULE_MIN_ENTITIES)]
        assert self._collect(items, None) == []

    def test_findings_name_entities_by_id_only(self):
        found = self._collect([entity("e1", name="bob@example.com", aliases=())])
        assert found[0].mount == "e1" and "bob" not in json.dumps(found[0].to_dict())


class TestActiveClients:
    def test_higher_of_billing_period_and_current_month(self):
        activity = {"total": {"clients": 5}, "by_namespace": [{"namespace_path": "team-a/", "counts": {"entity_clients": 3}}]}
        current = {"total": {"clients": 1}, "by_namespace": [{"namespace_path": "team-a/", "counts": {"entity_clients": 7}}]}
        assert active_entity_clients(activity, current) == {"team-a": 7}

    def test_empty_log_is_none(self):
        assert active_entity_clients({"total": {"clients": 0}}, {}) is None
        assert active_entity_clients(None) is None


class TestRun:
    def _run(self, vault, tmp_path, **kwargs):
        with patch("src.identity_audit.main.write_json") as wj, patch("src.identity_audit.main.write_csv") as wc, patch("src.identity_audit.main.write_markdown") as wm:
            document = run_identity_audit(vault, str(tmp_path), console=Console(quiet=True), **kwargs)
        return document, {c.args[0]: c.args[1] for c in wj.call_args_list}, wc, wm.call_args.args[1] if wm.called else None

    def test_default_outputs_hold_no_names_or_metadata(self, tmp_path):
        vault = fake_identity_client({"": ["team-a"]}, {"team-a/": [entity("e1", name="carol@example.com", aliases=(), metadata={"email": "carol@example.com"})]})
        document, written, write_csv, markdown = self._run(vault, tmp_path)
        jsonschema.validate(document, SCHEMA)
        assert document["summary"]["by_rule"] == {"VT-ID-001": 1}
        assert not any("identity-entities" in p for p in written)
        everything = json.dumps(list(written.values())) + json.dumps(write_csv.call_args.args[1]) + markdown
        assert "carol" not in everything

    def test_list_writes_the_confidential_file(self, tmp_path):
        vault = fake_identity_client({}, {"": [entity("e1", name="dave")]})
        _, written, _, markdown = self._run(vault, tmp_path, include_list=True)
        [entities] = [v for p, v in written.items() if "identity-entities" in p]
        assert entities["/"][0]["name"] == "dave"
        assert "Treat it as confidential" in markdown

    def test_given_namespaces_skip_discovery(self, tmp_path):
        vault = fake_identity_client({"": ["never-listed"]}, {"": [entity("e1")]})
        self._run(vault, tmp_path, namespaces=[""])
        assert not any(path == "sys/namespaces" for _, path in vault.calls)

    def test_connection_failure_returns_none(self, tmp_path):
        from src.common.vault_client import VaultConnectionError

        vault = fake_identity_client({}, {})
        vault.validate_connection.side_effect = VaultConnectionError("down")
        assert self._run(vault, tmp_path)[0] is None
