"""Opt-in ACL policy body review: parser, rule checks, collection and the no-body guarantee."""

import json
import queue
from datetime import UTC, datetime

import hvac
import pytest

from src.namespace_audit.acl import (
    BODY_DENIED_SCOPE,
    AclRule,
    acl_policy_findings,
    assess_policy,
    glob_matches,
    matches_everything,
    parse_acl_policy,
    rule_flags,
)
from src.namespace_audit.main import NamespaceAuditor
from src.namespace_audit.report import build_findings_json, build_markdown_report
from tests.namespace_audit.fixtures import as_context_manager, make_hvac_client

ADMIN = 'path "*" {\n  capabilities = ["create", "read", "update", "delete", "list", "sudo"]\n}\n'
READER = '# read only\npath "secret/data/app/*" { capabilities = ["read", "list"] }\n'
POLICY_ADMIN = 'path "sys/policies/acl/*" {\n  capabilities = ["create", "update"]\n  allowed_parameters = { "policy" = ["s3cr3t-value"] }\n}\n'


def _ids(findings):
    return sorted(f.rule_id for f in findings)


class TestParser:
    def test_hcl_with_comments_and_parameters(self):
        rules = parse_acl_policy(POLICY_ADMIN + "// trailing\n/* block */\n" + READER)
        assert rules == (AclRule("sys/policies/acl/*", ("create", "update")), AclRule("secret/data/app/*", ("read", "list")))

    def test_json_policy(self):
        body = json.dumps({"path": {"kv/*": {"capabilities": ["read"]}}})
        assert parse_acl_policy(body) == (AclRule("kv/*", ("read",)),)

    def test_unparseable_returns_none(self):
        assert parse_acl_policy('path "x" { capabilities = ["read"') is None
        assert parse_acl_policy("not a policy at all") is None

    def test_empty_body_has_no_rules(self):
        assert parse_acl_policy("") == ()


class TestGlobs:
    @pytest.mark.parametrize(
        "glob,path,expected",
        [
            ("sys/auth/*", "sys/auth/x", True),
            ("+/sys/auth/x", "ns/sys/auth/x", True),
            ("+/sys/auth/x", "a/b/sys/auth/x", False),
            ("auth/token/create", "auth/token/create", True),
            ("auth/token/create", "auth/token/create/x", False),
        ],
    )
    def test_glob_matches(self, glob, path, expected):
        assert glob_matches(glob, path) is expected

    @pytest.mark.parametrize("glob,expected", [("*", True), ("+/*", True), ("+/+/*", True), ("secret/*", False), ("+/secret/*", False)])
    def test_matches_everything(self, glob, expected):
        assert matches_everything(glob) is expected


class TestRuleFlags:
    def test_wildcard_sudo_is_admin_only_not_also_sudo(self):
        """VT-POL-001 already covers sudo on every path; VT-POL-003 would double-count it."""
        assert rule_flags(AclRule("*", ("update", "sudo"))) == ["VT-POL-001"]
        assert rule_flags(AclRule("+/*", ("sudo",))) == ["VT-POL-001"]

    def test_sudo_on_a_specific_path_is_still_flagged(self):
        assert rule_flags(AclRule("sys/audit", ("read", "sudo"))) == ["VT-POL-003"]
        assert rule_flags(AclRule("sys/policies/acl/*", ("update", "sudo"))) == ["VT-POL-002", "VT-POL-003"]

    def test_read_only_wildcard_is_not_flagged(self):
        assert rule_flags(AclRule("*", ("read", "list"))) == []

    def test_escalation_paths(self):
        assert rule_flags(AclRule("auth/token/create", ("update",))) == ["VT-POL-002"]
        assert rule_flags(AclRule("identity/group/*", ("create",))) == ["VT-POL-002"]

    def test_deny_grants_nothing(self):
        assert rule_flags(AclRule("*", ("deny", "sudo"))) == []

    def test_ordinary_secret_write_is_not_escalation(self):
        assert rule_flags(AclRule("secret/data/app/*", ("create", "update"))) == []


class TestAssessment:
    def test_body_and_parameter_values_are_not_kept(self):
        a = assess_policy(POLICY_ADMIN)
        dumped = json.dumps(a.to_dict())
        assert "s3cr3t-value" not in dumped and "allowed_parameters" not in dumped
        assert a.flagged == [{"path": "sys/policies/acl/*", "capabilities": ["create", "update"], "rules": ["VT-POL-002"]}]
        assert a.parsed and a.rule_count == 1 and len(a.sha256) == 16

    def test_unparseable_is_marked(self):
        a = assess_policy("??")
        assert (a.parsed, a.rule_count, a.flagged) == (False, 0, [])


class TestFindings:
    def test_one_finding_per_rule_per_policy(self):
        found = acl_policy_findings({"": {"admin": assess_policy(ADMIN), "policy-admin": assess_policy(POLICY_ADMIN), "reader": assess_policy(READER)}})
        assert _ids(found) == ["VT-POL-001", "VT-POL-002"]
        [p2] = [f for f in found if f.rule_id == "VT-POL-002"]
        assert p2.evidence["areas"] == ["ACL policies"] and p2.mount == "policy-admin"

    def test_unparsed_policy(self):
        assert _ids(acl_policy_findings({"a": {"weird": assess_policy("??")}})) == ["VT-POL-005"]

    def test_drift_across_namespaces(self):
        found = acl_policy_findings({"a": {"app": assess_policy(READER)}, "b": {"app": assess_policy(READER)}, "c": {"app": assess_policy(READER + "\n")}})
        [f] = found
        assert f.rule_id == "VT-POL-004" and f.evidence["examples"] == ["c/"] and f.namespace == ""

    def test_identical_copies_do_not_drift(self):
        assert acl_policy_findings({ns: {"app": assess_policy(READER)} for ns in ("a", "b")}) == []


class TestCollection:
    def _auditor(self, mock_vault_client, **sys_overrides):
        auditor = NamespaceAuditor(mock_vault_client, collect_acl_bodies=True)
        client = make_hvac_client(list_acl_policies={"data": {"keys": ["admin", "default", "root"]}}, **sys_overrides)
        mock_vault_client.get_client.return_value = as_context_manager(client)
        return auditor, client

    def test_bodies_are_assessed_with_root_skipped(self, mock_vault_client):
        auditor, client = self._auditor(mock_vault_client)
        client.sys.read_acl_policy.side_effect = lambda name: {"data": {"name": name, "policy": ADMIN if name == "admin" else READER}}

        auditor._traverse_namespace("team-a/", queue.Queue())

        assert sorted(auditor.data.acl_assessments["team-a"]) == ["admin", "default"]
        assert [c.args[0] for c in client.sys.read_acl_policy.call_args_list] == ["admin", "default"]
        # The names list keeps excluding built-ins.
        assert auditor.data.acl_policies["team-a"] == ["admin"]

    def test_denied_bodies_record_one_gap_naming_the_add_on(self, mock_vault_client):
        auditor, client = self._auditor(mock_vault_client)
        client.sys.read_acl_policy.side_effect = hvac.exceptions.Forbidden()

        auditor._traverse_namespace("team-a/", queue.Queue())

        assert auditor.stats.forbidden_namespaces == [("team-a/", BODY_DENIED_SCOPE)]
        assert "team-a" not in auditor.data.acl_assessments

    def test_bodies_are_not_read_by_default(self, mock_vault_client):
        auditor = NamespaceAuditor(mock_vault_client)
        client = make_hvac_client(list_acl_policies={"data": {"keys": ["admin"]}})
        mock_vault_client.get_client.return_value = as_context_manager(client)

        auditor._traverse_namespace("team-a/", queue.Queue())

        client.sys.read_acl_policy.assert_not_called()
        assert auditor.data.acl_assessments == {}


class TestReporting:
    NOW = datetime(2026, 10, 1, tzinfo=UTC)

    def test_findings_and_note_reach_both_files(self, clean_data, finished_stats):
        clean_data.acl_assessments = {"": {"admin": assess_policy(ADMIN)}}
        markdown = build_markdown_report("c", clean_data, finished_stats, generated_at=self.NOW)
        assert "Permissions assessed for 1 policy" in markdown and "| VT-POL-001 |" in markdown
        doc = build_findings_json("c", clean_data, finished_stats, generated_at=self.NOW)
        assert doc["summary"]["by_rule"] == {"VT-POL-001": 1}

    def test_default_run_says_permissions_were_not_assessed(self, clean_data, finished_stats):
        assert "Permissions were not assessed" in build_markdown_report("c", clean_data, finished_stats, generated_at=self.NOW)

    def test_review_file_holds_no_body(self, auditor):
        from unittest.mock import patch

        auditor.data.acl_policies = {"": ["policy-admin"]}
        auditor.data.acl_assessments = {"": {"policy-admin": assess_policy(POLICY_ADMIN)}}
        with patch("src.namespace_audit.main.write_json") as write_json, patch("src.namespace_audit.main.write_csv"), patch("src.namespace_audit.main.write_markdown"), patch("os.makedirs"):
            auditor._write_reports("c")
        [review] = [c.args[1] for c in write_json.call_args_list if "-acl-policy-review-" in c.args[0]]
        assert review["/"]["policy-admin"]["flagged"][0]["path"] == "sys/policies/acl/*"
        assert "s3cr3t-value" not in json.dumps(review)


class TestReviewFixes:
    """Regressions from the code review: specific-path escalation and legacy syntax."""

    @pytest.mark.parametrize(
        "path,area",
        [
            ("sys/policies/acl/admin", "ACL policies"),
            ("sys/auth/userpass", "auth methods"),
            ("auth/token/roles/ci", "token roles"),
            ("identity/entity/id/abc", "identity entities"),
            ("+/sys/policies/acl/*", "ACL policies"),
            ("team-a/auth/token/create", "token creation"),
        ],
    )
    def test_writes_on_a_specific_target_are_escalation(self, path, area):
        assert rule_flags(AclRule(path, ("update",))) == ["VT-POL-002"]
        [f] = acl_policy_findings({"": {"p": assess_policy(f'path "{path}" {{ capabilities = ["update"] }}')}})
        assert f.evidence["areas"] == [area]

    @pytest.mark.parametrize("path", ["secret/data/app/*", "sys/mounts", "sys/policies/egp/x", "kv/sys/notes"])
    def test_unrelated_paths_are_not_escalation(self, path):
        assert rule_flags(AclRule(path, ("create", "update"))) == []

    @pytest.mark.parametrize(
        "legacy,expected",
        [("sudo", ["VT-POL-001"]), ("write", ["VT-POL-001"]), ("read", []), ("deny", [])],
    )
    def test_legacy_policy_attribute_is_assessed(self, legacy, expected):
        assessment = assess_policy(f'path "*" {{\n  policy = "{legacy}"\n}}\n')
        assert assessment.parsed
        assert sorted({r for f in assessment.flagged for r in f["rules"]}) == expected

    def test_legacy_attribute_in_json_policy(self):
        rules = parse_acl_policy(json.dumps({"path": {"sys/auth/*": {"policy": "sudo"}}}))
        assert set(rules[0].capabilities) == {"create", "read", "update", "delete", "list", "sudo"}
