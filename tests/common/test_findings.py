"""Tests for the shared findings model, findings.json document, diff and exit codes."""

from datetime import UTC, datetime, timedelta

import pytest

from src.common.findings import (
    EXIT_FINDINGS,
    EXIT_GAPS,
    EXIT_OK,
    MAX_ERROR_MESSAGE_LENGTH,
    RULES,
    build_findings_document,
    coverage_block,
    diff_documents,
    exit_code_for,
    finding,
    fingerprint,
    run_block,
    sort_findings,
)

STARTED = datetime(2026, 10, 1, 12, 0, 0, tzinfo=UTC)


def _document(findings, *, complete=True):
    return build_findings_document(
        findings,
        run=run_block("c", "https://vault", "", STARTED, STARTED + timedelta(seconds=5)),
        cluster_context={"system_max_lease_ttl_seconds": None, "system_default_lease_ttl_seconds": None, "sentinel": "skipped"},
        coverage=coverage_block(1, [] if complete else [("root", "whole namespace")], []),
        tool_version="test",
    )


class TestFingerprint:
    def test_matches_the_vault_ops_skill(self):
        """Pinned values computed with the skill's fingerprint(): a cross-tool diff
        depends on both producing the same identity for the same finding."""
        assert fingerprint("VT-MOUNT-003", "team-a/", "secrets_mount", "transit/") == "7cbd15ead9e1f328"
        assert fingerprint("VT-LIC-001", "", "cluster", None) == "ff861aa9963689fd"

    def test_trailing_slash_on_the_stored_key_does_not_change_it(self):
        assert fingerprint("VT-NS-001", "a/b", "namespace", None) == fingerprint("VT-NS-001", "a/b/", "namespace", None)


class TestFinding:
    def test_severity_defaults_to_the_rule(self):
        assert finding("VT-MOUNT-001", "", "secrets_mount", "kv/", "kv", "d").severity == "Medium"

    def test_severity_can_be_escalated(self):
        f = finding("VT-LIC-001", "", "cluster", None, "license", "d", severity="High")
        assert f.severity == "High"
        assert f.to_dict()["severity"] == "high"

    def test_markdown_columns_use_a_dash_for_missing_objects(self):
        f = finding("VT-NS-001", "a/", "namespace", None, None, "d")
        assert (f.mount, f.mount_type) == ("—", "—")

    def test_to_dict_carries_rule_metadata_and_sorted_evidence(self):
        d = finding("VT-AUTH-001", "a", "auth_mount", "userpass/", "userpass", "d", z=1, a=2).to_dict()
        assert d["namespace"] == "a/"
        assert d["category"] == RULES["VT-AUTH-001"].category
        assert d["title"] == RULES["VT-AUTH-001"].title
        assert d["object"] == {"kind": "auth_mount", "path": "userpass/", "type": "userpass"}
        assert list(d["evidence"]) == ["a", "z"]

    def test_unknown_rule_is_rejected(self):
        with pytest.raises(KeyError):
            finding("VT-NOPE-001", "", "cluster", None, None, "d")

    def test_sort_puts_most_severe_first(self):
        low = finding("VT-AUTH-001", "", "auth_mount", "a/", "x", "d")
        high = finding("VT-LIC-001", "", "cluster", None, "license", "d", severity="High")
        info = finding("VT-NS-001", "", "namespace", None, None, "d")
        assert sort_findings([info, low, high]) == [high, low, info]


class TestCoverageBlock:
    def test_root_label_is_rendered_as_slash(self):
        block = coverage_block(1, [("root", "whole namespace")], [])
        assert block["denied"] == [{"namespace": "/", "scope": "whole namespace"}]
        assert block["complete"] is False

    def test_error_messages_are_truncated_to_the_schema_limit(self):
        block = coverage_block(1, [], [("a/", "x" * 1000)])
        assert len(block["errors"][0]["message"]) == MAX_ERROR_MESSAGE_LENGTH

    def test_unattributed_failures_still_make_coverage_incomplete(self):
        assert coverage_block(1, [], [], unattributed_errors=1)["complete"] is False
        assert coverage_block(1, [], [], unattributed_denials=1)["complete"] is False

    def test_clean_run_is_complete(self):
        assert coverage_block(3, [], [])["complete"] is True


class TestDocument:
    def test_summary_counts_by_severity_and_rule(self):
        doc = _document(
            [
                finding("VT-NS-001", "a", "namespace", None, None, "d"),
                finding("VT-NS-001", "b", "namespace", None, None, "d"),
                finding("VT-MOUNT-001", "", "secrets_mount", "kv/", "kv", "d"),
            ]
        )
        assert doc["summary"]["total"] == 3
        assert doc["summary"]["by_severity"] == {"high": 0, "medium": 1, "low": 0, "info": 2}
        assert doc["summary"]["by_rule"] == {"VT-MOUNT-001": 1, "VT-NS-001": 2}
        assert doc["tool"]["name"] == "vault-tools"

    def test_run_timestamps_are_utc_iso(self):
        block = run_block("c", "addr", "team/", STARTED, STARTED + timedelta(seconds=2.04), worker_threads=4)
        assert block["started_at"] == "2026-10-01T12:00:00Z"
        assert block["duration_seconds"] == 2.0
        assert block["start_namespace"] == "team/"
        assert block["worker_threads"] == 4


class TestDiff:
    def test_new_resolved_unchanged_and_evidence_changes(self):
        kept = finding("VT-MOUNT-002", "", "secrets_mount", "kv/", "kv", "d", max_lease_ttl_seconds=10)
        kept_longer = finding("VT-MOUNT-002", "", "secrets_mount", "kv/", "kv", "d", max_lease_ttl_seconds=20)
        gone = finding("VT-NS-001", "old", "namespace", None, None, "d")
        added = finding("VT-NS-002", "new", "namespace", None, None, "d")

        result = diff_documents(_document([kept, gone]), _document([kept_longer, added]))

        assert result["summary"] == {"new": 1, "resolved": 1, "unchanged": 1, "evidence_changed": 1}
        assert result["new"][0]["rule_id"] == "VT-NS-002"
        assert result["resolved"][0]["rule_id"] == "VT-NS-001"
        assert result["evidence_changed"][0]["old"] == {"max_lease_ttl_seconds": 10}

    def test_identical_runs_have_no_changes(self):
        doc = _document([finding("VT-NS-001", "a", "namespace", None, None, "d")])
        assert diff_documents(doc, doc)["summary"] == {"new": 0, "resolved": 0, "unchanged": 1, "evidence_changed": 0}

    def test_coverage_is_compared(self):
        result = diff_documents(_document([], complete=True), _document([], complete=False))
        assert result["coverage"] == {"old_complete": True, "new_complete": False}


class TestExitCode:
    LOW = finding("VT-AUTH-001", "", "auth_mount", "a/", "x", "d")

    @pytest.mark.parametrize(
        "fail_on,expected",
        [(None, EXIT_OK), ("info", EXIT_FINDINGS), ("low", EXIT_FINDINGS), ("medium", EXIT_OK), ("high", EXIT_OK)],
    )
    def test_fail_on_threshold(self, fail_on, expected):
        assert exit_code_for(_document([self.LOW]), fail_on, False) == expected

    def test_gaps_only_count_when_asked(self):
        doc = _document([], complete=False)
        assert exit_code_for(doc, None, False) == EXIT_OK
        assert exit_code_for(doc, None, True) == EXIT_GAPS

    def test_findings_win_over_gaps(self):
        assert exit_code_for(_document([self.LOW], complete=False), "low", True) == EXIT_FINDINGS


class TestFilePrefix:
    def test_appends_the_short_cluster_id(self):
        from src.common.utils import file_prefix

        assert file_prefix("vault-cluster", "d33099d9-206e-53c2-4e50-44fb62ac69a6") == "vault-cluster-d33099d9"

    def test_default_names_are_not_doubled(self):
        from src.common.utils import file_prefix

        assert file_prefix("vault-cluster-d33099d9", "d33099d9-206e-53c2-4e50-44fb62ac69a6") == "vault-cluster-d33099d9"

    def test_no_id_means_the_name_alone(self):
        from src.common.utils import file_prefix

        assert file_prefix("vault", None) == "vault" and file_prefix("vault", "") == "vault"
