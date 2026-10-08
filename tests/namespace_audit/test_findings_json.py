"""findings.json from the namespace audit: schema conformance and agreement with the markdown."""

import json
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import patch

import jsonschema
import pytest

from src.common.findings import RULES
from src.namespace_audit.report import build_findings_json, build_markdown_report, collect_findings, sentinel_status

SCHEMA = json.loads((Path(__file__).parents[2] / "schemas" / "findings.schema.json").read_text())
NOW = datetime(2026, 10, 1, tzinfo=UTC)


def _build(data, stats, **kwargs):
    return build_findings_json("test-cluster", data, stats, generated_at=NOW, vault_addr="https://vault", worker_threads=4, **kwargs)


@pytest.mark.parametrize("fixture", ["clean_data", "flagged_data", "sentinel_data", "license_expiring_data", "ce_data"])
def test_document_validates_against_the_vendored_schema(request, fixture, finished_stats):
    doc = _build(request.getfixturevalue(fixture), finished_stats, sentinel_supported=True)
    jsonschema.validate(doc, SCHEMA)


def test_every_finding_uses_a_catalogued_rule(flagged_data, finished_stats):
    doc = _build(flagged_data, finished_stats)
    assert doc["findings"]
    assert {f["rule_id"] for f in doc["findings"]} <= set(RULES)


def test_findings_match_the_markdown_report(flagged_data, finished_stats):
    """Same inputs and clock, so the two files report the same findings."""
    doc = _build(flagged_data, finished_stats)
    markdown = build_markdown_report("test-cluster", flagged_data, finished_stats, generated_at=NOW)
    assert doc["summary"]["total"] == len(collect_findings(flagged_data, now=NOW))
    for f in doc["findings"]:
        assert f"| {f['rule_id']} |" in markdown


def test_denials_and_errors_reach_coverage(clean_data, denied_stats):
    doc = _build(clean_data, denied_stats)
    jsonschema.validate(doc, SCHEMA)
    assert doc["coverage"]["complete"] is False
    assert doc["coverage"]["denied"] == [{"namespace": "restricted/", "scope": "child namespaces (subtree not audited)"}]
    assert doc["coverage"]["errors"] == [{"namespace": "broken/", "message": "connection reset"}]


def test_cluster_context_carries_lease_ttls_and_edition(clean_data, finished_stats):
    clean_data.vault_version = "1.17.0+ent"
    clean_data.is_enterprise = True
    ctx = _build(clean_data, finished_stats, system_lease_ttls=(3600, 86400), sentinel_supported=False)["cluster_context"]
    assert ctx == {
        "vault_version": "1.17.0+ent",
        "enterprise": True,
        "system_max_lease_ttl_seconds": 86400,
        "system_default_lease_ttl_seconds": 3600,
        "sentinel": "unsupported",
    }


def test_expired_license_is_vt_lic_001_escalated_to_high(license_expiring_data, finished_stats):
    license_expiring_data.license_status["expiration_time"] = "2026-09-01T00:00:00Z"
    doc = _build(license_expiring_data, finished_stats)
    [lic] = [f for f in doc["findings"] if f["rule_id"] == "VT-LIC-001"]
    assert lic["severity"] == "high"
    assert lic["evidence"]["days_remaining"] < 0


@pytest.mark.parametrize("supported,expected", [(True, "supported"), (False, "unsupported"), (None, "skipped")])
def test_sentinel_status(supported, expected):
    assert sentinel_status(supported) == expected


class TestAuditorWritesFindings:
    def test_write_reports_writes_and_keeps_the_document(self, auditor):
        auditor.data.auth_methods = {"": {"token/": {"type": "token"}}}
        auditor.data.secret_engines = {"": {"kv/": {"type": "kv"}}}

        with (
            patch("src.namespace_audit.main.write_json") as mock_write_json,
            patch("src.namespace_audit.main.write_csv"),
            patch("src.namespace_audit.main.write_markdown"),
            patch("os.makedirs"),
        ):
            auditor._write_reports("test-cluster")

        written = {call.args[0]: call.args[1] for call in mock_write_json.call_args_list}
        [path] = [p for p in written if "-namespace-findings-" in p]
        assert written[path] is auditor.findings_document
        jsonschema.validate(auditor.findings_document, SCHEMA)

    def test_findings_json_is_written_even_with_no_findings(self, auditor):
        with (
            patch("src.namespace_audit.main.write_json") as mock_write_json,
            patch("src.namespace_audit.main.write_csv"),
            patch("src.namespace_audit.main.write_markdown"),
            patch("os.makedirs"),
        ):
            auditor._write_reports("test-cluster")

        assert any("-namespace-findings-" in call.args[0] for call in mock_write_json.call_args_list)
        assert auditor.findings_document["summary"]["total"] == 0
