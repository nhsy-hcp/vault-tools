"""Cluster health rendering, and its embedding in the namespace audit report."""

from datetime import UTC, datetime

from src.cluster_audit.collector import ClusterCoverage, collect_cluster_health
from src.cluster_audit.report import render_cluster_health, render_cluster_reads
from src.namespace_audit.report import build_findings_json, build_markdown_report
from tests.cluster_audit.fakes import HEALTHY, enterprise_routes, fake_vault_client

NOW = datetime(2026, 9, 21, 12, 0, tzinfo=UTC)


def _health(routes):
    return collect_cluster_health(fake_vault_client(routes))


def test_full_section_renders_every_block():
    health, _ = _health(enterprise_routes())
    rendered = render_cluster_health(health)
    for heading in ("## Cluster health", "### Replication", "### Integrated storage (raft)", "### Audit devices", "### Automated snapshots", "### Node metrics"):
        assert heading in rendered
    assert "the queried node only" in rendered
    assert "| node1 |" in rendered


def test_sealed_node_explains_why_blocks_are_empty():
    health, _ = _health({"sys/health": {**HEALTHY, "sealed": True}, "sys/seal-status": {"type": "awskms", "t": 1, "n": 1, "progress": 0}})
    rendered = render_cluster_health(health)
    assert "**sealed**" in rendered and "### Seal" in rendered
    assert "### Audit devices" not in rendered


def test_unread_blocks_point_at_the_access_gaps():
    health, coverage = _health({"sys/health": dict(HEALTHY)})
    assert "Not read" in render_cluster_health(health)
    assert render_cluster_reads(coverage) == ""


def test_cluster_reads_line_names_denied_endpoints():
    coverage = ClusterCoverage(denied=["sys/metrics", "sys/audit"])
    line = render_cluster_reads(coverage, license_unavailable_reason="denied")
    assert "`sys/audit`" in line and "`sys/metrics`" in line and "`sys/license/status`" in line


def test_nothing_collected_renders_nothing():
    assert render_cluster_health(None) == ""


class TestEmbeddedInNamespaceReport:
    def test_section_and_findings_reach_the_namespace_report(self, clean_data, finished_stats):
        routes = enterprise_routes(**{"sys/audit": {"data": {}}})
        clean_data.cluster_health, clean_data.cluster_coverage = _health(routes)
        markdown = build_markdown_report("c", clean_data, finished_stats, generated_at=NOW)
        assert "## Cluster health" in markdown
        assert "| VT-AUD-001 |" in markdown
        doc = build_findings_json("c", clean_data, finished_stats, generated_at=NOW)
        assert doc["summary"]["by_rule"].get("VT-AUD-001") == 1

    def test_cluster_denials_count_against_coverage_in_json_only(self, clean_data, finished_stats):
        clean_data.cluster_health = dict(HEALTHY)
        clean_data.cluster_coverage = ClusterCoverage(denied=["sys/audit"])
        doc = build_findings_json("c", clean_data, finished_stats, generated_at=NOW)
        assert doc["coverage"]["complete"] is False
        assert {"namespace": "/", "scope": "sys/audit"} in doc["coverage"]["denied"]
        markdown = build_markdown_report("c", clean_data, finished_stats, generated_at=NOW)
        assert "the audit covered the full tree" in markdown
        assert "`sys/audit`" in markdown

    def test_namespace_report_without_cluster_health_is_unchanged(self, clean_data, finished_stats):
        assert "## Cluster health" not in build_markdown_report("c", clean_data, finished_stats, generated_at=NOW)


def test_cluster_errors_are_root_rows_naming_the_endpoint(clean_data, finished_stats):
    """Regression: (scope, message) was read as (namespace, message)."""
    coverage = ClusterCoverage(errors=[("sys/metrics", "InternalServerError (HTTP 500)")])
    assert coverage.error_rows() == [("", "sys/metrics: InternalServerError (HTTP 500)")]
    clean_data.cluster_health = dict(HEALTHY)
    clean_data.cluster_coverage = coverage
    doc = build_findings_json("c", clean_data, finished_stats, generated_at=NOW)
    assert {"namespace": "/", "message": "sys/metrics: InternalServerError (HTTP 500)"} in doc["coverage"]["errors"]
