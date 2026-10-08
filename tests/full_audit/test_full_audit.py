"""full-audit orchestration: order, reuse between steps, failure isolation, merging."""

from datetime import date
from unittest.mock import MagicMock, Mock, patch

import pytest
from rich.console import Console

from src.activity_export.main import ActivityExportResult
from src.cluster_audit.collector import ClusterCoverage, ClusterReads, LicenseResult
from src.cluster_audit.main import ClusterAuditResult
from src.common.findings import finding, merge_documents
from src.full_audit.main import build_full_report, default_window, files_written_since, run_full_audit
from src.identity_audit.main import IdentityAuditResult


def _doc(findings=(), complete=True, denied=(), sentinel="skipped"):
    items = [f.to_dict() for f in findings]
    return {
        "findings": items,
        "summary": {"total": len(items)},
        "coverage": {"namespaces_processed": 1, "complete": complete, "denied": list(denied), "errors": []},
        "cluster_context": {"vault_version": "1.20.1+ent", "enterprise": True, "system_max_lease_ttl_seconds": None, "system_default_lease_ttl_seconds": None, "sentinel": sentinel},
        "run": {},
    }


AUD = finding("VT-AUD-001", "", "cluster", None, "audit", "no audit device", devices=0)
KV1 = finding("VT-MOUNT-006", "team-a", "secrets_mount", "old/", "kv", "kv v1", kv_version=1)
ORPHAN = finding("VT-ID-001", "team-a", "entity", "e1", None, "orphan", entity_id="e1")


def _cluster(reason=None):
    health, coverage = {"enterprise": True, "version": "1.20.1+ent"}, ClusterCoverage()
    reads = ClusterReads(health, coverage, LicenseResult(None, None, True), (3600, 86400))
    return ClusterAuditResult(_doc([AUD]), health, coverage, "c", reason, reads)


class Harness:
    """Patches every step; the instance records what each was called with."""

    def __init__(self, tmp_path, cluster=None, **failures):
        self.tmp_path = tmp_path
        self.cluster = _cluster() if cluster is None else cluster
        self.failures = failures
        self.calls: list[str] = []

    def run(self, **kwargs):
        auditor = MagicMock()
        auditor.data.auth_methods = {"": {}, "team-a": {}}

        def namespace_audit():
            self.calls.append("namespace-audit")
            if "namespace" in self.failures:
                raise self.failures["namespace"]
            return _doc([AUD, KV1], sentinel="supported")

        auditor.audit_cluster.side_effect = namespace_audit

        def step(name, value):
            def fn(*args, **kw):
                self.calls.append(name)
                self.kwargs[name] = kw
                self.args[name] = args
                if name.split("-")[0] in self.failures:
                    raise self.failures[name.split("-")[0]]
                return value

            return fn

        self.kwargs: dict[str, dict] = {}
        self.args: dict[str, tuple] = {}
        vault = Mock()
        vault.vault_addr = "https://vault.example.com:8200"
        with (
            patch("src.full_audit.main.run_cluster_audit_full", side_effect=step("cluster-audit", self.cluster)),
            patch("src.full_audit.main.NamespaceAuditor", return_value=auditor) as auditor_cls,
            patch("src.full_audit.main.run_identity_audit_full", side_effect=step("identity-audit", IdentityAuditResult(_doc([ORPHAN]), {"clients": 7}))),
            patch("src.full_audit.main.run_activity_export", side_effect=step("activity-export", ActivityExportResult([], [], _doc()))),
            patch("src.full_audit.main.run_entity_export", side_effect=step("entity-export", None)),
            patch("src.full_audit.main.write_json") as write_json,
            patch("src.full_audit.main.write_markdown") as write_markdown,
        ):
            merged = run_full_audit(vault, str(self.tmp_path), console=Console(quiet=True), **kwargs)
        self.auditor_kwargs = auditor_cls.call_args.kwargs if auditor_cls.called else None
        self.written = {c.args[0]: c.args[1] for c in write_json.call_args_list}
        self.report = write_markdown.call_args.args[1] if write_markdown.called else None
        return merged


def test_runs_every_step_in_order_and_reuses_shared_state(tmp_path):
    h = Harness(tmp_path)
    merged = h.run(collect_acl_bodies=True, include_entity_list=True)

    assert h.calls == ["cluster-audit", "namespace-audit", "identity-audit", "activity-export", "entity-export"]
    assert h.auditor_kwargs["cluster_reads"] is h.cluster.reads
    assert h.auditor_kwargs["collect_acl_bodies"] is True
    assert h.kwargs["identity-audit"]["namespaces"] == ["", "team-a"]
    assert h.kwargs["identity-audit"]["include_list"] is True
    assert h.kwargs["activity-export"]["is_enterprise"] is True
    # identity-audit's current-month read is handed on, not repeated.
    assert h.kwargs["activity-export"]["current_month"] == {"clients": 7}
    # VT-AUD-001 came from both cluster- and namespace-audit: listed once.
    assert merged["summary"]["by_rule"] == {"VT-AUD-001": 1, "VT-ID-001": 1, "VT-MOUNT-006": 1}
    assert merged["cluster_context"]["sentinel"] == "supported"
    assert any(p.endswith(".json") and "-full-findings-" in p for p in h.written)
    assert "## Steps" in h.report and "| entity-export | ok |" in h.report


def test_a_failing_step_does_not_stop_the_rest(tmp_path):
    h = Harness(tmp_path, identity=RuntimeError("boom"))
    merged = h.run()

    assert h.calls[-2:] == ["activity-export", "entity-export"]
    assert merged["coverage"]["complete"] is False
    assert any("identity-audit: RuntimeError: boom" in e["message"] for e in merged["coverage"]["errors"])
    assert "| identity-audit | failed |" in h.report


def test_sealed_node_runs_only_cluster_audit(tmp_path):
    h = Harness(tmp_path, cluster=_cluster("sealed"))
    merged = h.run()

    assert h.calls == ["cluster-audit"]
    assert merged["summary"]["by_rule"] == {"VT-AUD-001": 1}
    assert h.report.count("| skipped |") == 4
    assert "node is sealed" in h.report


def test_unreachable_vault_returns_none(tmp_path):
    h = Harness(tmp_path, cluster=False)
    h.cluster = None
    assert h.run() is None
    assert h.calls == ["cluster-audit"]


def test_default_window_is_twelve_calendar_months():
    assert default_window(date(2026, 10, 8)) == ("2025-11-01", "2026-10-08")
    assert default_window(date(2026, 1, 31)) == ("2025-02-01", "2026-01-31")


def test_given_dates_reach_both_exporters(tmp_path):
    h = Harness(tmp_path)
    h.run(start_date="2026-01-01", end_date="2026-03-31")
    # Positional: (client, start, end, cluster_name)
    assert h.args["activity-export"][1:4] == ("2026-01-01", "2026-03-31", "c")
    assert h.args["entity-export"][1:4] == ("2026-01-01", "2026-03-31", "c")


def test_omitted_dates_use_the_default_window(tmp_path):
    h = Harness(tmp_path)
    h.run()
    start, end = h.args["activity-export"][1:3]
    assert start.endswith("-01") and start < end


class TestMerge:
    def test_dedupes_and_unions_coverage(self):
        a = _doc([AUD], complete=False, denied=[{"namespace": "/", "scope": "sys/audit"}])
        b = _doc([AUD, KV1], denied=[{"namespace": "/", "scope": "sys/audit"}])
        merged = merge_documents([a, b], run={}, cluster_context={}, tool_version="t")
        assert merged["summary"]["total"] == 2
        assert merged["coverage"]["complete"] is False
        assert merged["coverage"]["denied"] == [{"namespace": "/", "scope": "sys/audit"}]
        assert merged["summary"]["by_severity"]["medium"] == 1

    def test_most_severe_first(self):
        high = finding("VT-REPL-004", "", "cluster", "dr", "dr", "corrupted")
        merged = merge_documents([_doc([KV1]), _doc([high])], run={}, cluster_context={}, tool_version="t")
        assert [f["rule_id"] for f in merged["findings"]] == ["VT-REPL-004", "VT-MOUNT-006"]


def test_report_renders_merged_findings_by_rule():
    merged = merge_documents([_doc([AUD, KV1])], run={}, cluster_context={}, tool_version="t")
    from datetime import UTC, datetime

    from src.full_audit.main import StepResult

    report = build_full_report(
        "c", merged, [StepResult("cluster-audit", "ok", document=_doc([AUD]))], vault_addr="addr", generated_at=datetime(2026, 1, 1, tzinfo=UTC), window=("a", "b"), output_files=["x.json"]
    )
    assert "| VT-MOUNT-006 | team-a/ |" in report and "| VT-AUD-001 | / |" in report


@pytest.mark.parametrize("argv", [["full-audit", "-s", "2026-01-01"], ["full-audit", "-e", "2026-01-31"]])
def test_cli_needs_both_dates_or_neither(argv, monkeypatch, tmp_path):
    import main

    monkeypatch.setenv("VAULT_ADDR", "http://127.0.0.1:8200")
    monkeypatch.setenv("VAULT_TOKEN", "t")
    monkeypatch.setattr("sys.argv", ["main.py", *argv, "--output-dir", str(tmp_path)])
    with patch("main.run_full_audit") as run, pytest.raises(SystemExit) as exc:
        main.main()
    assert exc.value.code == 1
    run.assert_not_called()


def test_cli_gates_on_the_merged_document(monkeypatch, tmp_path):
    import main

    monkeypatch.setenv("VAULT_ADDR", "http://127.0.0.1:8200")
    monkeypatch.setenv("VAULT_TOKEN", "t")
    monkeypatch.setattr("sys.argv", ["main.py", "full-audit", "--fail-on", "medium", "--acl-bodies", "--output-dir", str(tmp_path)])
    with patch("main.run_full_audit", return_value=_doc([AUD])) as run, pytest.raises(SystemExit) as exc:
        main.main()
    assert exc.value.code == 3
    assert run.call_args.kwargs["collect_acl_bodies"] is True and run.call_args.kwargs["start_date"] is None


class TestFilesWrittenSince:
    def test_lists_only_this_runs_files_for_this_cluster(self, tmp_path):
        import os
        import time

        stale = tmp_path / "c-identity-entities-20261008.json"
        stale.write_text("{}")
        old = time.time() - 3600
        os.utime(stale, (old, old))
        since = time.time()
        (tmp_path / "c-namespace-findings-20261007.json").write_text("{}")  # local date differs from UTC: still listed
        (tmp_path / "c-cluster-findings-20261008.json").write_text("{}")
        (tmp_path / "other-cluster-findings-20261008.json").write_text("{}")
        report = tmp_path / "c-full-audit-20261008.md"
        report.write_text("")

        assert files_written_since(str(tmp_path), "c", since, exclude={str(report)}) == ["c-cluster-findings-20261008.json", "c-namespace-findings-20261007.json"]

    def test_missing_directory_is_empty(self, tmp_path):
        assert files_written_since(str(tmp_path / "nope"), "c", 0) == []
