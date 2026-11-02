"""Tunable cluster-health thresholds: --lease-count-warning and --snapshot-grace.

Covers the argparse types, the flags on every command that judges cluster
health, the Thresholds object reaching both findings call sites (cluster-audit
and namespace-audit's embedded health section), and the rules themselves.
"""

import argparse
from datetime import UTC, datetime, timedelta
from unittest.mock import patch

import pytest

import main
from main import _duration_seconds, _positive_int
from main import build_parser as _build_parser
from src.cluster_audit.findings import (
    DEFAULT_THRESHOLDS,
    LEASE_COUNT_WARNING,
    SNAPSHOT_OVERDUE_MIN_GRACE_SECONDS,
    Thresholds,
    metric_findings,
    snapshot_findings,
)
from src.cluster_audit.report import collect_cluster_findings
from src.namespace_audit.main import AuditData, NamespaceAuditor
from src.namespace_audit.report import collect_findings

NOW = datetime(2026, 9, 21, 12, 0, tzinfo=UTC)
HEALTH_COMMANDS = ["cluster-audit", "namespace-audit", "full-audit"]


# ---------------------------------------------------------------------------
# argparse types
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(("text", "seconds"), [("90", 90), ("45s", 45), ("90m", 5400), ("2h", 7200), ("1d", 86400), (" 3H ", 10800)])
def test_duration_seconds(text, seconds):
    assert _duration_seconds(text) == seconds


@pytest.mark.parametrize("text", ["0", "0h", "-1h", "2w", "h", "1.5h", ""])
def test_duration_seconds_rejects(text):
    with pytest.raises(argparse.ArgumentTypeError):
        _duration_seconds(text)


@pytest.mark.parametrize("text", ["0", "-5", "ten", "1e5"])
def test_positive_int_rejects(text):
    with pytest.raises(argparse.ArgumentTypeError):
        _positive_int(text)


# ---------------------------------------------------------------------------
# CLI flags
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("command", HEALTH_COMMANDS)
def test_defaults_are_the_skill_values(command):
    args = _build_parser().parse_args([command])
    assert main._thresholds(args) == DEFAULT_THRESHOLDS == Thresholds(LEASE_COUNT_WARNING, SNAPSHOT_OVERDUE_MIN_GRACE_SECONDS)


@pytest.mark.parametrize("command", HEALTH_COMMANDS)
def test_flags_build_thresholds(command):
    args = _build_parser().parse_args([command, "--lease-count-warning", "250000", "--snapshot-grace", "2h"])
    assert main._thresholds(args) == Thresholds(lease_count_warning=250_000, snapshot_grace_seconds=7200)


@pytest.mark.parametrize("command", ["identity-audit", "activity-export", "entity-export"])
def test_commands_without_health_findings_reject_the_flags(command):
    with pytest.raises(SystemExit):
        _build_parser().parse_args([command, "--lease-count-warning", "5"])


def _run_cli(monkeypatch, tmp_path, argv, target, **patch_kwargs):
    monkeypatch.setenv("VAULT_ADDR", "http://127.0.0.1:8200")
    monkeypatch.setenv("VAULT_TOKEN", "test-token")
    monkeypatch.setattr("sys.argv", ["main.py", *argv, "--output-dir", str(tmp_path)])
    with patch(target, **patch_kwargs) as mocked, pytest.raises(SystemExit):
        main.main()
    return mocked


FLAGS = ["--lease-count-warning", "7", "--snapshot-grace", "90m"]
TUNED = Thresholds(lease_count_warning=7, snapshot_grace_seconds=5400)


def test_cluster_audit_passes_thresholds(monkeypatch, tmp_path):
    run = _run_cli(monkeypatch, tmp_path, ["cluster-audit", *FLAGS], "main.run_cluster_audit", return_value=None)
    assert run.call_args.kwargs["thresholds"] == TUNED


def test_namespace_audit_passes_thresholds(monkeypatch, tmp_path):
    auditor_cls = _run_cli(monkeypatch, tmp_path, ["namespace-audit", *FLAGS], "main.NamespaceAuditor", **{"return_value.audit_cluster.return_value": None})
    assert auditor_cls.call_args.kwargs["thresholds"] == TUNED


def test_full_audit_passes_thresholds(monkeypatch, tmp_path):
    run = _run_cli(monkeypatch, tmp_path, ["full-audit", "--only", "cluster-audit", *FLAGS], "main.run_full_audit", return_value=None)
    assert run.call_args.kwargs["thresholds"] == TUNED


def test_namespace_auditor_stores_thresholds_on_audit_data(mock_vault_client):
    assert NamespaceAuditor(mock_vault_client, thresholds=TUNED).data.thresholds == TUNED
    assert NamespaceAuditor(mock_vault_client).data.thresholds == DEFAULT_THRESHOLDS


@pytest.fixture
def mock_vault_client():
    from unittest.mock import Mock

    from src.common.vault_client import VaultClient

    client = Mock(spec=VaultClient)
    client.vault_addr = "https://vault.example.com:8200"
    return client


# ---------------------------------------------------------------------------
# Both findings call sites honour the thresholds
# ---------------------------------------------------------------------------

HEALTH = {"version": "1.20.1+ent", "sealed": False, "metrics": {"leases": 150}, "server_time_utc": int(NOW.timestamp())}


def _rule_ids(findings):
    return sorted(f.rule_id for f in findings)


def test_cluster_audit_call_site():
    assert "VT-HLTH-006" not in _rule_ids(collect_cluster_findings(HEALTH))
    assert "VT-HLTH-006" in _rule_ids(collect_cluster_findings(HEALTH, thresholds=Thresholds(lease_count_warning=100)))


def test_namespace_audit_call_site():
    data = AuditData(cluster_health=HEALTH)
    assert "VT-HLTH-006" not in _rule_ids(collect_findings(data, now=NOW))
    data = AuditData(cluster_health=HEALTH, thresholds=Thresholds(lease_count_warning=100))
    assert "VT-HLTH-006" in _rule_ids(collect_findings(data, now=NOW))


# ---------------------------------------------------------------------------
# The rules
# ---------------------------------------------------------------------------


def test_lease_threshold_is_exclusive_and_in_evidence():
    tuned = Thresholds(lease_count_warning=150)
    assert metric_findings({"leases": 150}, tuned) == []
    [f] = metric_findings({"leases": 151}, tuned)
    assert f.evidence["threshold"] == 150
    assert "above the 150 review threshold" in f.detail


def _snapshot(interval: timedelta, **overrides):
    last = NOW - interval
    cfg = {"name": "s", "consecutive_errors": 0, "last_snapshot_start": last.isoformat(), "next_snapshot_start": NOW.isoformat(), "storage_scheme": "s3"}
    cfg.update(overrides)
    return {"configs": [cfg]}


def test_hourly_schedule_is_late_after_25h_by_default():
    assert snapshot_findings(_snapshot(timedelta(hours=1)), NOW + timedelta(hours=3)) == []


def test_hourly_schedule_with_a_tuned_grace():
    [f] = snapshot_findings(_snapshot(timedelta(hours=1)), NOW + timedelta(hours=3), Thresholds(snapshot_grace_seconds=7200))
    assert f.rule_id == "VT-SNAP-002"
    assert f.evidence["grace_seconds"] == 7200


def test_interval_still_floors_a_tuned_grace():
    """A daily schedule is never judged within a day, whatever --snapshot-grace says."""
    assert snapshot_findings(_snapshot(timedelta(days=1)), NOW + timedelta(hours=20), Thresholds(snapshot_grace_seconds=3600)) == []


def test_default_run_evidence_has_no_grace_key():
    """A default run's evidence is unchanged, so a diff against main stays clean."""
    [f] = snapshot_findings(_snapshot(timedelta(hours=1)), NOW + timedelta(hours=30))
    assert "grace_seconds" not in f.evidence
