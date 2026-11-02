"""scripts/threshold-margins.py: margins per threshold from a cluster-health.json."""

import importlib.util
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from src.cluster_audit.findings import DEFAULT_THRESHOLDS, REPL_CANARY_AGE_MS, health_findings

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "threshold-margins.py"
NOW = datetime(2026, 11, 2, 12, 0, tzinfo=UTC)


@pytest.fixture(scope="module")
def margins_mod():
    spec = importlib.util.spec_from_file_location("threshold_margins", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def health(**overrides):
    base = {
        "version": "2.1.1+ent",
        "sealed": False,
        "server_time_utc": int(NOW.timestamp()),
        "metrics": {"timestamp": NOW.isoformat(), "leases": 1084},
        "snapshots": {"configs": [{"name": "hourly", "last_snapshot_start": (NOW - timedelta(hours=2)).isoformat(), "next_snapshot_start": (NOW - timedelta(hours=1)).isoformat()}]},
        "replication": {
            "dr": {
                "mode": "primary",
                "state": "running",
                "secondaries": [
                    {"node_id": "vault-dr", "connection_status": "connected", "last_heartbeat": (NOW - timedelta(seconds=3)).isoformat(), "clock_skew_ms": -1, "replication_primary_canary_age_ms": 746}
                ],
            },
            "performance": {"mode": "disabled"},
        },
    }
    base.update(overrides)
    return base


def by_check(rows):
    return {(r["check"], r["subject"]): r for r in rows}


def test_every_judged_value_has_a_row(margins_mod):
    rows = by_check(margins_mod.margins(health()))
    assert rows[("VT-HLTH-006 leases", "queried node")]["margin"] == DEFAULT_THRESHOLDS.lease_count_warning - 1084
    assert rows[("VT-SNAP-002 late (s)", "hourly")] == {**rows[("VT-SNAP-002 late (s)", "hourly")], "value": 3600, "threshold": 25 * 3600, "fires": False}
    assert rows[("VT-REPL-001 canary (ms)", "dr:vault-dr")]["margin"] == REPL_CANARY_AGE_MS - 746
    assert rows[("VT-REPL-001 heartbeat (s)", "dr:vault-dr")]["value"] == 3
    assert rows[("VT-REPL-003 |skew| (ms)", "dr:vault-dr")]["value"] == 1


@pytest.mark.parametrize(
    ("overrides", "check"),
    [
        ({"metrics": {"leases": DEFAULT_THRESHOLDS.lease_count_warning + 1}}, "VT-HLTH-006 leases"),
        (
            {"snapshots": {"configs": [{"name": "s", "last_snapshot_start": (NOW - timedelta(days=3)).isoformat(), "next_snapshot_start": (NOW - timedelta(days=2)).isoformat()}]}},
            "VT-SNAP-002 late (s)",
        ),
    ],
)
def test_fires_agrees_with_the_rule(margins_mod, overrides, check):
    """The script's verdict and the real rule must never disagree."""
    sample = health(**overrides)
    [row] = [r for r in margins_mod.margins(sample) if r["check"] == check]
    assert row["fires"] is True
    rule = check.split()[0]
    assert rule in {f.rule_id for f in health_findings(sample)}


def test_running_snapshot_is_not_judged(margins_mod):
    sample = health(snapshots={"configs": [{"name": "s", "in_progress": True, "last_snapshot_start": NOW.isoformat(), "next_snapshot_start": (NOW - timedelta(days=2)).isoformat()}]})
    assert not [r for r in margins_mod.margins(sample) if r["check"].startswith("VT-SNAP")]


@pytest.mark.parametrize(
    ("flags", "role"),
    [({}, "active"), ({"standby": True}, "standby"), ({"standby": True, "performance_standby": True}, "perf-standby"), ({"dr_secondary": True}, "dr-secondary"), ({"sealed": True}, "sealed")],
)
def test_node_role(margins_mod, flags, role):
    assert margins_mod.node_role(flags) == role


def test_cli_prints_a_table(margins_mod, tmp_path, capsys):
    path = tmp_path / "x-cluster-health-20261102.json"
    path.write_text(json.dumps(health()))
    assert margins_mod.main([str(path)]) == 0
    out = capsys.readouterr().out.splitlines()
    assert out[0].split() == list(margins_mod.COLUMNS)
    assert any("VT-HLTH-006" in line and "queried node" in line for line in out[1:])


def test_cli_with_nothing_judged_exits_1(margins_mod, tmp_path):
    path = tmp_path / "empty.json"
    path.write_text("{}")
    assert margins_mod.main([str(path)]) == 1
