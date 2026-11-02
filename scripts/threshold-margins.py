#!/usr/bin/env python3
"""Print how far each cluster-health threshold is from firing, per cluster-health.json.

Calibration aid for the thresholds in src/cluster_audit/findings.py. Run it in the
project environment so the thresholds are imported, never copied:

    uv run scripts/threshold-margins.py outputs/*-cluster-health-*.json
    uv run scripts/threshold-margins.py --snapshot-grace 2h outputs/*-cluster-health-*.json

Collect the files with `vault-tools cluster-audit` pointed at each node (not a load
balancer), several times and at busy periods. Reads files only; makes no Vault call.
A positive margin is headroom; a negative one means the rule fires.
"""

import argparse
import json
import sys
from pathlib import Path
from typing import Any

from src.cluster_audit.findings import (
    DEFAULT_THRESHOLDS,
    REPL_CANARY_AGE_MS,
    REPL_CLOCK_SKEW_MS,
    REPL_HEARTBEAT_AGE_S,
    Thresholds,
    never_connected,
    server_time,
)
from src.common.findings import parse_time
from src.common.utils import duration_seconds, positive_int

COLUMNS = ("file", "role", "sampled", "check", "subject", "value", "threshold", "margin", "fires")


def node_role(health: dict[str, Any]) -> str:
    if health.get("sealed"):
        return "sealed"
    if health.get("dr_secondary"):
        return "dr-secondary"
    if health.get("performance_standby"):
        return "perf-standby"
    if health.get("standby"):
        return "standby"
    return "perf-secondary" if health.get("performance_secondary") else "active"


def _row(check: str, subject: str, value: int, threshold: int) -> dict[str, Any]:
    return {"check": check, "subject": subject, "value": value, "threshold": threshold, "margin": threshold - value, "fires": value > threshold}


def margins(health: dict[str, Any], thresholds: Thresholds = DEFAULT_THRESHOLDS) -> list[dict[str, Any]]:
    """One row per value the rules judge: VT-HLTH-006, VT-SNAP-002 (overdue), VT-REPL-001/003.

    Mirrors health_findings' choice of what to judge, so "fires" never disagrees
    with the audit. Time-based rows need the node's clock and are left out
    without it, where the audit would fall back to wall-clock time.
    """
    rows: list[dict[str, Any]] = []
    now = server_time(health)

    leases = (health.get("metrics") or {}).get("leases")
    if isinstance(leases, int):
        rows.append(_row("VT-HLTH-006 leases", "queried node", leases, thresholds.lease_count_warning))

    for cfg in (health.get("snapshots") or {}).get("configs") or []:
        last, upcoming = parse_time(cfg.get("last_snapshot_start")), parse_time(cfg.get("next_snapshot_start"))
        if now and last and upcoming and not cfg.get("in_progress"):
            grace = int(max((upcoming - last).total_seconds(), thresholds.snapshot_grace_seconds))
            rows.append(_row("VT-SNAP-002 late (s)", cfg.get("name", "?"), int((now - upcoming).total_seconds()), grace))

    for kind, block in (health.get("replication") or {}).items():
        if not isinstance(block, dict) or block.get("mode") in (None, "", "disabled", "unknown"):
            continue
        # Same peer list and the same skips as replication_link_findings: a
        # never-connected peer is VT-REPL-002 only, and VT-REPL-001 judges
        # connected peers only (a disconnected one is VT-HLTH-002).
        for peer in block.get("secondaries") or block.get("primaries") or []:
            if never_connected(peer):
                continue
            subject = f"{kind}:{peer.get('node_id') or 'primary'}"
            if isinstance(peer.get("clock_skew_ms"), int):
                rows.append(_row("VT-REPL-003 |skew| (ms)", subject, abs(peer["clock_skew_ms"]), REPL_CLOCK_SKEW_MS))
            if peer.get("connection_status") != "connected":
                continue
            if isinstance(peer.get("replication_primary_canary_age_ms"), int):
                rows.append(_row("VT-REPL-001 canary (ms)", subject, peer["replication_primary_canary_age_ms"], REPL_CANARY_AGE_MS))
            heartbeat = parse_time(peer.get("last_heartbeat")) if peer.get("last_heartbeat") else None
            if now and heartbeat:
                rows.append(_row("VT-REPL-001 heartbeat (s)", subject, int((now - heartbeat).total_seconds()), REPL_HEARTBEAT_AGE_S))
    return rows


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("files", nargs="+", type=Path, help="cluster-health.json files written by cluster-audit")
    # The same flags, types and defaults as cluster-audit, to check a tuned value.
    parser.add_argument("--lease-count-warning", type=positive_int, default=DEFAULT_THRESHOLDS.lease_count_warning, metavar="N", help="As cluster-audit's flag. Default: %(default)s.")
    parser.add_argument("--snapshot-grace", type=duration_seconds, default=DEFAULT_THRESHOLDS.snapshot_grace_seconds, metavar="DURATION", help="As cluster-audit's flag (e.g. 2h). Default: 25h.")
    args = parser.parse_args(argv)
    thresholds = Thresholds(lease_count_warning=args.lease_count_warning, snapshot_grace_seconds=args.snapshot_grace)

    table: list[dict[str, Any]] = []
    for path in args.files:
        try:
            health = json.loads(path.read_text())
        except (OSError, ValueError) as e:
            print(f"skipped {path}: {e}", file=sys.stderr)
            continue
        context = {"file": path.name, "role": node_role(health), "sampled": (health.get("metrics") or {}).get("timestamp") or "-"}
        table += [{**context, **row} for row in margins(health, thresholds)]
    if not table:
        print("No judged values found.", file=sys.stderr)
        return 1

    cells = [[str(row[c]) for c in COLUMNS] for row in table]
    widths = [max(len(c), *(len(r[i]) for r in cells)) for i, c in enumerate(COLUMNS)]
    print("  ".join(c.ljust(w) for c, w in zip(COLUMNS, widths, strict=True)))
    for r in cells:
        print("  ".join(v.ljust(w) for v, w in zip(r, widths, strict=True)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
