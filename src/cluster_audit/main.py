"""`cluster-audit` subcommand: cluster-level health, audit devices, snapshots and metrics.

Unlike namespace-audit this works against a sealed, uninitialised or DR-secondary
node: it reads the unauthenticated ``sys/health`` first and only validates the
token when the node can serve authenticated reads at all.
"""

from __future__ import annotations

import logging
import os
from datetime import UTC, datetime
from typing import Any, NamedTuple

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from src.cluster_audit.collector import (
    ClusterCoverage,
    ClusterReads,
    collect_cluster_health,
    fetch_license_status,
    fetch_system_lease_ttls,
    read_health,
    unauthenticated_only,
)
from src.cluster_audit.report import build_cluster_findings_json, build_cluster_report, collect_cluster_findings
from src.common.exceptions import VaultConnectionError
from src.common.file_utils import write_json, write_markdown
from src.common.findings import SEVERITY_ORDER
from src.common.utils import FILE_DATE_FORMAT
from src.common.vault_client import VaultClient

logger = logging.getLogger(__name__)

_NODE_STATE = {
    "sealed": "sealed — only seal status was read",
    "uninitialized": "not initialized — only seal status was read",
    "dr_secondary": "DR secondary — only unauthenticated status was read",
}


class ClusterAuditResult(NamedTuple):
    document: dict[str, Any]
    health: dict[str, Any]
    coverage: ClusterCoverage
    cluster_name: str
    # "sealed", "uninitialized" or "dr_secondary" when the node rejects
    # authenticated reads; None when it serves them.
    unavailable_reason: str | None
    reads: ClusterReads


def run_cluster_audit(vault_client: VaultClient, output_dir: str, console: Console | None = None) -> dict[str, Any] | None:
    """Collect, judge and write the cluster audit. Returns the findings document, or None on failure."""
    result = run_cluster_audit_full(vault_client, output_dir, console)
    return result.document if result else None


def run_cluster_audit_full(vault_client: VaultClient, output_dir: str, console: Console | None = None) -> ClusterAuditResult | None:
    """run_cluster_audit, also returning what was collected so full-audit can reuse it."""
    console = console or Console()
    console.print(Panel.fit(f"[bold cyan]Vault Cluster Audit[/bold cyan]\nVault address: [yellow]{vault_client.vault_addr}[/yellow]", border_style="cyan"))
    started = datetime.now(UTC)

    health_status = read_health(vault_client)
    if health_status is None:
        console.print(f"[red]✗[/red] Cannot reach Vault at {vault_client.vault_addr} (sys/health did not answer).")
        return None

    reason = unauthenticated_only(health_status)
    cluster_name = health_status.get("cluster_name") or "vault"
    if reason is None:
        try:
            cluster_name = vault_client.validate_connection().cluster_name
        except VaultConnectionError as e:
            console.print(f"[red]✗[/red] Connection failed: {e}")
            return None
        console.print(f"[green]✓[/green] Connected to cluster: [bold]{cluster_name}[/bold]")
    else:
        # A sealed node does not report its name; the address identifies it.
        console.print(f"[yellow]⚠[/yellow] Node is {_NODE_STATE[reason]}.")

    health, coverage = collect_cluster_health(vault_client, health_status)
    lease_ttls = None
    license_result = None
    if reason is None:
        lease_ttls = fetch_system_lease_ttls(vault_client)
        license_result = fetch_license_status(vault_client, health.get("enterprise"))
        if license_result.is_enterprise is not None:
            health["enterprise"] = license_result.is_enterprise

    generated = datetime.now(UTC)
    license_status = license_result.status if license_result else None
    license_reason = license_result.unavailable_reason if license_result else None
    findings = collect_cluster_findings(health, license_status=license_status, system_lease_ttls=lease_ttls, now=generated)

    os.makedirs(output_dir, exist_ok=True)
    date_str = generated.strftime(FILE_DATE_FORMAT)

    def path_for(kind: str, extension: str) -> str:
        return os.path.join(output_dir, f"{cluster_name}-{kind}-{date_str}.{extension}")

    document = build_cluster_findings_json(
        cluster_name,
        health,
        coverage,
        findings,
        vault_addr=vault_client.vault_addr,
        started_at=started,
        finished_at=generated,
        system_lease_ttls=lease_ttls,
        license_unavailable_reason=license_reason,
    )
    written: list[str] = []
    write_json(path_for("cluster-health", "json"), health)
    written.append(path_for("cluster-health", "json"))
    write_json(path_for("cluster-findings", "json"), document)
    written.append(path_for("cluster-findings", "json"))
    report_path = path_for("cluster-audit-report", "md")
    try:
        write_markdown(
            report_path,
            build_cluster_report(
                cluster_name,
                health,
                coverage,
                findings,
                vault_addr=vault_client.vault_addr,
                generated_at=generated,
                license_status=license_status,
                license_unavailable_reason=license_reason,
                system_lease_ttls=lease_ttls,
                output_files=[os.path.basename(p) for p in written],
            ),
        )
        written.append(report_path)
    except Exception as e:
        # The JSON files carry the data; a rendering failure must not lose them.
        logger.exception(f"Failed to write the cluster report: {e}")
        console.print(f"[yellow]⚠[/yellow] Markdown report could not be written: {e}")

    _print_summary(console, health, document)
    console.print(f"\n[bold]Output files[/bold] → [cyan]{output_dir}/[/cyan]")
    for path in written:
        console.print(f"  [green]✓[/green] {os.path.basename(path)}")
    return ClusterAuditResult(document, health, coverage, cluster_name, reason, ClusterReads(health, coverage, license_result, lease_ttls))


def _print_summary(console: Console, health: dict[str, Any], document: dict[str, Any]) -> None:
    table = Table(title="Cluster Audit Summary")
    table.add_column("Metric", style="cyan")
    table.add_column("Value", style="magenta")
    table.add_row("Vault version", str(health.get("version") or "—"))
    table.add_row("Sealed", "yes" if health.get("sealed") else "no")
    devices = health.get("audit_devices")
    table.add_row("Audit devices", "not read" if devices is None else str(len(devices)))
    by_severity = document["summary"]["by_severity"]
    table.add_row("Findings", ", ".join(f"{by_severity.get(s.lower(), 0)} {s.lower()}" for s in SEVERITY_ORDER))
    coverage = document["coverage"]
    table.add_row("Denied reads", str(len(coverage["denied"])))
    table.add_row("Errors", str(len(coverage["errors"])))
    console.print(table)
