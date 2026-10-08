"""`identity-audit` subcommand: identity entities, aliases and direct policies (VT-ID-001..005)."""

from __future__ import annotations

import logging
import os
from datetime import UTC, datetime
from typing import Any, NamedTuple

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from src.common.exceptions import VaultConnectionError
from src.common.file_utils import write_csv, write_json, write_markdown
from src.common.findings import SEVERITY_ORDER, sort_findings
from src.common.utils import FILE_DATE_FORMAT, file_prefix
from src.common.vault_client import VaultClient
from src.identity_audit.collector import IdentityCoverage, active_entity_clients, collect_entities, discover_namespaces, read_activity
from src.identity_audit.findings import entity_findings
from src.identity_audit.report import build_identity_findings_json, build_identity_report, entity_rows, namespace_rows

logger = logging.getLogger(__name__)

CSV_HEADERS = ["namespace", "entities", "disabled", "without_aliases", "with_direct_policies", "unreadable", "alias_mount_types"]


class IdentityAuditResult(NamedTuple):
    document: dict[str, Any]
    # The activity/monthly read, handed on to activity-export in full-audit.
    # None when unreadable; {} when nothing is recorded.
    current_month: dict[str, Any] | None


def run_identity_audit(vault_client: VaultClient, output_dir: str, **kwargs: Any) -> dict[str, Any] | None:
    """Collect, judge and write the identity audit. Returns the findings document, or None on failure."""
    result = run_identity_audit_full(vault_client, output_dir, **kwargs)
    return result.document if result else None


def run_identity_audit_full(
    vault_client: VaultClient,
    output_dir: str,
    *,
    workers: int = 4,
    include_list: bool = False,
    namespaces: list[str] | None = None,
    console: Console | None = None,
) -> IdentityAuditResult | None:
    """run_identity_audit, also returning the current-month activity it read.

    ``namespaces`` (stored keys, "" for root) skips discovery: full-audit passes
    the tree its namespace walk already found.
    """
    console = console or Console()
    console.print(Panel.fit(f"[bold cyan]Vault Identity Audit[/bold cyan]\nVault address: [yellow]{vault_client.vault_addr}[/yellow]\nWorker threads: [green]{workers}[/green]", border_style="cyan"))
    started = datetime.now(UTC)
    try:
        info = vault_client.validate_connection()
    except VaultConnectionError as e:
        console.print(f"[red]✗[/red] Connection failed: {e}")
        return None
    console.print(f"[green]✓[/green] Connected to cluster: [bold]{info.cluster_name}[/bold]")

    coverage = IdentityCoverage()
    with console.status("[cyan]Reading identity entities..."):
        tree = namespaces if namespaces is not None else discover_namespaces(vault_client, workers, coverage)
        entities, coverage = collect_entities(vault_client, tree, workers, coverage)
        # Read at root: the activity log reports every namespace.
        activity = read_activity(vault_client, "sys/internal/counters/activity", coverage)
        current = read_activity(vault_client, "sys/internal/counters/activity/monthly", coverage)
    active = active_entity_clients(activity, current)

    generated = datetime.now(UTC)
    findings = sort_findings(entity_findings(entities, active))
    document = build_identity_findings_json(
        info.cluster_name,
        coverage,
        findings,
        vault_addr=vault_client.vault_addr,
        started_at=started,
        finished_at=generated,
        worker_threads=workers,
        vault_version=info.vault_version,
        is_enterprise=info.is_enterprise,
    )

    os.makedirs(output_dir, exist_ok=True)
    date_str = generated.strftime(FILE_DATE_FORMAT)

    def path_for(kind: str, extension: str) -> str:
        return os.path.join(output_dir, f"{file_prefix(info.cluster_name, info.cluster_id)}-{kind}-{date_str}.{extension}")

    written: list[str] = []
    write_json(path_for("identity-findings", "json"), document)
    written.append(path_for("identity-findings", "json"))
    rows = namespace_rows(entities)
    if rows:
        write_csv(path_for("identity-summary", "csv"), rows, CSV_HEADERS)
        written.append(path_for("identity-summary", "csv"))
    if include_list:
        write_json(path_for("identity-entities", "json"), entity_rows(entities))
        written.append(path_for("identity-entities", "json"))
    report_path = path_for("identity-audit-report", "md")
    try:
        write_markdown(
            report_path,
            build_identity_report(
                info.cluster_name,
                entities,
                coverage,
                findings,
                active,
                vault_addr=vault_client.vault_addr,
                generated_at=generated,
                output_files=[os.path.basename(p) for p in written],
                listed=include_list,
            ),
        )
        written.append(report_path)
    except Exception as e:
        logger.exception(f"Failed to write the identity report: {e}")
        console.print(f"[yellow]⚠[/yellow] Markdown report could not be written: {e}")

    table = Table(title="Identity Audit Summary")
    table.add_column("Metric", style="cyan")
    table.add_column("Value", style="magenta")
    table.add_row("Namespaces", str(len(entities)))
    table.add_row("Entities", str(sum(len(items) for items in entities.values())))
    by_severity = document["summary"]["by_severity"]
    table.add_row("Findings", ", ".join(f"{by_severity.get(s.lower(), 0)} {s.lower()}" for s in SEVERITY_ORDER))
    table.add_row("Denied", str(len(coverage.denied)))
    table.add_row("Errors", str(len(coverage.errors)))
    console.print(table)
    console.print(f"\n[bold]Output files[/bold] → [cyan]{output_dir}/[/cyan]")
    for path in written:
        console.print(f"  [green]✓[/green] {os.path.basename(path)}")
    return IdentityAuditResult(document, current)
