import logging
import os
import time
from datetime import UTC, datetime
from typing import Any, NamedTuple

import hvac
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table

from src.activity_export.findings import client_count, parse_activity_config, usage_findings
from src.common.audit_logger import get_audit_logger
from src.common.exceptions import VaultPermissionError
from src.common.file_utils import FileProcessingError, write_csv, write_json, write_markdown
from src.common.findings import Finding, build_findings_document, coverage_block, get_tool_version, run_block, sort_findings
from src.common.markdown import md_table, render_findings_table
from src.common.utils import FILE_DATE_FORMAT, file_prefix
from src.common.vault_client import VaultAPIError, VaultClient

logger = logging.getLogger(__name__)


def get_activity_data(client: VaultClient, start_date: str, end_date: str) -> dict[str, Any]:
    path = "sys/internal/counters/activity"
    # end_time is inclusive of the whole end date, matching entity-export's
    # T23:59:59Z. It previously stopped at midnight *starting* the end date, so
    # the same -s/-e produced two different windows across the two exporters.
    #
    # In practice Vault normalises this endpoint's window to month boundaries
    # (a request for 08-16..08-16 comes back as 2025-10-01..2026-08-31), so the
    # old value rarely changed the result here. That normalisation is a server
    # behaviour, not a contract, and the entity export endpoint does not apply
    # it -- so the two exporters should agree on what they ask for.
    params = {
        "start_time": f"{start_date}T00:00:00Z",
        "end_time": f"{end_date}T23:59:59Z",
    }

    logger.info(f"Fetching activity data from {start_date} to {end_date}")
    try:
        response = client.get(path, params=params)
        return response.get("data", {})
    except VaultAPIError as e:
        logger.error(f"Vault API request failed: {e}")
        raise


class ActivityExportResult(NamedTuple):
    namespaces: list[dict[str, Any]]
    mounts: list[dict[str, Any]]
    # findings.json document for the VT-CLI checks; main.py derives the exit code from it.
    findings_document: dict[str, Any]


FINDINGS_CSV_HEADERS = ["rule_id", "severity", "namespace", "object", "detail"]


def _read_optional(client: VaultClient, path: str, denied: list[tuple[str, str]], errors: list[tuple[str, str]]) -> dict[str, Any] | None:
    """A root-level read that only enriches the checks. {} on 404, None when denied or failed."""
    try:
        response = client.get(path)
        return response.get("data", response) if isinstance(response, dict) else {}
    except VaultPermissionError:
        denied.append(("", path))
    except Exception as e:
        if isinstance(e.__cause__, hvac.exceptions.InvalidPath):
            return {}
        errors.append(("", f"{path}: {type(e).__name__}"))
    return None


# Default for "the caller has not read activity/monthly": None already means
# "read and found unreadable", so it cannot double as "not read".
NOT_READ: Any = object()


def _covers_current_month(end_date: str, now: datetime) -> bool:
    """The billing-period query excludes the month in progress; read it only if the window reaches it."""
    return end_date >= now.strftime("%Y-%m-01")


def render_activity_findings_report(
    cluster_name: str,
    data: dict[str, Any],
    activity_log: dict[str, Any] | None,
    findings: list[Finding],
    denied: list[tuple[str, str]],
    errors: list[tuple[str, str]],
    *,
    start_date: str,
    end_date: str,
    generated_at: datetime,
    current: dict[str, Any] | None,
    output_files: list[str],
) -> str:
    """The client-usage findings report. Pure: everything comes in as arguments."""
    if activity_log is None:
        log_state = "unreadable — see access gaps"
    else:
        log_state = f"`{activity_log.get('enabled')}`" + ("" if activity_log.get("recording") is not False else " — **nothing is recorded, so every count below reads zero**")
    rows = [
        ["Cluster", cluster_name],
        ["Generated", generated_at.strftime("%Y-%m-%d %H:%M:%S UTC")],
        ["Tool version", f"vault-tools {get_tool_version()}"],
        ["Requested window", f"{start_date} to {end_date}"],
        ["Window Vault reported", f"{(data.get('start_time') or '—')[:10]} to {(data.get('end_time') or '—')[:10]}"],
        ["Activity log", log_state],
        ["Clients in window", client_count(data.get("total"))],
        ["Clients this month (in progress)", "not read" if current is None else client_count(current)],
    ]
    gaps = [[scope, "denied"] for _, scope in denied] + [[message, "error"] for _, message in errors]
    sections = [
        f"# Vault Client Usage Findings — {cluster_name}",
        "",
        md_table(["Field", "Value"], rows),
        "",
        "Vault computes client counts on a delay of about 10 minutes after startup, so zero counts with the log recording can just mean a new cluster.",
        "",
        "## Access gaps",
        "",
        md_table(["Read", "Result"], gaps) if gaps else "None.",
        "",
        "## Security observations",
        "",
        render_findings_table(findings, "_No observations — no token-only sprawl, sharp growth, per-run identities or root-namespace concentration._"),
        "",
        "## Output files",
        "",
        md_table(["File"], [[f] for f in output_files]),
        "",
    ]
    return "\n".join(sections)


def assess_activity(
    client: VaultClient,
    data: dict[str, Any],
    cluster_name: str,
    start_date: str,
    end_date: str,
    output_dir: str,
    is_enterprise: bool | None = None,
    started_at: datetime | None = None,
    current_month: Any = NOT_READ,
    name_prefix: str | None = None,
) -> dict[str, Any]:
    """Run the VT-CLI checks over exported activity and write their findings files.

    Never raises for the extra reads: an unreadable counters/config or month in
    progress leaves those checks unjudged and is recorded in coverage.
    """
    started = started_at or datetime.now(UTC)
    denied: list[tuple[str, str]] = []
    errors: list[tuple[str, str]] = []
    activity_log = parse_activity_config(_read_optional(client, "sys/internal/counters/config", denied, errors))
    if not _covers_current_month(end_date, started):
        current = None
    elif current_month is not NOT_READ:
        # Already read this run (identity-audit, in full-audit).
        current = current_month
    else:
        current = _read_optional(client, "sys/internal/counters/activity/monthly", denied, errors)
    findings = sort_findings(usage_findings(data, current, is_enterprise, activity_log))
    generated = datetime.now(UTC)

    document = build_findings_document(
        findings,
        run=run_block(cluster_name, client.vault_addr or "", "", started, generated),
        cluster_context={
            "vault_version": None,
            "enterprise": is_enterprise,
            "system_max_lease_ttl_seconds": None,
            "system_default_lease_ttl_seconds": None,
            "sentinel": "skipped",
        },
        coverage=coverage_block(len(data.get("by_namespace") or []), denied, errors),
        tool_version=get_tool_version(),
    )

    date_str = datetime.now().strftime(FILE_DATE_FORMAT)
    base = os.path.join(output_dir, f"{name_prefix or cluster_name}-activity-findings-{date_str}")
    written = [f"{base}.json"]
    write_json(f"{base}.json", document)
    if findings:
        # Only with rows, like the other summary CSVs: a header alone is noise.
        write_csv(
            f"{base}.csv",
            [{"rule_id": f.rule_id, "severity": f.severity, "namespace": f.namespace or "/", "object": f.mount, "detail": f.detail} for f in findings],
            FINDINGS_CSV_HEADERS,
        )
        written.append(f"{base}.csv")
    write_markdown(
        f"{base}.md",
        render_activity_findings_report(
            cluster_name,
            data,
            activity_log,
            findings,
            denied,
            errors,
            start_date=start_date,
            end_date=end_date,
            generated_at=generated,
            current=current,
            output_files=[os.path.basename(p) for p in written],
        ),
    )
    return document


def process_activity_data(data: dict[str, Any], cluster_name: str, output_dir: str = "outputs"):
    date_str = datetime.now().strftime(FILE_DATE_FORMAT)

    if not isinstance(data, dict):
        logger.warning("process_activity_data received non-dict data; returning empty results")
        return [], []

    # Process namespaces and mounts
    namespaces_data = []
    mounts_data = []
    for namespace in data.get("by_namespace", []):
        ns_id = namespace.get("namespace_id", "")
        ns_path = namespace.get("namespace_path", "")
        # Convert root namespace path to "root/" when namespace_id is "root"
        if ns_id == "root" and ns_path == "":
            ns_path = "root/"
        elif ns_path == "":
            # Non-root namespace with an empty path is unexpected; preserve the
            # truthful empty string and emit a debug log for observability.
            logger.debug(f"namespace_id {ns_id!r} has empty namespace_path; leaving as-is")
        ns_counts = namespace.get("counts", {})
        namespaces_data.append(
            {
                "namespace_id": ns_id,
                "namespace_path": ns_path,
                "mounts": len(namespace.get("mounts", [])),
                "clients": ns_counts.get("clients", 0),
                "entity_clients": ns_counts.get("entity_clients", 0),
                "non_entity_clients": ns_counts.get("non_entity_clients", 0),
            }
        )
        for mount in namespace.get("mounts", []):
            mount_counts = mount.get("counts", {})
            mounts_data.append(
                {
                    "namespace_id": ns_id,
                    "namespace_path": ns_path,
                    "mount_path": mount.get("mount_path", ""),
                    "clients": mount_counts.get("clients", 0),
                    "entity_clients": mount_counts.get("entity_clients", 0),
                    "non_entity_clients": mount_counts.get("non_entity_clients", 0),
                }
            )

    # Write reports
    try:
        logger.debug(f"Writing activity JSON with data for {len(data.get('by_namespace', []))} namespaces")
        write_json(f"{output_dir}/{cluster_name}-activity-{date_str}.json", data)

        logger.debug(f"Writing activity namespaces CSV with {len(namespaces_data)} namespace entries")
        write_csv(
            f"{output_dir}/{cluster_name}-activity-namespaces-{date_str}.csv",
            namespaces_data,
        )

        logger.debug(f"Writing activity mounts CSV with {len(mounts_data)} mount entries")
        write_csv(f"{output_dir}/{cluster_name}-activity-mounts-{date_str}.csv", mounts_data)
    except FileProcessingError as e:
        logger.error(f"Error writing activity reports: {e}")

    return namespaces_data, mounts_data


def run_activity_export(
    client: VaultClient,
    start_date: str,
    end_date: str,
    cluster_name: str,
    data: dict[str, Any] | None = None,
    output_dir: str = "outputs",
    is_enterprise: bool | None = None,
    current_month: Any = NOT_READ,
    cluster_id: str | None = None,
) -> ActivityExportResult:
    console = Console()
    prefix = file_prefix(cluster_name, cluster_id)
    started_at = datetime.now(UTC)
    audit_logger = get_audit_logger()
    start_time = time.time()

    # Log audit start
    audit_logger.log_tool_execution(
        tool_name="activity-export",
        command=f"activity-export --start-date {start_date} --end-date {end_date}",
        parameters={
            "start_date": start_date,
            "end_date": end_date,
            "cluster_name": cluster_name,
        },
        result="started",
    )

    console.print(
        Panel.fit(
            f"[bold cyan]Vault Activity Export[/bold cyan]\nDate range: [yellow]{start_date}[/yellow] to [yellow]{end_date}[/yellow]\nCluster: [green]{cluster_name}[/green]",
            border_style="cyan",
        )
    )

    try:
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console,
        ) as progress:
            if data is None:
                task = progress.add_task("[cyan]Fetching activity data from Vault...", total=None)
                data = get_activity_data(client, start_date, end_date)
                progress.update(task, completed=True)
                console.print("[green]✓[/green] Activity data retrieved")

            task = progress.add_task("[cyan]Processing and writing reports...", total=None)
            namespaces_data, mounts_data = process_activity_data(data, prefix, output_dir)
            progress.update(task, completed=True)

            task = progress.add_task("[cyan]Checking client usage patterns...", total=None)
            findings_document = assess_activity(client, data, cluster_name, start_date, end_date, output_dir, is_enterprise, started_at, current_month, prefix)
            progress.update(task, completed=True)

        duration = time.time() - start_time

        # Display summary table
        table = Table(title="Export Summary", show_header=True, header_style="bold cyan")
        table.add_column("Metric", style="cyan", width=30)
        table.add_column("Value", style="green", width=20)

        table.add_row("Namespaces Exported", str(len(namespaces_data)))
        table.add_row("Mounts Exported", str(len(mounts_data)))
        table.add_row("Total Clients", str(data.get("total", {}).get("clients", 0)))
        by_severity = findings_document["summary"]["by_severity"]
        table.add_row("Usage findings", ", ".join(f"{n} {s}" for s, n in by_severity.items()))
        table.add_row("Duration", f"{duration:.2f} seconds")

        console.print()
        console.print(table)
        console.print(f"\n[green]✓[/green] Reports written to [cyan]{output_dir}/[/cyan]")

        # Log successful completion
        audit_logger.log_tool_execution(
            tool_name="activity-export",
            command=f"activity-export --start-date {start_date} --end-date {end_date}",
            parameters={
                "start_date": start_date,
                "end_date": end_date,
                "cluster_name": cluster_name,
            },
            result="success",
            duration_seconds=duration,
            metadata={
                "namespaces_exported": len(namespaces_data),
                "mounts_exported": len(mounts_data),
                "total_clients": data.get("total", {}).get("clients", 0),
            },
        )

        # Log data export
        audit_logger.log_data_export(
            export_type="activity",
            record_count=len(namespaces_data) + len(mounts_data),
            output_file=f"{output_dir}/{prefix}-activity-*.csv",
            filters={"start_date": start_date, "end_date": end_date},
        )

        return ActivityExportResult(namespaces_data, mounts_data, findings_document)

    except Exception as e:
        error_msg = str(e)
        console.print(f"[red]✗[/red] Export failed: {error_msg}")

        # Log failure
        audit_logger.log_tool_execution(
            tool_name="activity-export",
            command=f"activity-export --start-date {start_date} --end-date {end_date}",
            parameters={
                "start_date": start_date,
                "end_date": end_date,
                "cluster_name": cluster_name,
            },
            result="failure",
            duration_seconds=time.time() - start_time,
            error=error_msg,
        )
        raise
