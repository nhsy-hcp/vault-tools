import logging
import time
from datetime import datetime
from typing import Any

from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table

from src.common.audit_logger import get_audit_logger
from src.common.file_utils import FileProcessingError, write_csv, write_json
from src.common.vault_client import VaultAPIError, VaultClient

logger = logging.getLogger(__name__)


def get_activity_data(client: VaultClient, start_date: str, end_date: str) -> dict[str, Any]:
    path = "sys/internal/counters/activity"
    params = {
        "start_time": f"{start_date}T00:00:00Z",
        "end_time": f"{end_date}T00:00:00Z",
    }

    logger.info(f"Fetching activity data from {start_date} to {end_date}")
    try:
        response = client.get(path, params=params)
        return response.get("data", {})
    except VaultAPIError as e:
        logger.error(f"Vault API request failed: {e}")
        raise


def process_activity_data(data: dict[str, Any], cluster_name: str, output_dir: str = "outputs"):
    date_str = datetime.now().strftime("%Y%m%d")

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
):
    console = Console()
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
            f"[bold cyan]Vault Activity Export[/bold cyan]\n" f"Date range: [yellow]{start_date}[/yellow] to [yellow]{end_date}[/yellow]\n" f"Cluster: [green]{cluster_name}[/green]",
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
            namespaces_data, mounts_data = process_activity_data(data, cluster_name, output_dir)
            progress.update(task, completed=True)

        duration = time.time() - start_time

        # Display summary table
        table = Table(title="Export Summary", show_header=True, header_style="bold cyan")
        table.add_column("Metric", style="cyan", width=30)
        table.add_column("Value", style="green", width=20)

        table.add_row("Namespaces Exported", str(len(namespaces_data)))
        table.add_row("Mounts Exported", str(len(mounts_data)))
        table.add_row("Total Clients", str(data.get("total", {}).get("clients", 0)))
        table.add_row("Duration", f"{duration:.2f} seconds")

        console.print("\n")
        console.print(table)
        console.print(f"\n[green]✓[/green] Reports written to [cyan]{output_dir}/[/cyan]")

        # Display cache statistics
        cache_stats = client.get_cache_stats()
        console.print("\n[bold]Cache Performance:[/bold]")
        console.print(f"  Hits: [green]{cache_stats['hits']}[/green] | Misses: [yellow]{cache_stats['misses']}[/yellow] | Hit Rate: [cyan]{cache_stats['hit_rate']}[/cyan]")

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
                "cache_stats": cache_stats,
            },
        )

        # Log data export
        audit_logger.log_data_export(
            export_type="activity",
            record_count=len(namespaces_data) + len(mounts_data),
            output_file=f"{output_dir}/{cluster_name}-activity-*.csv",
            filters={"start_date": start_date, "end_date": end_date},
        )

        return namespaces_data, mounts_data

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
