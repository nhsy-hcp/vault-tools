import logging
import time
from datetime import datetime
from typing import Any

import pandas as pd
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table

from src.common.audit_logger import get_audit_logger
from src.common.file_utils import FileProcessingError, write_csv, write_json
from src.common.vault_client import VaultClient

logger = logging.getLogger(__name__)


def get_entity_export_data(client: VaultClient, start_date: str, end_date: str) -> list[dict[str, Any]]:
    start_rfc3339 = f"{start_date}T00:00:00Z"
    end_rfc3339 = f"{end_date}T23:59:59Z"
    params = {"start_time": start_rfc3339, "end_time": end_rfc3339, "format": "json"}

    logger.info(f"Fetching entity export data from {start_date} to {end_date}")
    return client.get("sys/internal/counters/activity/export", params=params)


def process_entity_export_data(data: list[dict[str, Any]], cluster_name: str, output_dir: str = "outputs") -> pd.DataFrame | None:
    if not data:
        logger.warning("No entity data to process")
        return None

    df = pd.DataFrame(data)
    if "client_type" not in df.columns:
        logger.error("Column 'client_type' not found in data")
        return None

    df["entity_type"] = df["client_type"]

    # Convert root namespace path to "root/" when namespace_id is "root"
    if "namespace_id" in df.columns and "namespace_path" in df.columns:
        mask = (df["namespace_id"] == "root") & (df["namespace_path"] == "")
        df.loc[mask, "namespace_path"] = "root/"

    date_str = datetime.now().strftime("%Y%m%d")

    try:
        logger.debug(f"Writing entity export JSON with {len(data)} entity records")
        write_json(f"{output_dir}/{cluster_name}-entity-export-{date_str}.json", data)

        # Convert numeric columns to int to avoid float output in CSV
        numeric_columns = df.select_dtypes(include=["float64"]).columns
        df[numeric_columns] = df[numeric_columns].astype("int64")

        logger.debug(f"Writing entity export CSV with {len(df)} entity records")
        write_csv(
            f"{output_dir}/{cluster_name}-entity-export-{date_str}.csv",
            df.to_dict("records"),
            df.columns.tolist(),
        )
    except FileProcessingError as e:
        logger.error(f"Failed to write entity export reports: {e}")
        return None

    return df


def run_entity_export(
    client: VaultClient,
    start_date: str,
    end_date: str,
    cluster_name: str,
    data: list[dict[str, Any]] | None = None,
    output_dir: str = "outputs",
):
    console = Console()
    audit_logger = get_audit_logger()
    start_time = time.time()

    # Log audit start
    audit_logger.log_tool_execution(
        tool_name="entity-export",
        command=f"entity-export --start-date {start_date} --end-date {end_date}",
        parameters={
            "start_date": start_date,
            "end_date": end_date,
            "cluster_name": cluster_name,
        },
        result="started",
    )

    console.print(
        Panel.fit(
            f"[bold cyan]Vault Entity Export[/bold cyan]\n" f"Date range: [yellow]{start_date}[/yellow] to [yellow]{end_date}[/yellow]\n" f"Cluster: [green]{cluster_name}[/green]",
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
                task = progress.add_task("[cyan]Fetching entity export data from Vault...", total=None)
                data = get_entity_export_data(client, start_date, end_date)
                progress.update(task, completed=True)
                console.print("[green]✓[/green] Entity data retrieved")

            task = progress.add_task("[cyan]Processing and writing reports...", total=None)
            df = process_entity_export_data(data, cluster_name, output_dir)
            progress.update(task, completed=True)

        duration = time.time() - start_time

        if df is not None:
            # Display summary table
            table = Table(title="Export Summary", show_header=True, header_style="bold cyan")
            table.add_column("Metric", style="cyan", width=30)
            table.add_column("Value", style="green", width=20)

            table.add_row("Total Entities", str(len(df)))

            # Count by entity type
            if "entity_type" in df.columns:
                entity_counts = df["entity_type"].value_counts()
                for entity_type, count in entity_counts.items():
                    table.add_row(f"  {entity_type}", str(count))

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
                tool_name="entity-export",
                command=f"entity-export --start-date {start_date} --end-date {end_date}",
                parameters={
                    "start_date": start_date,
                    "end_date": end_date,
                    "cluster_name": cluster_name,
                },
                result="success",
                duration_seconds=duration,
                metadata={
                    "entities_exported": len(df),
                    "cache_stats": cache_stats,
                },
            )

            # Log data export
            audit_logger.log_data_export(
                export_type="entities",
                record_count=len(df),
                output_file=f"{output_dir}/{cluster_name}-entity-export-*.csv",
                filters={"start_date": start_date, "end_date": end_date},
            )
        else:
            console.print("[yellow]⚠[/yellow] No entity data to export")

            # Log partial success
            audit_logger.log_tool_execution(
                tool_name="entity-export",
                command=f"entity-export --start-date {start_date} --end-date {end_date}",
                parameters={
                    "start_date": start_date,
                    "end_date": end_date,
                    "cluster_name": cluster_name,
                },
                result="partial",
                duration_seconds=duration,
                metadata={"message": "No entity data available"},
            )

    except Exception as e:
        error_msg = str(e)
        console.print(f"[red]✗[/red] Export failed: {error_msg}")

        # Log failure
        audit_logger.log_tool_execution(
            tool_name="entity-export",
            command=f"entity-export --start-date {start_date} --end-date {end_date}",
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
