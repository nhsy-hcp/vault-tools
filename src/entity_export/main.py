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
from src.common.utils import FILE_DATE_FORMAT
from src.common.vault_client import VaultClient

logger = logging.getLogger(__name__)


# Columns without which processing genuinely cannot proceed. Only client_type
# qualifies — it is the source of the derived entity_type column.
#
# namespace_id / namespace_path are deliberately NOT required: Vault omits them
# on non-namespaced (OSS) clusters and on older API versions, and the export is
# still perfectly usable without them. Requiring them turned a working export
# into a silent no-op for those clusters.
REQUIRED_COLUMNS = frozenset({"client_type"})

# Optional columns used only for the root-namespace display fix-up below.
NAMESPACE_COLUMNS = ("namespace_id", "namespace_path")


def get_entity_export_data(client: VaultClient, start_date: str, end_date: str) -> list[dict[str, Any]]:
    """Fetch entity export data from Vault.

    Args:
        client: Vault client instance.
        start_date: Start date string in YYYY-MM-DD format.
        end_date: End date string in YYYY-MM-DD format.

    Returns:
        list[dict[str, Any]]: List of entity records returned by the Vault API.
    """
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
    missing = REQUIRED_COLUMNS - set(df.columns)
    if missing:
        logger.error(f"Required columns missing from entity export data: {sorted(missing)}")
        return None

    df["entity_type"] = df["client_type"]

    # Convert root namespace path to "root/" when namespace_id is "root".
    # Absent namespace columns are normal on OSS clusters — note it and carry on.
    if all(column in df.columns for column in NAMESPACE_COLUMNS):
        mask = (df["namespace_id"] == "root") & (df["namespace_path"] == "")
        df.loc[mask, "namespace_path"] = "root/"
    else:
        missing_optional = [column for column in NAMESPACE_COLUMNS if column not in df.columns]
        logger.warning(f"Namespace columns absent from entity export data: {missing_optional}. Skipping root namespace normalisation; the export is otherwise unaffected.")

    date_str = datetime.now().strftime(FILE_DATE_FORMAT)

    try:
        logger.debug(f"Writing entity export JSON with {len(data)} entity records")
        write_json(f"{output_dir}/{cluster_name}-entity-export-{date_str}.json", data)

        # Convert numeric columns to int to avoid float output in CSV.
        # fillna(0) first: without it, NaN survives the cast and pandas writes
        # the literal string "<NA>" into the CSV, turning a numeric column into
        # text for every downstream consumer. Matches namespace_audit.
        numeric_columns = df.select_dtypes(include=["float64"]).columns
        df[numeric_columns] = df[numeric_columns].fillna(0).astype("int64")

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
            f"[bold cyan]Vault Entity Export[/bold cyan]\nDate range: [yellow]{start_date}[/yellow] to [yellow]{end_date}[/yellow]\nCluster: [green]{cluster_name}[/green]",
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
