"""`diff` subcommand: compare two findings.json documents.

Needs no Vault connection. Works on documents from vault-tools or the vault-ops
skill, since both write the same schema and the same fingerprints.
"""

import os
from datetime import datetime
from typing import Any

from rich.console import Console
from rich.table import Table

from src.common.exceptions import FileProcessingError
from src.common.file_utils import read_json, write_json
from src.common.findings import diff_documents
from src.common.utils import FILE_DATE_FORMAT


def _load_findings(path: str) -> dict[str, Any]:
    document = read_json(path)
    if not isinstance(document, dict) or not isinstance(document.get("findings"), list):
        raise FileProcessingError(f"{path} is not a findings document (no 'findings' list) — pass a *-findings-*.json file")
    return document


def run_diff(old_path: str, new_path: str, output_dir: str, console: Console | None = None) -> str:
    """Write ``diff-{date}.json`` to ``output_dir`` and print a summary; return the path."""
    console = console or Console()
    result = diff_documents(_load_findings(old_path), _load_findings(new_path))

    file_path = os.path.join(output_dir, f"diff-{datetime.now().strftime(FILE_DATE_FORMAT)}.json")
    write_json(file_path, result)

    summary = result["summary"]
    table = Table(title="Findings diff")
    table.add_column("Change", style="cyan")
    table.add_column("Count", justify="right")
    for label, key in (("New", "new"), ("Resolved", "resolved"), ("Unchanged", "unchanged"), ("Evidence changed", "evidence_changed")):
        table.add_row(label, str(summary[key]))
    console.print(table)

    if result["new"]:
        new_table = Table(title="New findings")
        for column in ("Rule", "Severity", "Namespace", "Object", "Detail"):
            new_table.add_column(column)
        for f in result["new"]:
            new_table.add_row(f["rule_id"], f["severity"], f["namespace"], (f.get("object") or {}).get("path") or "—", f["detail"])
        console.print(new_table)

    console.print(f"\n[bold]Output files[/bold] → [cyan]{output_dir}/[/cyan]\n  [green]✓[/green] {os.path.basename(file_path)}")
    return file_path
