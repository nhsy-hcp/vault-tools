"""`diff` subcommand: compare two findings.json documents.

Needs no Vault connection. Works on documents from vault-tools or the vault-ops
skill, since both write the same schema and the same fingerprints.
"""

import glob
import os
from datetime import datetime
from typing import Any

from rich.console import Console
from rich.table import Table

from src.common.exceptions import FileProcessingError
from src.common.file_utils import latest_files, read_json, write_json
from src.common.findings import diff_documents
from src.common.utils import FILE_DATE_FORMAT

# What full-audit writes; the per-command findings files are not auto-picked.
FULL_FINDINGS_PATTERN = "*-full-findings-*.json"


def _load_findings(path: str) -> dict[str, Any]:
    document = read_json(path)
    if not isinstance(document, dict) or not isinstance(document.get("findings"), list):
        raise FileProcessingError(f"{path} is not a findings document (no 'findings' list) — pass a *-findings-*.json file")
    return document


def pick_latest_pair(output_dir: str) -> tuple[str, str]:
    """The two newest full-audit findings files for one cluster in ``output_dir``, as ``(old, new)``.

    The cluster is the newest file's: a shared output directory must not pair
    one cluster's run with another's.
    """
    newest = latest_files(output_dir, FULL_FINDINGS_PATTERN, n=1)
    found = newest
    if newest:
        prefix = os.path.basename(newest[0]).rpartition("-full-findings-")[0]
        found = latest_files(output_dir, f"{glob.escape(prefix)}-full-findings-*.json", n=2)
    if len(found) < 2:
        raise FileProcessingError(
            f"diff needs two findings files; found {len(found)} full-findings file{'' if len(found) == 1 else 's'} for this cluster in {output_dir}. Pass OLD and NEW explicitly."
        )
    return found[1], found[0]


def run_diff(old_path: str | None, new_path: str | None, output_dir: str, console: Console | None = None) -> str:
    """Write ``diff-{date}.json`` to ``output_dir`` and print a summary; return the path.

    With neither path given, compares the two newest ``*-full-findings-*.json``
    files in ``output_dir``. Giving only one is an error.
    """
    console = console or Console()
    if old_path is None and new_path is None:
        old_path, new_path = pick_latest_pair(output_dir)
        console.print(f"Comparing the two newest full-audit findings in [cyan]{output_dir}/[/cyan]:\n  old: {os.path.basename(old_path)}\n  new: {os.path.basename(new_path)}")
    elif old_path is None or new_path is None:
        raise FileProcessingError("diff takes both OLD and NEW, or neither (to compare the two newest full-findings files in the output directory).")
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
