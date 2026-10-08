"""`full-audit` subcommand: every audit and export in one run, with one combined report.

Order: cluster-audit, namespace-audit, identity-audit, activity-export (with its
usage checks), entity-export. Each step writes exactly the files it writes on
its own; full-audit adds ``{cluster}-full-findings-{date}.json`` and
``{cluster}-full-audit-{date}.md`` on top.

What is shared rather than read twice: the token is validated by cluster-audit;
namespace-audit reuses its cluster health; identity-audit reuses the namespace
list the walk found. A failing step is recorded and the next one still runs.
On a node that rejects authenticated reads (sealed, uninitialised, DR
secondary) only cluster-audit runs; the rest are marked skipped.
"""

from __future__ import annotations

import logging
import os
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, date, datetime
from typing import Any

from rich.console import Console
from rich.table import Table

from src.activity_export.main import NOT_READ, run_activity_export
from src.cluster_audit.main import run_cluster_audit_full
from src.common.file_utils import write_json, write_markdown
from src.common.findings import SEVERITY_ORDER, finding_from_dict, get_tool_version, merge_documents, run_block
from src.common.markdown import md_escape, md_table, render_findings_table
from src.common.utils import FILE_DATE_FORMAT
from src.common.vault_client import VaultClient
from src.entity_export.main import run_entity_export
from src.identity_audit.main import run_identity_audit_full
from src.namespace_audit.main import NamespaceAuditor

logger = logging.getLogger(__name__)

STEPS = ("cluster-audit", "namespace-audit", "identity-audit", "activity-export", "entity-export")
MAX_REASON_LENGTH = 200


@dataclass
class StepResult:
    name: str
    status: str  # "ok", "failed" or "skipped"
    reason: str = ""
    document: dict[str, Any] | None = None
    extra: dict[str, Any] = field(default_factory=dict)

    @property
    def findings(self) -> int | None:
        return self.document["summary"]["total"] if self.document else None


def default_window(today: date) -> tuple[str, str]:
    """The last 12 calendar months: the first of the month 11 months back, to today."""
    month_index = today.year * 12 + today.month - 1 - 11
    start = date(month_index // 12, month_index % 12 + 1, 1)
    return start.isoformat(), today.isoformat()


def _run_step(name: str, results: list[StepResult], console: Console, fn: Callable[[], StepResult]) -> StepResult:
    """Run one step; any exception becomes a failed result instead of ending the run."""
    console.rule(f"[bold]{name}")
    try:
        result = fn()
    except Exception as e:
        logger.exception(f"{name} failed: {e}")
        result = StepResult(name, "failed", f"{type(e).__name__}: {e}"[:MAX_REASON_LENGTH])
    results.append(result)
    return result


def run_full_audit(
    vault_client: VaultClient,
    output_dir: str,
    *,
    workers: int = 4,
    collect_sentinel: bool = True,
    collect_acl_bodies: bool = False,
    include_entity_list: bool = False,
    start_date: str | None = None,
    end_date: str | None = None,
    console: Console | None = None,
) -> dict[str, Any] | None:
    """Run every step and write the combined files. Returns the merged findings document, or None if Vault was unreachable."""
    console = console or Console()
    started = datetime.now(UTC)
    # Wall-clock floor for "written by this run": steps name files by local or
    # UTC date inconsistently, and same-day leftovers share their names.
    started_epoch = time.time()
    if not (start_date and end_date):
        start_date, end_date = default_window(started.date())
    results: list[StepResult] = []

    cluster = None

    def cluster_step() -> StepResult:
        nonlocal cluster
        cluster = run_cluster_audit_full(vault_client, output_dir, console)
        if cluster is None:
            return StepResult("cluster-audit", "failed", "Vault unreachable or the token was rejected — see the message above.")
        return StepResult("cluster-audit", "ok", document=cluster.document)

    _run_step("cluster-audit", results, console, cluster_step)
    if cluster is None:
        # Nothing else can connect either; there is no cluster name to file a report under.
        return None

    if cluster.unavailable_reason:
        reason = f"skipped: node is {cluster.unavailable_reason.replace('_', ' ')} and cannot serve authenticated reads"
        results.extend(StepResult(name, "skipped", reason) for name in STEPS[1:])
    else:
        namespaces: list[str] | None = None

        def namespace_step() -> StepResult:
            nonlocal namespaces
            auditor = NamespaceAuditor(
                vault_client,
                worker_threads=workers,
                output_dir=output_dir,
                collect_sentinel=collect_sentinel,
                collect_acl_bodies=collect_acl_bodies,
                cluster_reads=cluster.reads,
            )
            document = auditor.audit_cluster()
            if document is None:
                return StepResult("namespace-audit", "failed", "the namespace walk failed — see the message above.")
            namespaces = sorted(auditor.data.auth_methods) or None
            return StepResult("namespace-audit", "ok", document=document, extra={"sentinel": document["cluster_context"]["sentinel"]})

        current_month: Any = NOT_READ

        def identity_step() -> StepResult:
            nonlocal current_month
            result = run_identity_audit_full(vault_client, output_dir, workers=workers, include_list=include_entity_list, namespaces=namespaces, console=console)
            if result is None:
                return StepResult("identity-audit", "failed", "see the message above.")
            current_month = result.current_month
            return StepResult("identity-audit", "ok", document=result.document)

        def activity_step() -> StepResult:
            result = run_activity_export(
                vault_client,
                start_date,
                end_date,
                cluster.cluster_name,
                output_dir=output_dir,
                is_enterprise=cluster.health.get("enterprise"),
                current_month=current_month,
            )
            return StepResult("activity-export", "ok", document=result.findings_document)

        def entity_step() -> StepResult:
            run_entity_export(vault_client, start_date, end_date, cluster.cluster_name, output_dir=output_dir)
            return StepResult("entity-export", "ok", "export only — no findings")

        for name, fn in (("namespace-audit", namespace_step), ("identity-audit", identity_step), ("activity-export", activity_step), ("entity-export", entity_step)):
            _run_step(name, results, console, fn)

    finished = datetime.now(UTC)
    documents = [r.document for r in results if r.document]
    sentinel = next((r.extra["sentinel"] for r in results if "sentinel" in r.extra), "skipped")
    merged = merge_documents(
        documents,
        run=run_block(cluster.cluster_name, vault_client.vault_addr, "", started, finished, workers),
        cluster_context={**cluster.document["cluster_context"], "sentinel": sentinel},
        tool_version=get_tool_version(),
    )
    # A step that failed outright judged nothing, so the run cannot be complete.
    if any(r.status == "failed" for r in results):
        merged["coverage"]["complete"] = False
        merged["coverage"]["errors"].extend({"namespace": "/", "message": f"{r.name}: {r.reason}"[:MAX_REASON_LENGTH]} for r in results if r.status == "failed")

    date_str = finished.strftime(FILE_DATE_FORMAT)
    findings_path = os.path.join(output_dir, f"{cluster.cluster_name}-full-findings-{date_str}.json")
    report_path = os.path.join(output_dir, f"{cluster.cluster_name}-full-audit-{date_str}.md")
    write_json(findings_path, merged)
    step_files = files_written_since(output_dir, cluster.cluster_name, started_epoch, exclude={report_path})
    try:
        write_markdown(
            report_path,
            build_full_report(
                cluster.cluster_name,
                merged,
                results,
                vault_addr=vault_client.vault_addr,
                generated_at=finished,
                window=(start_date, end_date),
                output_files=step_files,
                vault_version=cluster.health.get("version"),
            ),
        )
    except Exception as e:
        logger.exception(f"Failed to write the full audit report: {e}")
        console.print(f"[yellow]⚠[/yellow] Markdown report could not be written: {e}")

    _print_summary(console, results, merged)
    console.print(f"\n[bold]Combined files[/bold] → [cyan]{output_dir}/[/cyan]")
    for path in (findings_path, report_path):
        if os.path.exists(path):
            console.print(f"  [green]✓[/green] {os.path.basename(path)}")
    return merged


def files_written_since(output_dir: str, cluster_name: str, since: float, exclude: set[str] | None = None) -> list[str]:
    """Basenames of this cluster's files modified at or after ``since``.

    Found on disk rather than collected from each step: several writers skip
    empty outputs, and the steps disagree on local vs UTC dates in file names.
    A leftover from an earlier run — an identity ``--list`` file, say — is older
    than ``since`` and so is never claimed as this run's output.
    """
    exclude = {os.path.abspath(p) for p in exclude or set()}
    found = []
    try:
        entries = list(os.scandir(output_dir))
    except OSError:
        return []
    for entry in entries:
        if not entry.is_file() or not entry.name.startswith(f"{cluster_name}-") or os.path.abspath(entry.path) in exclude:
            continue
        # One second of slack: some filesystems store whole-second mtimes.
        if entry.stat().st_mtime >= since - 1:
            found.append(entry.name)
    return sorted(found)


def build_full_report(
    cluster_name: str,
    merged: dict[str, Any],
    results: list[StepResult],
    *,
    vault_addr: str,
    generated_at: datetime,
    window: tuple[str, str],
    output_files: list[str],
    vault_version: str | None = None,
) -> str:
    """The combined report. Pure: everything comes in as arguments."""
    header = [
        ["Cluster", cluster_name],
        ["Vault address", vault_addr],
        ["Generated", generated_at.strftime("%Y-%m-%d %H:%M:%S UTC")],
        ["Tool version", f"vault-tools {get_tool_version()}"],
        ["Activity window", f"{window[0]} to {window[1]}"],
    ]
    if vault_version:
        header.append(["Vault version", vault_version])
    steps = [[r.name, r.status, "—" if r.findings is None else r.findings, md_escape(r.reason) or "—"] for r in results]
    by_severity = merged["summary"]["by_severity"]
    coverage = merged["coverage"]
    gaps = [[d["namespace"], d["scope"]] for d in coverage["denied"]]
    gap_text = md_table(["Namespace", "What was denied"], gaps) if gaps else "None."
    if coverage["errors"]:
        gap_text += "\n\n**Errors**\n\n" + md_table(["Namespace", "Error"], [[e["namespace"], e["message"]] for e in coverage["errors"]])
    findings = [finding_from_dict(f) for f in merged["findings"]]
    sections = [
        f"# Vault Full Audit — {cluster_name}",
        "",
        md_table(["Field", "Value"], header),
        "",
        "## Steps",
        "",
        md_table(["Step", "Status", "Findings", "Notes"], steps),
        "",
        "Each step's own report has the detail behind its findings; this report merges them. Findings reported by more than one step (cluster health appears in both cluster-audit and namespace-audit) are listed once.",
        "",
        "## Summary",
        "",
        md_table(["Severity", "Findings"], [[s, by_severity.get(s.lower(), 0)] for s in SEVERITY_ORDER]),
        "",
        "## Access gaps",
        "",
        gap_text,
        "",
        "## Security observations",
        "",
        render_findings_table(findings, "_No observations from any step._"),
        "",
        "## Output files",
        "",
        md_table(["File"], [[f] for f in output_files]),
        "",
    ]
    return "\n".join(sections)


def _print_summary(console: Console, results: list[StepResult], merged: dict[str, Any]) -> None:
    table = Table(title="Full Audit Summary")
    table.add_column("Step", style="cyan")
    table.add_column("Status")
    table.add_column("Findings", justify="right")
    styles = {"ok": "[green]ok[/green]", "failed": "[red]failed[/red]", "skipped": "[yellow]skipped[/yellow]"}
    for r in results:
        table.add_row(r.name, styles[r.status], "—" if r.findings is None else str(r.findings))
    by_severity = merged["summary"]["by_severity"]
    table.add_row("[bold]merged[/bold]", "", str(merged["summary"]["total"]))
    console.print(table)
    console.print("Merged findings: " + ", ".join(f"{by_severity.get(s.lower(), 0)} {s.lower()}" for s in SEVERITY_ORDER))
