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

import glob
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
from src.common.file_utils import latest_files, read_json, scan_files, write_json, write_markdown
from src.common.findings import SEVERITY_ORDER, diff_documents, get_tool_version, merge_documents, run_block
from src.common.utils import FILE_DATE_FORMAT
from src.common.vault_client import VaultClient
from src.entity_export.main import run_entity_export
from src.full_audit.report import FullAuditContext, StepSummary, build_full_report, top_groups
from src.identity_audit.main import run_identity_audit_full
from src.namespace_audit.main import NamespaceAuditor

logger = logging.getLogger(__name__)

STEPS = ("cluster-audit", "namespace-audit", "identity-audit", "activity-export", "entity-export")
MAX_REASON_LENGTH = 200
# The reason on a step the caller left out (``--skip`` / ``--only``), as opposed
# to one the node's state ruled out.
USER_SKIP_REASON = "skipped: not selected (--skip/--only)"
# The steps that read the activity window.
WINDOW_STEPS = frozenset({"activity-export", "entity-export"})


@dataclass
class StepResult:
    name: str
    status: str  # "ok", "failed" or "skipped"
    reason: str = ""
    document: dict[str, Any] | None = None
    extra: dict[str, Any] = field(default_factory=dict)
    duration: float | None = None

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
    began = time.monotonic()
    try:
        result = fn()
    except Exception as e:
        logger.exception(f"{name} failed: {e}")
        result = StepResult(name, "failed", f"{type(e).__name__}: {e}"[:MAX_REASON_LENGTH])
    result.duration = time.monotonic() - began
    results.append(result)
    return result


def run_full_audit(
    vault_client: VaultClient,
    output_dir: str,
    *,
    workers: int = 4,
    collect_sentinel: bool = True,
    names_only: bool = False,
    include_entity_list: bool = False,
    start_date: str | None = None,
    end_date: str | None = None,
    console: Console | None = None,
    skip: frozenset[str] = frozenset(),
) -> dict[str, Any] | None:
    """Run every step and write the combined files. Returns the merged findings document, or None if Vault was unreachable.

    ``skip`` names steps to leave out (any of ``STEPS[1:]``; cluster-audit
    always runs, as it supplies the cluster name and node state). A skipped step
    is listed as skipped and makes the merged coverage incomplete; the steps
    after it fall back to their own reads.
    """
    unknown = set(skip) - set(STEPS[1:])
    if unknown:
        raise ValueError(f"cannot skip {', '.join(sorted(unknown))}: choose from {', '.join(STEPS[1:])}")
    console = console or Console()
    started = datetime.now(UTC)
    # Wall-clock floor for "written by this run": steps name files by local or
    # UTC date inconsistently, and same-day leftovers share their names.
    started_epoch = time.time()
    window: tuple[str, str] | None = None
    if not skip >= WINDOW_STEPS:
        window = (start_date, end_date) if start_date and end_date else default_window(started.date())
        start_date, end_date = window
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

    # What the report needs from each step beyond its findings document.
    context: dict[str, Any] = {}

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
                names_only=names_only,
                cluster_reads=cluster.reads,
            )
            document = auditor.audit_cluster()
            if document is None:
                return StepResult("namespace-audit", "failed", "the namespace walk failed — see the message above.")
            namespaces = sorted(auditor.data.auth_methods) or None
            context.update(audit_data=auditor.data, audit_stats=auditor.stats)
            return StepResult(
                "namespace-audit",
                "ok",
                document=document,
                extra={"sentinel": document["cluster_context"]["sentinel"], "policy_bodies": document["cluster_context"].get("policy_bodies", {})},
            )

        current_month: Any = NOT_READ

        def identity_step() -> StepResult:
            nonlocal current_month
            result = run_identity_audit_full(vault_client, output_dir, workers=workers, include_list=include_entity_list, namespaces=namespaces, console=console)
            if result is None:
                return StepResult("identity-audit", "failed", "see the message above.")
            current_month = result.current_month
            context["identity_rows"] = result.namespace_rows
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
                cluster_id=cluster.health.get("cluster_id"),
            )
            context.update(
                activity_ran=True,
                activity_log=result.activity_log,
                total_clients=result.total_clients,
                current_month_clients=result.current_month_clients,
                activity_namespaces=result.namespaces,
            )
            return StepResult("activity-export", "ok", document=result.findings_document)

        def entity_step() -> StepResult:
            run_entity_export(vault_client, start_date, end_date, cluster.cluster_name, output_dir=output_dir, cluster_id=cluster.health.get("cluster_id"))
            return StepResult("entity-export", "ok", "export only — no findings")

        for name, fn in (("namespace-audit", namespace_step), ("identity-audit", identity_step), ("activity-export", activity_step), ("entity-export", entity_step)):
            if name in skip:
                # Not called, so namespaces stays None (identity-audit discovers
                # its own) and current_month stays NOT_READ (activity reads it).
                results.append(StepResult(name, "skipped", USER_SKIP_REASON))
            else:
                _run_step(name, results, console, fn)

    finished = datetime.now(UTC)
    documents = [r.document for r in results if r.document]
    sentinel = next((r.extra["sentinel"] for r in results if "sentinel" in r.extra), "skipped")
    policy_bodies = next((r.extra["policy_bodies"] for r in results if "policy_bodies" in r.extra), {})
    merged = merge_documents(
        documents,
        run=run_block(cluster.cluster_name, vault_client.vault_addr, "", started, finished, workers),
        cluster_context={**cluster.document["cluster_context"], "sentinel": sentinel, "policy_bodies": policy_bodies},
        tool_version=get_tool_version(),
    )
    # A step that failed outright judged nothing, so the run cannot be complete.
    if any(r.status == "failed" for r in results):
        merged["coverage"]["complete"] = False
        merged["coverage"]["errors"].extend({"namespace": "/", "message": f"{r.name}: {r.reason}"[:MAX_REASON_LENGTH]} for r in results if r.status == "failed")
    # Nor can one with a step skipped, on request or because the node (sealed,
    # DR secondary) cannot serve authenticated reads: it judged nothing either.
    # Not an error, so coverage.errors is untouched; the report's Steps and Not
    # covered sections name it.
    if any(r.status == "skipped" for r in results):
        merged["coverage"]["complete"] = False

    date_str = finished.strftime(FILE_DATE_FORMAT)
    # A run with steps left out on request is "partial": its own file names, so
    # it never replaces a complete run's files, and it is never compared with
    # one (here or by diff's auto-pick), which would read every finding of a
    # skipped step as new or resolved.
    kind = "partial" if skip else "full"
    findings_path = os.path.join(output_dir, f"{cluster.file_prefix}-{kind}-findings-{date_str}.json")
    report_path = os.path.join(output_dir, f"{cluster.file_prefix}-{kind}-audit-{date_str}.md")
    # Before writing this run's file, which may replace a same-day earlier one.
    previous_path = None if skip else latest_previous_findings(output_dir, cluster.file_prefix, started_epoch)
    previous_diff = None
    if previous_path:
        try:
            previous_diff = diff_documents(read_json(previous_path), merged)
        except Exception as e:
            logger.debug(f"Could not compare with {previous_path}: {e}")
    write_json(findings_path, merged)
    step_files = files_written_since(output_dir, cluster.file_prefix, started_epoch, exclude={report_path})
    reads = cluster.reads
    report_context = FullAuditContext(
        cluster_name=cluster.cluster_name,
        cluster_id=cluster.health.get("cluster_id"),
        vault_addr=vault_client.vault_addr,
        started_at=started,
        finished_at=finished,
        workers=workers,
        window=window,
        merged=merged,
        steps=[StepSummary(r.name, r.status, r.reason, r.findings, r.duration) for r in results],
        health=cluster.health,
        license_status=reads.license.status if reads.license else None,
        license_reason=reads.license.unavailable_reason if reads.license else None,
        lease_ttls=reads.lease_ttls,
        policy_bodies=dict(context["audit_data"].policy_bodies) if context.get("audit_data") is not None else {},
        previous_diff=previous_diff,
        previous_path=os.path.basename(previous_path) if previous_path else None,
        output_files=step_files,
        **context,
    )
    try:
        write_markdown(report_path, build_full_report(report_context))
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
    # One second of slack: some filesystems store whole-second mtimes.
    return sorted(os.path.basename(path) for mtime, path in scan_files(output_dir, f"{glob.escape(cluster_name)}-*") if mtime >= since - 1 and os.path.abspath(path) not in exclude)


def latest_previous_findings(output_dir: str, prefix: str, before: float) -> str | None:
    """The newest earlier ``{prefix}-full-findings-*.json`` in the output directory, if any."""
    found = latest_files(output_dir, f"{glob.escape(prefix)}-full-findings-*.json", before=before)
    return found[0] if found else None


def _print_summary(console: Console, results: list[StepResult], merged: dict[str, Any]) -> None:
    table = Table(title="Full Audit Summary")
    table.add_column("Step", style="cyan")
    table.add_column("Status")
    table.add_column("Findings", justify="right")
    table.add_column("Duration", justify="right")
    styles = {"ok": "[green]ok[/green]", "failed": "[red]failed[/red]", "skipped": "[yellow]skipped[/yellow]"}
    for r in results:
        table.add_row(r.name, styles[r.status], "—" if r.findings is None else str(r.findings), f"{r.duration:.1f}s" if r.duration is not None else "—")
    table.add_row("[bold]merged[/bold]", "", str(merged["summary"]["total"]), "")
    console.print(table)

    by_severity = merged["summary"]["by_severity"]
    coverage = merged["coverage"]
    console.print(
        "Findings: "
        + ", ".join(f"{by_severity.get(s.lower(), 0)} {s.lower()}" for s in SEVERITY_ORDER)
        + f" · coverage {'complete' if coverage['complete'] else '[yellow]partial[/yellow]'}"
        + f" · {coverage['namespaces_processed']} namespaces"
    )
    groups = top_groups(merged)
    if groups:
        top = Table(title="Top findings")
        for column in ("#", "Rule", "Severity", "Count", "Title"):
            top.add_column(column)
        for i, g in enumerate(groups, 1):
            top.add_row(str(i), g.rule_id, g.severity.lower(), str(g.count), g.title)
        console.print(top)
