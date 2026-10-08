"""Markdown, CSV rows and findings.json for `identity-audit`. Pure functions.

Every output here holds counts and entity IDs only. Per-entity names, metadata
and aliases go to the separate ``--list`` file, built by ``entity_rows``.
"""

from __future__ import annotations

from collections import Counter
from datetime import UTC, datetime
from typing import Any

from src.common.findings import Finding, build_findings_document, coverage_block, display_namespace, get_tool_version, run_block
from src.common.markdown import md_table, render_findings_table
from src.identity_audit.collector import Entity, IdentityCoverage

# Rows in the markdown per-namespace table; the CSV carries every namespace.
MAX_REPORT_NAMESPACES = 500


def namespace_rows(entities: dict[str, list[Entity]]) -> list[dict[str, Any]]:
    """One row per namespace — the CSV grain, and the source of the markdown table."""
    rows = []
    for ns in sorted(entities, key=display_namespace):
        items = entities[ns]
        mount_types = Counter(a.get("mount_type") or "unknown" for e in items for a in e.aliases)
        rows.append(
            {
                "namespace": display_namespace(ns),
                "entities": len(items),
                "disabled": sum(1 for e in items if e.disabled),
                "without_aliases": sum(1 for e in items if e.disabled is not None and not e.aliases),
                "with_direct_policies": sum(1 for e in items if e.policies),
                "unreadable": sum(1 for e in items if e.disabled is None),
                "alias_mount_types": ", ".join(f"{t} ({n})" for t, n in sorted(mount_types.items())),
            }
        )
    return rows


def entity_rows(entities: dict[str, list[Entity]]) -> dict[str, list[dict[str, Any]]]:
    """The --list document: every entity with name, metadata and aliases. Confidential."""
    return {display_namespace(ns): [e.to_dict() for e in sorted(items, key=lambda e: e.name)] for ns, items in sorted(entities.items()) if items}


def _summary(entities: dict[str, list[Entity]], active: dict[str, int] | None) -> list[list[Any]]:
    everything = [e for items in entities.values() for e in items]
    return [
        ["Namespaces", len(entities)],
        ["Namespaces with entities", sum(1 for items in entities.values() if items)],
        ["Entities", len(everything)],
        ["Disabled", sum(1 for e in everything if e.disabled)],
        ["Without aliases", sum(1 for e in everything if e.disabled is not None and not e.aliases)],
        ["With direct policies", sum(1 for e in everything if e.policies)],
        ["Active entity clients", "not recorded (activity log empty or unreadable)" if active is None else sum(active.values())],
    ]


def build_identity_report(
    cluster_name: str,
    entities: dict[str, list[Entity]],
    coverage: IdentityCoverage,
    findings: list[Finding],
    active: dict[str, int] | None,
    *,
    vault_addr: str = "",
    generated_at: datetime | None = None,
    output_files: list[str] | None = None,
    listed: bool = False,
) -> str:
    generated = generated_at or datetime.now(UTC)
    header = [
        ["Cluster", cluster_name],
        ["Generated", generated.strftime("%Y-%m-%d %H:%M:%S UTC")],
        ["Tool version", f"vault-tools {get_tool_version()}"],
    ]
    if vault_addr:
        header.insert(1, ["Vault address", vault_addr])

    rows = namespace_rows(entities)
    table = md_table(
        ["Namespace", "Entities", "Disabled", "No aliases", "Direct policies", "Unreadable", "Alias mount types"],
        [[r["namespace"], r["entities"], r["disabled"], r["without_aliases"], r["with_direct_policies"], r["unreadable"], r["alias_mount_types"] or "—"] for r in rows[:MAX_REPORT_NAMESPACES]],
    )
    if len(rows) > MAX_REPORT_NAMESPACES:
        table += f"\n\n_Showing {MAX_REPORT_NAMESPACES} of {len(rows)} namespaces — see the identity summary CSV for the full list._"

    gaps = [[display_namespace(ns), scope] for ns, scope in sorted(coverage.denied)]
    gap_text = md_table(["Namespace", "What was denied"], gaps) if gaps else "None — every namespace's entities were readable."
    if coverage.errors:
        gap_text += "\n\n**Errors**\n\n" + md_table(["Namespace", "Error"], [[display_namespace(ns), msg] for ns, msg in sorted(coverage.errors)])

    privacy = (
        "Per-entity names, metadata and aliases were written to the entities file (`--list`). Treat it as confidential."
        if listed
        else "Entities are identified by ID only. Names, metadata and alias names can hold emails or role_ids; run with `--list` to write them to a separate file."
    )
    sections = [
        f"# Vault Identity Audit — {cluster_name}",
        "",
        md_table(["Field", "Value"], header),
        "",
        "## Summary",
        "",
        md_table(["Metric", "Value"], _summary(entities, active)),
        "",
        privacy,
        "",
        "## Access gaps",
        "",
        gap_text,
        "",
        "## Entities by namespace",
        "",
        table,
        "",
        "## Security observations",
        "",
        "Prompts for review, not a compliance verdict. Entity counts are compared with the activity log's active clients (VT-ID-004) only when it records any.",
        "",
        render_findings_table(findings, "_No observations — no orphaned, disabled or directly-granted entities, no duplicate aliases and no entity sprawl._"),
        "",
        "## Output files",
        "",
        md_table(["File"], [[f] for f in (output_files or [])]),
        "",
    ]
    return "\n".join(sections)


def build_identity_findings_json(
    cluster_name: str,
    coverage: IdentityCoverage,
    findings: list[Finding],
    *,
    vault_addr: str,
    started_at: datetime,
    finished_at: datetime,
    worker_threads: int | None = None,
    vault_version: str | None = None,
    is_enterprise: bool | None = None,
) -> dict[str, Any]:
    return build_findings_document(
        findings,
        run=run_block(cluster_name, vault_addr, "", started_at, finished_at, worker_threads),
        cluster_context={
            "vault_version": vault_version,
            "enterprise": is_enterprise,
            "system_max_lease_ttl_seconds": None,
            "system_default_lease_ttl_seconds": None,
            "sentinel": "skipped",
        },
        coverage=coverage_block(coverage.namespaces_processed, coverage.denied, coverage.errors),
        tool_version=get_tool_version(),
    )
