"""Markdown primitives shared by every report.

Pure string functions; no Vault and no filesystem.
"""

from __future__ import annotations

from typing import Any

from src.common.findings import SEVERITY_ORDER, Finding, display_namespace


def md_escape(value: Any) -> str:
    """Make an arbitrary value safe to drop into a markdown table cell.

    Pipes would end the cell early and newlines would end the row, so both are
    neutralised. Everything else is left alone.
    """
    text = "" if value is None else str(value)
    return text.replace("\\", "\\\\").replace("|", "\\|").replace("\r\n", " ").replace("\n", " ").replace("\r", " ")


def md_table(headers: list[str], rows: list[list[Any]]) -> str:
    """Render a markdown table.

    Hand-rolled on purpose: ``DataFrame.to_markdown`` would pull in tabulate,
    which is not a project dependency.

    Returns an italic placeholder rather than a headerless table when there are
    no rows, so a section never renders as a bare, confusing header line.
    """
    if not rows:
        return "_No entries._"

    header_line = "| " + " | ".join(md_escape(h) for h in headers) + " |"
    separator = "| " + " | ".join("---" for _ in headers) + " |"
    body = ["| " + " | ".join(md_escape(cell) for cell in row) + " |" for row in rows]
    return "\n".join([header_line, separator, *body])


def render_findings_table(findings: list[Finding], empty_message: str) -> str:
    """Findings grouped by severity, most severe first; ``empty_message`` when there are none."""
    if not findings:
        return empty_message

    sections: list[str] = []
    for severity in SEVERITY_ORDER:
        group = [f for f in findings if f.severity == severity]
        if not group:
            continue
        rows = [[f.rule_id, display_namespace(f.namespace), f.mount, f.mount_type, f.detail] for f in group]
        # "Object", not "Mount": the Sentinel checks put a policy name in this
        # column, and findings that name a whole namespace put a dash in it.
        # "Rule" carries the vault-ops catalogue ID, so a row can be looked up
        # in the skill's rules.md and matched against findings.json.
        sections.append(f"#### {severity} ({len(group)})\n\n" + md_table(["Rule", "Namespace", "Object", "Type", "Observation"], rows))
    return "\n\n".join(sections)
