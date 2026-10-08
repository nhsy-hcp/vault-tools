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


# Above this many namespaces with an identical finding (same rule, object, type
# and wording), the table collapses them into one row with a count and three
# examples. A policy copied into every namespace is one decision, not 62 — on a
# dev cluster a single `admin` policy otherwise filled 124 of 167 rows. Matches
# the access-gaps threshold in namespace_audit/report.py. findings.json is never
# collapsed: each copy keeps its own fingerprint for diffs and CI gates.
MAX_FINDING_COPIES = 10


def _finding_rows(group: list[Finding], max_copies: int) -> list[list[Any]]:
    """One row per finding, except identical copies across many namespaces, which share one."""
    copies: dict[tuple[str, str, str, str], list[Finding]] = {}
    for f in group:
        copies.setdefault((f.rule_id, f.mount, f.mount_type, f.detail), []).append(f)
    rows: list[list[Any]] = []
    emitted: set[tuple[str, str, str, str]] = set()
    for f in group:
        key = (f.rule_id, f.mount, f.mount_type, f.detail)
        same = copies[key]
        if len(same) <= max_copies:
            rows.append([f.rule_id, display_namespace(f.namespace), f.mount, f.mount_type, f.detail])
        elif key not in emitted:
            emitted.add(key)
            examples = ", ".join(display_namespace(c.namespace) for c in same[:3])
            rows.append([f.rule_id, f"{len(same)} namespaces ({examples}, …)", f.mount, f.mount_type, f.detail])
    return rows


def render_findings_table(findings: list[Finding], empty_message: str, max_copies: int = MAX_FINDING_COPIES) -> str:
    """Findings grouped by severity, most severe first; ``empty_message`` when there are none.

    Each heading counts findings, not rows, so it still agrees with findings.json
    when copies are collapsed.
    """
    if not findings:
        return empty_message

    sections: list[str] = []
    for severity in SEVERITY_ORDER:
        group = [f for f in findings if f.severity == severity]
        if not group:
            continue
        rows = _finding_rows(group, max_copies)
        # "Object", not "Mount": the Sentinel checks put a policy name in this
        # column, and findings that name a whole namespace put a dash in it.
        # "Rule" carries the vault-ops catalogue ID, so a row can be looked up
        # in the skill's rules.md and matched against findings.json.
        sections.append(f"#### {severity} ({len(group)})\n\n" + md_table(["Rule", "Namespace", "Object", "Type", "Observation"], rows))
    return "\n\n".join(sections)
