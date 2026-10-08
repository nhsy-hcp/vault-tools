"""Findings table rendering, including the collapse of identical copies."""

from src.common.findings import finding
from src.common.markdown import MAX_FINDING_COPIES, render_findings_table


def _admin(ns):
    return finding("VT-POL-001", ns, "acl_policy", "admin", None, "Grants write or sudo on every path (`*`) — effectively admin in this namespace.", paths=["*"])


def test_copies_above_the_threshold_collapse_to_one_row():
    findings = [_admin(f"team-{i:02d}") for i in range(MAX_FINDING_COPIES + 1)]
    table = render_findings_table(findings, "none")
    assert table.count("| VT-POL-001 |") == 1
    assert f"{MAX_FINDING_COPIES + 1} namespaces (team-00/, team-01/, team-02/, …)" in table
    # The heading still counts findings, so it agrees with findings.json.
    assert f"#### Medium ({MAX_FINDING_COPIES + 1})" in table


def test_copies_at_the_threshold_are_listed():
    table = render_findings_table([_admin(f"team-{i}") for i in range(MAX_FINDING_COPIES)], "none")
    assert table.count("| VT-POL-001 |") == MAX_FINDING_COPIES


def test_different_wording_is_never_merged():
    a = finding("VT-MOUNT-002", "a", "secrets_mount", "kv/", "kv", "max 48h")
    b = finding("VT-MOUNT-002", "b", "secrets_mount", "kv/", "kv", "max 96h")
    table = render_findings_table([a, b], "none", max_copies=1)
    assert table.count("| VT-MOUNT-002 |") == 2


def test_collapsed_row_keeps_its_place_among_the_others():
    other = finding("VT-POL-002", "z", "acl_policy", "minter", None, "Can write token creation")
    findings = [_admin(f"team-{i}") for i in range(3)] + [other]
    rows = [line for line in render_findings_table(findings, "none", max_copies=2).splitlines() if line.startswith("| VT-")]
    assert [r.split(" | ")[0] for r in rows] == ["| VT-POL-001", "| VT-POL-002"]


def test_empty_message():
    assert render_findings_table([], "nothing here") == "nothing here"
