"""Markdown rendering for the namespace audit.

Pure functions: this module never talks to Vault and never touches the
filesystem. It takes the collected AuditData/AuditStats and returns a string,
which keeps every rendering rule testable without mock plumbing.

Note the deliberate absence of a `from .main import AuditData` at runtime —
`main` imports this module, so the annotations below are guarded by
`TYPE_CHECKING` and deferred via `from __future__ import annotations` to avoid a
circular import.
"""

from __future__ import annotations

import hashlib
import logging
import re
from collections import Counter
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

from src.cluster_audit.findings import (
    DEFAULT_LEASE_TTL_WARNING_SECONDS,
    LICENSE_EXPIRY_WARNING_DAYS,
    cluster_lease_findings,
    health_findings,
    license_expiry_days,
    license_findings,
    parse_license_time,
)
from src.cluster_audit.report import render_cluster_health, render_cluster_reads, render_license
from src.common.findings import (
    SEVERITY_ORDER,
    Finding,
    build_findings_document,
    coverage_block,
    display_namespace,
    drift_findings,
    finding,
    format_ttl,
    get_tool_version,
    run_block,
    sort_findings,
)
from src.common.markdown import md_escape, md_table, render_findings_table
from src.namespace_audit.acl import acl_policy_findings

if TYPE_CHECKING:  # pragma: no cover - typing only
    from .main import AuditData, AuditStats

logger = logging.getLogger(__name__)

# A cluster can hold tens of thousands of namespaces — the auditor warns at a
# queue depth of 10,000 — and a markdown document that long is unreadable and
# slow to render. Past these caps the report points at the CSV instead.
MAX_REPORT_NODES = 500
MAX_MATRIX_NAMESPACES = 25

# Policy names joined into one table cell. The reference cluster peaks at 11
# per namespace, but nothing stops a namespace holding hundreds, and a 4 KB
# cell would wreck the table for every other row.
MAX_ACL_NAMES_PER_CELL = 15

# Above this many namespaces sharing one denial reason, the access-gaps table
# collapses them into a single row. A denial repeated across the whole tree is
# a missing policy rule, not a targeted restriction, and listing it per
# namespace buries the handful of gaps that are genuinely specific: a token
# without the Sentinel rules produces 268 rows on a 134-namespace cluster.
MAX_ACCESS_GAP_ROWS = 10

# Fallback threshold, used only when the cluster's own system max is unavailable
# (the token cannot read sys/config/state/sanitized). 768h (32 days) is Vault's
# stock system max. Prefer the real value: a cluster tuned down to, say, 24h
# makes this constant far too permissive to catch anything.
LONG_MAX_LEASE_TTL_SECONDS = 768 * 3600

# More than this many non-built-in mounts of one type in one namespace
# (VT-MOUNT-005). Above it the mount table itself becomes the problem: slower
# namespace operations and replication, and policies written per mount.
MOUNT_SPRAWL_THRESHOLD = 20

# Mounts Vault creates itself in every namespace. A namespace holding only these
# has nothing in it, which is what the "empty namespace" check looks for.
# Child namespaces get the "ns_"-prefixed variants of the same engines.
BUILTIN_ENGINE_TYPES = frozenset(
    {
        "cubbyhole",
        "identity",
        "system",
        "ns_cubbyhole",
        "ns_identity",
        "ns_system",
        "ns_agent_registry",
        "agent_registry",
    }
)

# The token backend Vault mounts in every namespace; "ns_token" is the child
# namespace form. Neither means anyone can actually log in, which is what the
# "no external auth" check is really asking about.
BUILTIN_AUTH_TYPES = frozenset({"token", "ns_token"})

# Plugin lifecycle states that mean the mount will stop working at some point.
DEPRECATED_STATUSES = frozenset({"deprecated", "pending-removal", "removed"})

# Sentinel's three enforcement levels, ordered strongest first. Only
# hard-mandatory actually stops a request outright: soft-mandatory can be
# overridden by a caller holding a sudo-capable token, and advisory merely logs.
SENTINEL_ENFORCEMENT_LEVELS = ("hard-mandatory", "soft-mandatory", "advisory")

# A main rule that is the literal `true` passes every request unconditionally.
# Vault will not store a policy with no main rule at all, so this — not an empty
# body — is what a do-nothing Sentinel policy looks like on a real cluster.
ALWAYS_TRUE_MAIN = re.compile(r"^main\s*=\s*rule\s*\{\s*true\s*\}$")

# The mirror image: a main that is literally false denies every request the
# policy applies to. Only a finding under hard-mandatory (VT-SNT-006), where
# nothing can override it. Literal match only — "false in practice" would need
# evaluating the policy.
ALWAYS_FALSE_MAIN = re.compile(r"^main\s*=\s*(?:rule\s*\{\s*false\s*\}|false)$")

# Sentinel import statements. Only `http` is acted on (VT-SNT-007): it is the
# one import that makes request handling wait on something outside Vault.
SENTINEL_IMPORT = re.compile(r'^\s*import\s+"([^"]+)"', re.M)

# EGP paths that cover every endpoint in the namespace. Worth surfacing not
# because it is wrong — a catch-all EGP is a legitimate pattern — but because
# the blast radius should be a deliberate choice.
BROAD_EGP_PATHS = frozenset({"*", "/*"})


# Re-exported so callers keep importing these from the report module.
__all__ = [
    "DEFAULT_LEASE_TTL_WARNING_SECONDS",
    "LICENSE_EXPIRY_WARNING_DAYS",
    "SEVERITY_ORDER",
    "Finding",
    "display_namespace",
    "format_ttl",
    "get_tool_version",
    "md_escape",
    "md_table",
    "render_license",
]

# The license helpers moved to cluster_audit.findings, which cluster-audit shares.
_parse_license_time = parse_license_time
_license_expiry_days = license_expiry_days


def _format_multiple(value: int, baseline: int) -> str:
    """How many times larger value is than baseline, e.g. '90x' or '1.5x'."""
    ratio = value / baseline
    return f"{ratio:.0f}x" if abs(ratio - round(ratio)) < 0.05 else f"{ratio:.1f}x"


def _namespace_nodes(data: AuditData) -> list[str]:
    """Every namespace the report knows about, as stored keys.

    Sourced primarily from the auth_methods keys: those are the namespaces
    actually *processed*, and they include the root as "". ``data.namespaces``
    holds only discovered children and omits the root entirely, so using it
    alone would drop the starting namespace from the tree.
    """
    nodes = set(data.auth_methods) | set(data.secret_engines) | set(data.namespaces)
    return sorted(nodes)


def _depth(path: str) -> int:
    """Nesting level of a stored namespace key; root is 0."""
    return 0 if path == "" else len(path.strip("/").split("/"))


def _parent_of(path: str) -> str | None:
    """Parent key of a stored namespace key, or None for a top-level node."""
    if path == "":
        return None
    trimmed = path.strip("/")
    if "/" not in trimmed:
        return ""
    return trimmed.rsplit("/", 1)[0]


def build_namespace_tree(data: AuditData) -> dict[str, list[str]]:
    """Map each namespace key to its sorted child keys.

    Nodes whose parent was never recorded — which happens when the audit starts
    partway down the tree, or when a parent was denied — are attached under the
    sentinel key ``"__roots__"`` so nothing is silently dropped from the tree.
    """
    nodes = _namespace_nodes(data)
    node_set = set(nodes)
    tree: dict[str, list[str]] = {"__roots__": []}

    for node in nodes:
        tree.setdefault(node, [])

    for node in nodes:
        parent = _parent_of(node)
        if parent is not None and parent in node_set:
            tree[parent].append(node)
        else:
            tree["__roots__"].append(node)

    for children in tree.values():
        children.sort()
    return tree


def _mount_counts(data: AuditData, namespace: str) -> tuple[int, int]:
    """(auth method count, secrets engine count) for one namespace."""
    return len(data.auth_methods.get(namespace, {})), len(data.secret_engines.get(namespace, {}))


def render_namespace_tree(data: AuditData, max_nodes: int = MAX_REPORT_NODES) -> str:
    """Render the namespace hierarchy as an indented markdown list."""
    tree = build_namespace_tree(data)
    roots = tree.get("__roots__", [])
    if not roots:
        return "_No namespaces recorded._"

    lines: list[str] = []
    rendered = 0
    truncated = False

    def walk(node: str, indent: int) -> None:
        nonlocal rendered, truncated
        if truncated:
            return
        if rendered >= max_nodes:
            truncated = True
            return
        auth_count, engine_count = _mount_counts(data, node)
        lines.append(f"{'  ' * indent}- `{display_namespace(node)}` — {auth_count} auth, {engine_count} engines")
        rendered += 1
        for child in tree.get(node, []):
            walk(child, indent + 1)

    for root in roots:
        walk(root, 0)

    if truncated:
        total = len(_namespace_nodes(data))
        lines.append(f"\n_Tree truncated at {max_nodes} of {total} namespaces — see the namespaces summary CSV for the full list._")
    return "\n".join(lines)


def render_namespace_inventory(data: AuditData, max_rows: int = MAX_REPORT_NODES) -> str:
    """Table of namespaces with their IDs, mount counts and custom metadata."""
    nodes = _namespace_nodes(data)
    rows: list[list[Any]] = []
    for node in nodes[:max_rows]:
        info = data.namespaces.get(node, {})
        auth_count, engine_count = _mount_counts(data, node)
        metadata = info.get("custom_metadata") or {}
        rows.append(
            [
                display_namespace(node),
                info.get("id", "—"),
                _depth(node),
                auth_count,
                engine_count,
                ", ".join(f"{k}={v}" for k, v in sorted(metadata.items())) if metadata else "—",
            ]
        )

    table = md_table(["Namespace", "ID", "Depth", "Auth methods", "Secrets engines", "Custom metadata"], rows)
    if len(nodes) > max_rows:
        table += f"\n\n_Showing {max_rows} of {len(nodes)} namespaces — see the namespaces summary CSV for the full list._"
    return table


def _type_distribution(collection: dict[str, Any]) -> list[tuple[str, int, int]]:
    """(type, mount count, namespace count) per mount type, most common first."""
    mount_counts: dict[str, int] = {}
    namespace_counts: dict[str, set[str]] = {}
    for namespace, mounts in collection.items():
        for mount_data in mounts.values():
            mount_type = mount_data.get("type")
            if not mount_type:
                continue
            mount_counts[mount_type] = mount_counts.get(mount_type, 0) + 1
            namespace_counts.setdefault(mount_type, set()).add(namespace)
    # Secondary sort on the name keeps equal-count rows in a stable, readable order.
    return sorted(
        ((t, c, len(namespace_counts[t])) for t, c in mount_counts.items()),
        key=lambda item: (-item[1], item[0]),
    )


def render_type_distribution(collection: dict[str, Any], label: str) -> str:
    """Table of how many mounts of each type exist, and in how many namespaces."""
    rows = [[mount_type, count, ns_count] for mount_type, count, ns_count in _type_distribution(collection)]
    return md_table([label, "Mounts", "Namespaces"], rows)


def render_type_matrix(collection: dict[str, Any], label: str, max_namespaces: int = MAX_MATRIX_NAMESPACES) -> str:
    """Per-namespace count matrix, or a pointer to the CSV when too wide to read."""
    if not collection:
        return "_No entries._"
    if len(collection) > max_namespaces:
        return f"_{len(collection)} namespaces is too many to tabulate here — see the {label.lower()} summary CSV for the full per-namespace matrix._"

    types = [t for t, _, _ in _type_distribution(collection)]
    if not types:
        return "_No entries._"

    rows: list[list[Any]] = []
    for namespace in sorted(collection):
        counts: dict[str, int] = {}
        for mount_data in collection[namespace].values():
            mount_type = mount_data.get("type")
            if mount_type:
                counts[mount_type] = counts.get(mount_type, 0) + 1
        rows.append([display_namespace(namespace), *(counts.get(t, 0) for t in types)])

    return md_table(["Namespace", *types], rows)


def _policy_line_count(body: Any) -> int:
    """Number of lines in a Sentinel policy body; 0 for anything unreadable."""
    return len(body.splitlines()) if isinstance(body, str) else 0


def _meaningful_lines(body: str) -> list[str]:
    """Policy lines with comments and blank lines removed; Sentinel takes # and //."""
    return [stripped for line in body.splitlines() if (stripped := line.strip()) and not stripped.startswith(("#", "//"))]


def _is_always_false_policy(body: Any) -> bool:
    """True when the only rule is ``main = rule { false }`` (or ``main = false``).

    Imports are skipped as well as comments: an unused import does not change
    what the policy decides.
    """
    if not isinstance(body, str):
        return False
    meaningful = [line for line in _meaningful_lines(body) if not SENTINEL_IMPORT.match(line)]
    return ALWAYS_FALSE_MAIN.match(" ".join(meaningful)) is not None


def _sentinel_imports(body: Any) -> list[str]:
    return sorted(set(SENTINEL_IMPORT.findall(body))) if isinstance(body, str) else []


def _is_trivial_policy(body: Any) -> bool:
    """True when the policy body has no executable content.

    Two cases. An empty body cannot actually be written through Vault's own
    endpoint — it refuses at write time with "every policy must have a main
    rule" — but it is cheap to recognise and can still reach the report from a
    hand-assembled JSON dump. The case that occurs in practice is
    ``main = rule { true }``: it compiles, it appears in the policy list looking
    like a control, and it permits every request.

    Sentinel takes both ``#`` and ``//`` comments, so both are stripped first: a
    comment sitting above the rule must not hide it.
    """
    if not isinstance(body, str):
        return False
    meaningful = _meaningful_lines(body)
    if not meaningful:
        return True
    # Joined rather than matched line by line — the rule is often wrapped.
    return ALWAYS_TRUE_MAIN.match(" ".join(meaningful)) is not None


def reduce_sentinel_policy(raw: dict[str, Any]) -> dict[str, Any]:
    """What is kept of a Sentinel policy read: never its source.

    The checks need only these facts about the body, so they are computed here,
    in memory, and the body is dropped — matching the ACL review and the
    vault-ops skill. ``sha256`` is what VT-SNT-005 compares across namespaces.
    """
    body = raw.get("policy")
    reduced: dict[str, Any] = {"name": raw.get("name"), "enforcement_level": raw.get("enforcement_level")}
    if "paths" in raw:
        reduced["paths"] = raw.get("paths")
    if isinstance(body, str):
        reduced.update(
            sha256=hashlib.sha256(body.encode()).hexdigest()[:16],
            line_count=_policy_line_count(body),
            always_true=_is_trivial_policy(body),
            always_false=_is_always_false_policy(body),
            imports=_sentinel_imports(body),
        )
    return reduced


def _sentinel_rows(collection: dict[str, Any], kind: str) -> list[list[Any]]:
    """Flatten a Sentinel collection into sorted table rows."""
    rows: list[list[Any]] = []
    for namespace in sorted(collection):
        for name in sorted(collection[namespace]):
            policy = collection[namespace][name]
            if not isinstance(policy, dict):
                continue
            row: list[Any] = [display_namespace(namespace), name, policy.get("enforcement_level", "—")]
            if kind == "egp":
                paths = policy.get("paths")
                row.append(", ".join(paths) if isinstance(paths, list) and paths else "—")
            row.append(policy.get("line_count", "—"))
            rows.append(row)
    return rows


def render_acl_policies(acl_policies: dict[str, list[str]], max_rows: int = MAX_REPORT_NODES, max_names: int = MAX_ACL_NAMES_PER_CELL) -> str:
    """One row per namespace listing the ACL policies defined in it.

    Grouped by namespace rather than one row per policy: a real cluster is
    heavily templated, and the flat form ran to 1,233 rows against 133
    namespaces while repeating the same handful of names throughout. The
    per-policy grain lives in the CSV.

    Namespaces with none render ``0`` and a dash. Dropping the row instead would
    read as "not audited" rather than "nothing defined here", and the two are
    very different answers.
    """
    if not acl_policies:
        return "_No entries._"

    rows: list[list[Any]] = []
    for namespace in sorted(acl_policies)[:max_rows]:
        names = acl_policies[namespace]
        if not names:
            listed = "—"
        elif len(names) > max_names:
            listed = ", ".join(names[:max_names]) + f", … (+{len(names) - max_names} more)"
        else:
            listed = ", ".join(names)
        rows.append([display_namespace(namespace), len(names), listed])

    table = md_table(["Namespace", "Count", "Policies"], rows)
    if len(acl_policies) > max_rows:
        table += f"\n\n_Showing {max_rows} of {len(acl_policies)} namespaces — see the ACL policies summary CSV for the full list._"
    return table


# Why policy bodies were or were not assessed, per status, for both kinds.
POLICY_BODY_NOTES = {
    "not readable": "the token cannot read policy bodies, so only names were listed. Attach `{addon}` to the token to assess them",
    "names only": "only names were listed (`--names-only`)",
    "none found": "there were no policies to read",
}


def render_acl_review_note(acl_assessments: dict[str, dict[str, Any]], status: str | None = None) -> str:
    """One line on whether bodies were assessed; the findings carry the detail.

    No per-policy table: the flagged paths are already in the findings, and a
    table of every assessed policy would repeat the names list above.
    """
    if not acl_assessments:
        reason = POLICY_BODY_NOTES.get(status or "not readable", POLICY_BODY_NOTES["not readable"]).format(addon="policies/audit-policy-acl-reader.hcl")
        return f"_Permissions were not assessed: {reason}._"
    total = sum(len(p) for p in acl_assessments.values())
    flagged = sum(1 for p in acl_assessments.values() for a in p.values() if a.flagged)
    unparsed = sum(1 for p in acl_assessments.values() for a in p.values() if not a.parsed)
    note = f"Permissions assessed for {total} polic{'y' if total == 1 else 'ies'} (built-ins included, `root` excluded): {flagged} with flagged rules"
    if unparsed:
        note += f", {unparsed} could not be parsed"
    return note + ". Each rule is judged on its own — a `deny` elsewhere, or another policy on the same token, can narrow it. See **Security observations**."


def render_sentinel_policies(collection: dict[str, Any], kind: str, max_rows: int = MAX_REPORT_NODES) -> str:
    """Table of Sentinel policies of one kind, across every namespace.

    The body itself is never rendered or kept — only its line count, from
    reduce_sentinel_policy. Policies whose bodies were not read show dashes.
    """
    rows = _sentinel_rows(collection, kind)
    headers = ["Namespace", "Policy", "Enforcement"] + (["Paths"] if kind == "egp" else []) + ["Lines"]
    table = md_table(headers, rows[:max_rows])
    if len(rows) > max_rows:
        table += f"\n\n_Showing {max_rows} of {len(rows)} policies — see the sentinel policies summary CSV for the full list._"
    return table


def render_enforcement_distribution(egp: dict[str, Any], rgp: dict[str, Any]) -> str:
    """How many policies of each kind sit at each enforcement level."""
    counts: dict[str, dict[str, int]] = {level: {"egp": 0, "rgp": 0} for level in SENTINEL_ENFORCEMENT_LEVELS}
    other: dict[str, int] = {"egp": 0, "rgp": 0}
    for kind, collection in (("egp", egp), ("rgp", rgp)):
        for policies in collection.values():
            for policy in policies.values():
                if not isinstance(policy, dict):
                    continue
                level = policy.get("enforcement_level")
                if level in counts:
                    counts[level][kind] += 1
                else:
                    # Unreadable bodies and any level Vault adds later still get
                    # counted, so the totals here reconcile with the tables below.
                    other[kind] += 1

    rows: list[list[Any]] = [[level, counts[level]["egp"], counts[level]["rgp"]] for level in SENTINEL_ENFORCEMENT_LEVELS]
    if other["egp"] or other["rgp"]:
        rows.append(["unknown", other["egp"], other["rgp"]])
    if not any(row[1] or row[2] for row in rows):
        return "_No entries._"
    return md_table(["Enforcement level", "EGP", "RGP"], rows)


def _collect_sentinel_findings(data: AuditData) -> list[Finding]:
    """Security observations derived from the Sentinel policies collected."""
    findings: list[Finding] = []
    for kind, collection in (("egp", data.egp_policies), ("rgp", data.rgp_policies)):
        object_kind = f"{kind}_policy"
        for namespace, policies in collection.items():
            for name, policy in policies.items():
                if not isinstance(policy, dict):
                    continue
                level = policy.get("enforcement_level")
                if level == "advisory":
                    findings.append(
                        finding(
                            "VT-SNT-001",
                            namespace,
                            object_kind,
                            name,
                            kind,
                            "Enforcement level is `advisory` — the policy logs violations but never blocks a request.",
                            enforcement_level=level,
                        )
                    )
                elif level == "soft-mandatory":
                    findings.append(
                        finding(
                            "VT-SNT-002",
                            namespace,
                            object_kind,
                            name,
                            kind,
                            "Enforcement level is `soft-mandatory` — a caller with a `sudo`-capable token can override it.",
                            enforcement_level=level,
                        )
                    )

                paths = policy.get("paths")
                if kind == "egp" and isinstance(paths, list) and any(p in BROAD_EGP_PATHS for p in paths):
                    findings.append(
                        finding(
                            "VT-SNT-003",
                            namespace,
                            object_kind,
                            name,
                            kind,
                            "Endpoint path is a wildcard — the policy applies to every request in this namespace.",
                            paths=sorted(paths),
                        )
                    )

                if policy.get("always_true"):
                    findings.append(
                        finding(
                            "VT-SNT-004",
                            namespace,
                            object_kind,
                            name,
                            kind,
                            "Policy body always evaluates to true — it enforces nothing despite appearing in the policy list.",
                            line_count=policy.get("line_count", 0),
                        )
                    )

                if level == "hard-mandatory" and policy.get("always_false"):
                    scope = f" on {', '.join(f'`{p}`' for p in paths)}" if kind == "egp" and isinstance(paths, list) and paths else ""
                    evidence: dict[str, Any] = {"enforcement_level": level}
                    if kind == "egp" and isinstance(paths, list):
                        evidence["paths"] = sorted(paths)
                    findings.append(
                        finding(
                            "VT-SNT-006",
                            namespace,
                            object_kind,
                            name,
                            kind,
                            f"Hard-mandatory and `main` is always false — every request it applies to{scope} is denied, which can lock callers out.",
                            **evidence,
                        )
                    )

                imports = policy.get("imports") or []
                if "http" in imports:
                    findings.append(
                        finding(
                            "VT-SNT-007",
                            namespace,
                            object_kind,
                            name,
                            kind,
                            "Imports `http` — each request it applies to can wait on an outbound call, so that endpoint's availability and latency gate Vault requests.",
                            imports=imports,
                        )
                    )

    findings.extend(_collect_sentinel_drift_findings(data))
    return findings


def _collect_sentinel_drift_findings(data: AuditData) -> list[Finding]:
    """VT-SNT-005: one policy name, several bodies across namespaces.

    Compared by body hash only; enforcement level and paths are left out
    because a deliberately stricter copy is still worth seeing as drift, and the
    body is where accidental divergence happens. Unread bodies (names only, or
    a failed read) have no hash and are skipped — an unknown body is not
    evidence of a different one.
    """
    findings: list[Finding] = []
    for kind, collection in (("egp", data.egp_policies), ("rgp", data.rgp_policies)):
        copies: dict[str, list[tuple[str, str]]] = {}
        for namespace, policies in collection.items():
            for name, policy in policies.items():
                digest = policy.get("sha256") if isinstance(policy, dict) else None
                if digest:
                    copies.setdefault(name, []).append((namespace, digest))
        findings.extend(drift_findings("VT-SNT-005", f"{kind}_policy", kind, copies, label=f"{kind.upper()} "))
    return findings


def collect_findings(
    data: AuditData,
    system_max_lease_ttl: int | None = None,
    now: datetime | None = None,
    system_default_lease_ttl: int | None = None,
) -> list[Finding]:
    """Derive security observations from the mount metadata already collected.

    These are prompts for review, not a compliance verdict — several are
    informational by design.

    ``system_max_lease_ttl`` is the cluster's own ``max_lease_ttl`` from
    sys/config/state/sanitized. When known, the lease check reports mounts that
    *override* it, which is the actionable question; without it the check falls
    back to the fixed LONG_MAX_LEASE_TTL_SECONDS threshold.

    ``system_default_lease_ttl`` is the same endpoint's ``default_lease_ttl``,
    judged on its own by VT-LEASE-001.

    Two checks Vault users often expect are deliberately absent because they
    would be pure noise rather than signal. ``max_lease_ttl == 0`` means "inherit
    the system default", not "unlimited" — on a real cluster 99.7% of mounts sit
    at 0, so flagging them buries every other finding. ``seal_wrap: false`` is
    the default for almost every mount type.
    """
    findings: list[Finding] = []
    # Compare against the cluster's real ceiling where available.
    ttl_baseline = system_max_lease_ttl if system_max_lease_ttl else LONG_MAX_LEASE_TTL_SECONDS

    for kind, collection in (("auth_mount", data.auth_methods), ("secrets_mount", data.secret_engines)):
        for namespace, mounts in collection.items():
            for mount_path, mount_data in mounts.items():
                if not isinstance(mount_data, dict):
                    continue
                mount_type = mount_data.get("type", "unknown")
                config = mount_data.get("config") or {}

                status = (mount_data.get("deprecation_status") or "").lower()
                if status in DEPRECATED_STATUSES:
                    findings.append(
                        finding(
                            "VT-MOUNT-001",
                            namespace,
                            kind,
                            mount_path,
                            mount_type,
                            f"Plugin lifecycle status is `{status}` — plan a migration before it stops working.",
                            deprecation_status=status,
                        )
                    )

                if kind == "auth_mount" and config.get("listing_visibility") == "unauth":
                    findings.append(
                        finding(
                            "VT-AUTH-001",
                            namespace,
                            kind,
                            mount_path,
                            mount_type,
                            "`listing_visibility: unauth` — this mount is enumerable by unauthenticated callers.",
                            listing_visibility="unauth",
                        )
                    )

                max_ttl = config.get("max_lease_ttl")
                if isinstance(max_ttl, int) and max_ttl > ttl_baseline:
                    if system_max_lease_ttl:
                        detail = (
                            f"`max_lease_ttl` {format_ttl(max_ttl)} overrides the cluster system max of {format_ttl(system_max_lease_ttl)} — {_format_multiple(max_ttl, system_max_lease_ttl)} higher."
                        )
                    else:
                        detail = f"`max_lease_ttl` is {format_ttl(max_ttl)}, above the {format_ttl(LONG_MAX_LEASE_TTL_SECONDS)} review threshold (the cluster system max could not be read)."
                    findings.append(
                        finding(
                            "VT-MOUNT-002",
                            namespace,
                            kind,
                            mount_path,
                            mount_type,
                            detail,
                            max_lease_ttl_seconds=max_ttl,
                            baseline_seconds=ttl_baseline,
                            baseline_source="cluster" if system_max_lease_ttl else "fallback",
                            multiple=round(max_ttl / ttl_baseline, 1),
                        )
                    )

                default_ttl = config.get("default_lease_ttl")
                if isinstance(default_ttl, int) and default_ttl > DEFAULT_LEASE_TTL_WARNING_SECONDS:
                    findings.append(
                        finding(
                            "VT-MOUNT-004",
                            namespace,
                            kind,
                            mount_path,
                            mount_type,
                            f"`default_lease_ttl` is {format_ttl(default_ttl)}, above the {format_ttl(DEFAULT_LEASE_TTL_WARNING_SECONDS)} review threshold — new leases get this TTL by default.",
                            default_lease_ttl_seconds=default_ttl,
                            threshold_seconds=DEFAULT_LEASE_TTL_WARNING_SECONDS,
                        )
                    )

                # "generic" is the pre-0.8 name for the same engine. A missing
                # version option means v1: Vault only writes it for v2.
                if mount_type in ("kv", "generic") and str((mount_data.get("options") or {}).get("version") or "1") == "1":
                    findings.append(
                        finding(
                            "VT-MOUNT-006",
                            namespace,
                            kind,
                            mount_path,
                            mount_type,
                            "KV version 1 — no secret versioning, soft delete or check-and-set.",
                            kv_version=1,
                        )
                    )

                # Built-ins are excluded because cubbyhole is *always* local —
                # it is per-token storage. Flagging it produced one noise row per
                # namespace and no signal at all.
                if mount_data.get("local") is True and mount_type not in BUILTIN_ENGINE_TYPES:
                    findings.append(
                        finding(
                            "VT-MOUNT-003",
                            namespace,
                            kind,
                            mount_path,
                            mount_type,
                            "Mount is `local` — it is not replicated to performance secondaries or DR.",
                            local=True,
                        )
                    )

            # One finding per namespace and kind, naming every crowded type, so
            # a namespace with 40 KV and 30 PKI mounts is one row, not two.
            by_type = Counter(m.get("type", "unknown") for m in mounts.values() if isinstance(m, dict) and m.get("type") not in BUILTIN_ENGINE_TYPES | BUILTIN_AUTH_TYPES)
            crowded = {t: n for t, n in sorted(by_type.items()) if n > MOUNT_SPRAWL_THRESHOLD}
            if crowded:
                findings.append(
                    finding(
                        "VT-MOUNT-005",
                        namespace,
                        kind,
                        None,
                        None,
                        f"{', '.join(f'{n} {t}' for t, n in crowded.items())} mounts in one namespace — consider fewer mounts with per-path policies.",
                        mounts_by_type=crowded,
                        threshold=MOUNT_SPRAWL_THRESHOLD,
                    )
                )

    findings.extend(cluster_lease_findings(system_default_lease_ttl))

    for namespace, mounts in data.auth_methods.items():
        external = {m.get("type") for m in mounts.values() if isinstance(m, dict) and m.get("type") not in BUILTIN_AUTH_TYPES}
        if not external:
            findings.append(
                finding(
                    "VT-NS-001",
                    namespace,
                    "namespace",
                    None,
                    None,
                    "No auth method beyond the built-in token backend — nothing can log in to this namespace directly.",
                    auth_types=sorted({m.get("type") for m in mounts.values() if isinstance(m, dict) and m.get("type")}),
                )
            )

    # Only leaf namespaces: a parent that holds nothing but child namespaces is
    # ordinary organisation, not an unused namespace.
    tree = build_namespace_tree(data)
    for namespace, mounts in data.secret_engines.items():
        if tree.get(namespace):
            continue
        non_builtin = {m.get("type") for m in mounts.values() if isinstance(m, dict) and m.get("type") not in BUILTIN_ENGINE_TYPES}
        if not non_builtin:
            findings.append(
                finding(
                    "VT-NS-002",
                    namespace,
                    "namespace",
                    None,
                    None,
                    "No secrets engine beyond the Vault built-ins, and no child namespaces — the namespace appears unused.",
                    secrets_engine_types=sorted({m.get("type") for m in mounts.values() if isinstance(m, dict) and m.get("type")}),
                )
            )

    findings.extend(_collect_sentinel_findings(data))

    findings.extend(_collect_license_findings(data, now))

    findings.extend(acl_policy_findings(data.acl_assessments))

    # Judged against the node's own clock at collection, not ``now``: the walk
    # can take minutes, and that must not read as replication lag.
    findings.extend(health_findings(data.cluster_health))

    return sort_findings(findings)


def _collect_license_findings(data: AuditData, now: datetime | None) -> list[Finding]:
    """Expiry findings, counted from ``now`` so they agree with the report date."""
    return license_findings(data.license_status, now)


def render_findings(findings: list[Finding]) -> str:
    """Findings grouped by severity, most severe first."""
    return render_findings_table(
        findings,
        "_No observations — no deprecated plugins, publicly listed auth mounts, long leases, KV v1 or crowded mounts, empty namespaces, Sentinel policy issues or cluster health problems were found._",
    )


def _access_gap_rows(forbidden: list[tuple[str, str]]) -> list[list[Any]]:
    """Denial rows, collapsing any reason that applies across the whole tree.

    A handful of denied namespaces is the interesting case and stays listed by
    name. The same denial repeated across every namespace is one missing policy
    rule wearing 134 hats, and spelling it out drowns the specific gaps.
    """
    by_scope: dict[str, list[str]] = {}
    for namespace, scope in forbidden:
        by_scope.setdefault(scope, []).append(namespace)

    rows: list[list[Any]] = []
    for scope in sorted(by_scope):
        namespaces = sorted(by_scope[scope])
        if len(namespaces) <= MAX_ACCESS_GAP_ROWS:
            rows.extend([namespace, scope] for namespace in namespaces)
        else:
            examples = ", ".join(namespaces[:3])
            rows.append([f"{len(namespaces)} namespaces ({examples}, …)", scope])
    return rows


def render_access_gaps(stats: AuditStats, start_namespace: str, license_unavailable_reason: str | None = None, cluster_coverage: Any = None) -> str:
    """What the audit could not reach — denials first, then errors.

    A denied license read is listed separately from the namespace denials: it
    is a cluster-level endpoint, and listing it against the root would claim
    the whole tree is incomplete when only the license data is missing.
    """
    parts: list[str] = []

    if stats.forbidden_namespaces:
        rows = _access_gap_rows(stats.forbidden_namespaces)
        parts.append(
            "The token was denied access to the following namespaces, so this report is incomplete below these paths:\n\n" + md_table(["Namespace", "What was denied"], rows),
        )
    elif stats.forbidden_count:
        # Counted but unattributed — older call sites, or a denial raised where
        # the namespace was not in scope.
        parts.append(f"{stats.forbidden_count} permission denial(s) were recorded without an attributed namespace.")
    else:
        parts.append(f"None — the audit covered the full tree reachable from `{display_namespace(start_namespace)}`.")

    if license_unavailable_reason == "denied":
        parts.append("**Cluster-level reads:** `sys/license/status` was denied, so the License section is incomplete.")
    # Cluster health denials sit here for the same reason as the license: they
    # say nothing about how much of the namespace tree was covered.
    if cluster_lines := render_cluster_reads(cluster_coverage):
        parts.append(cluster_lines)

    if stats.errors:
        rows = [[namespace, message] for namespace, message in sorted(stats.errors)]
        parts.append("**Errors**\n\n" + md_table(["Namespace", "Error"], rows))
    elif stats.error_count:
        parts.append(f"**Errors:** {stats.error_count} error(s) were recorded without an attributed namespace.")

    return "\n\n".join(parts)


def _summary_rows(
    data: AuditData,
    stats: AuditStats,
    worker_threads: int,
    system_lease_ttls: tuple[int, int] | None = None,
    sentinel_supported: bool | None = None,
) -> list[list[Any]]:
    nodes = _namespace_nodes(data)
    total_auth = sum(len(m) for m in data.auth_methods.values())
    total_engines = sum(len(m) for m in data.secret_engines.values())
    duration = stats.duration

    # Counted from the collected inventory rather than stats.discovered_count:
    # that counter is the progress-bar denominator and carries a seed value of 1
    # for the root, so it is not a namespace total. This is the cumulative count
    # of every namespace known to exist — root plus all descendants.
    total_namespaces = len(nodes)
    # The two agree on any run that drained the queue, so one number is enough.
    # They diverge only when a discovered namespace was never traversed, which
    # means the walk did not finish cleanly — worth showing, but not worth a
    # second row on every healthy report.
    namespaces_value: Any = total_namespaces if stats.processed_count == total_namespaces else f"{total_namespaces} ({stats.processed_count} processed)"

    rows: list[list[Any]] = [
        ["Namespaces", namespaces_value],
        ["Maximum nesting depth", max((_depth(n) for n in nodes), default=0)],
        ["Total auth methods", total_auth],
        ["Distinct auth method types", len(_type_distribution(data.auth_methods))],
        ["Total secrets engines", total_engines],
        ["Distinct secrets engine types", len(_type_distribution(data.secret_engines))],
        ["Duration", f"{duration:.2f}s" if duration is not None else "—"],
        ["Worker threads", worker_threads],
        ["Errors", stats.error_count],
        ["Permission denied (skipped)", stats.forbidden_count],
    ]
    # Unconditional, unlike the Sentinel rows: ACL policies exist on every
    # edition, so zero is a real measurement rather than an untested check.
    rows.append(["ACL policies", sum(len(n) for n in data.acl_policies.values())])
    if sentinel_supported:
        # Only on a cluster that answered: a pair of zero rows on every
        # Community report would imply Sentinel was checked and found wanting.
        rows.append(["Sentinel EGP policies", sum(len(p) for p in data.egp_policies.values())])
        rows.append(["Sentinel RGP policies", sum(len(p) for p in data.rgp_policies.values())])
    if system_lease_ttls:
        # The ceiling almost every mount inherits, so the reader can judge the
        # override findings below against it rather than against Vault's stock
        # defaults, which a tuned cluster will not be using.
        default_ttl, max_ttl = system_lease_ttls
        rows.append(["System lease TTL", f"{format_ttl(default_ttl)} default / {format_ttl(max_ttl)} max"])
    if isinstance(data.license_status, dict):
        expiry = data.license_status.get("expiration_time", "")
        if expiry:
            rows.append(["License expiry", expiry[:10]])
        features = data.license_status.get("features") or []
        rows.append(["Licensed features", len(features)])
    return rows


def build_markdown_report(
    cluster_name: str,
    data: AuditData,
    stats: AuditStats,
    *,
    start_namespace: str = "",
    vault_addr: str = "",
    worker_threads: int = 0,
    output_files: list[str] | None = None,
    generated_at: datetime | None = None,
    system_lease_ttls: tuple[int, int] | None = None,
    sentinel_supported: bool | None = None,
) -> str:
    """Render the complete namespace audit report as a markdown document.

    ``system_lease_ttls`` is the cluster's ``(default_lease_ttl, max_lease_ttl)``
    in seconds, used to calibrate the lease findings against the cluster's own
    ceiling. None when the token cannot read sys/config/state/sanitized.

    ``sentinel_supported`` is tri-state and the three cases read differently:
    True means the Sentinel endpoints answered, False means the cluster has none
    (Community, or Enterprise without Governance & Policy), and None means the
    collection never ran. "Zero policies" and "no Sentinel at all" are very
    different findings, so the section never collapses them into one.
    """
    generated = generated_at or datetime.now(UTC)
    system_max = system_lease_ttls[1] if system_lease_ttls else None
    system_default = system_lease_ttls[0] if system_lease_ttls else None
    findings = collect_findings(data, system_max_lease_ttl=system_max, now=generated, system_default_lease_ttl=system_default)

    header_rows = [
        ["Cluster", cluster_name],
        ["Generated", generated.strftime("%Y-%m-%d %H:%M:%S UTC")],
        ["Tool version", f"vault-tools {get_tool_version()}"],
        ["Starting namespace", display_namespace(start_namespace)],
    ]
    if vault_addr:
        header_rows.insert(1, ["Vault address", vault_addr])
    if data.cluster_id:
        header_rows.insert(1, ["Cluster ID", data.cluster_id])
    if data.vault_version:
        version = data.vault_version
        if data.is_enterprise is not None:
            version += " (Enterprise)" if data.is_enterprise else " (Community Edition)"
        header_rows.append(["Vault version", version])

    sentinel_sections: list[str] = ["## Sentinel policies", ""]
    if sentinel_supported is False:
        sentinel_sections.append(
            "Sentinel EGP/RGP endpoints are unavailable on this cluster — Vault Community, or an Enterprise licence without the Governance & Policy module. No policies were collected."
        )
    elif sentinel_supported is None:
        # None means no endpoint ever answered, which has two very different
        # causes. If the token was denied every time, saying "skipped" reads as
        # "you turned this off" and sends the reader looking for a flag they
        # never set — so distinguish them from what the denials recorded.
        if any(scope.startswith("sentinel") for _, scope in stats.forbidden_namespaces):
            sentinel_sections.append(
                "The token was denied access to the Sentinel policy endpoints in every namespace, so none were collected. See **Access gaps** above, and grant the `sys/policies/egp` and `sys/policies/rgp` rules from `policies/audit-policy.hcl`."
            )
        else:
            sentinel_sections.append("Sentinel collection was skipped, so this run says nothing about the governing policies in place.")
    else:
        egp_total = sum(len(p) for p in data.egp_policies.values())
        rgp_total = sum(len(p) for p in data.rgp_policies.values())
        body_status = data.policy_bodies.get("sentinel")
        body_note = (
            " Their bodies were not assessed: "
            + POLICY_BODY_NOTES[body_status].format(addon="policies/audit-policy-sentinel-reader.hcl")
            + ", so enforcement levels and the VT-SNT checks are unknown."
            if body_status in ("not readable", "names only")
            else ""
        )
        sentinel_sections.extend(
            [
                f"{egp_total} endpoint governing polic{'y' if egp_total == 1 else 'ies'} and {rgp_total} role governing polic{'y' if rgp_total == 1 else 'ies'} across the namespaces audited. "
                "Only `hard-mandatory` policies actually block a request." + body_note,
                "",
                "### Enforcement levels",
                "",
                render_enforcement_distribution(data.egp_policies, data.rgp_policies),
                "",
                "### Endpoint governing policies (EGP)",
                "",
                render_sentinel_policies(data.egp_policies, "egp"),
                "",
                "### Role governing policies (RGP)",
                "",
                render_sentinel_policies(data.rgp_policies, "rgp"),
            ]
        )

    license_content = render_license(data.license_status, data.is_enterprise, data.license_unavailable_reason)
    cluster_section: list[str] = []
    if cluster_content := render_cluster_health(data.cluster_health):
        cluster_section = [cluster_content, ""]

    license_section: list[str] = []
    if license_content:
        license_section = ["## License", "", license_content, ""]

    sections = [
        f"# Vault Namespace Audit — {cluster_name}",
        "",
        md_table(["Field", "Value"], header_rows),
        "",
        "## Summary",
        "",
        md_table(["Metric", "Value"], _summary_rows(data, stats, worker_threads, system_lease_ttls, sentinel_supported)),
        "",
        *license_section,
        *cluster_section,
        "## Access gaps",
        "",
        render_access_gaps(stats, start_namespace, data.license_unavailable_reason, data.cluster_coverage),
        "",
        "## Namespace inventory",
        "",
        "### Hierarchy",
        "",
        render_namespace_tree(data),
        "",
        "### Namespaces",
        "",
        render_namespace_inventory(data),
        "",
        "## Type distribution",
        "",
        "### Auth methods",
        "",
        render_type_distribution(data.auth_methods, "Auth method type"),
        "",
        render_type_matrix(data.auth_methods, "Auth methods"),
        "",
        "### Secrets engines",
        "",
        render_type_distribution(data.secret_engines, "Secrets engine type"),
        "",
        render_type_matrix(data.secret_engines, "Secrets engines"),
        "",
        "## ACL policies",
        "",
        "Policies defined in each namespace. Vault's own `default`, `root` and `default-ceiling` are present everywhere and are excluded.",
        "",
        render_acl_policies(data.acl_policies),
        "",
        render_acl_review_note(data.acl_assessments, data.policy_bodies.get("acl")),
        "",
        *sentinel_sections,
        "",
        "## Security observations",
        "",
        "These are prompts for review derived from mount metadata, not a compliance verdict. Informational rows are expected in a healthy cluster.",
        "",
        render_findings(findings),
        "",
        "## Output files",
        "",
        md_table(["File"], [[f] for f in (output_files or [])]),
        "",
    ]
    return "\n".join(sections)


def _cluster_denials(data: AuditData) -> list[tuple[str, str]]:
    """Cluster-level reads the token was refused, as root-namespace coverage rows.

    In findings.json they count against completeness, unlike the markdown's
    access-gaps table: a CI gate asking "was anything not judged?" must see a
    denied sys/audit, even though it says nothing about namespace coverage.
    """
    denied = [("", scope) for scope in (data.cluster_coverage.denied if data.cluster_coverage else [])]
    if data.license_unavailable_reason == "denied":
        denied.append(("", "sys/license/status"))
    return denied


def sentinel_status(sentinel_supported: bool | None) -> str:
    """The schema's three-way Sentinel state.

    None covers both "--no-sentinel" and "every probe was denied"; the second
    case is visible in the document's coverage denials, so it is not lost.
    """
    if sentinel_supported is True:
        return "supported"
    if sentinel_supported is False:
        return "unsupported"
    return "skipped"


def build_findings_json(
    cluster_name: str,
    data: AuditData,
    stats: AuditStats,
    *,
    start_namespace: str = "",
    vault_addr: str = "",
    worker_threads: int = 0,
    generated_at: datetime | None = None,
    system_lease_ttls: tuple[int, int] | None = None,
    sentinel_supported: bool | None = None,
) -> dict[str, Any]:
    """The namespace audit's findings as a findings.schema.json document.

    Takes the same arguments as build_markdown_report and runs the same
    collect_findings call, so given one ``generated_at`` the two files cannot
    disagree about what was found.
    """
    generated = generated_at or datetime.now(UTC)
    system_max = system_lease_ttls[1] if system_lease_ttls else None
    system_default = system_lease_ttls[0] if system_lease_ttls else None
    findings = collect_findings(data, system_max_lease_ttl=system_max, now=generated, system_default_lease_ttl=system_default)
    started = stats.start_time or generated
    finished = stats.end_time or generated
    return build_findings_document(
        findings,
        run=run_block(cluster_name, vault_addr, start_namespace, started, finished, worker_threads or None),
        cluster_context={
            "vault_version": data.vault_version,
            "enterprise": data.is_enterprise,
            "system_max_lease_ttl_seconds": system_max,
            "system_default_lease_ttl_seconds": system_default,
            "sentinel": sentinel_status(sentinel_supported),
            # Whether bodies were read, per kind: the token decides. Not in the
            # skill's schema, which permits extra cluster_context keys.
            "policy_bodies": dict(data.policy_bodies),
        },
        coverage=coverage_block(
            stats.processed_count,
            [*stats.forbidden_namespaces, *_cluster_denials(data)],
            [*stats.errors, *(data.cluster_coverage.error_rows() if data.cluster_coverage else [])],
            unattributed_denials=stats.forbidden_count - len(stats.forbidden_namespaces),
            unattributed_errors=stats.error_count - len(stats.errors),
        ),
        tool_version=get_tool_version(),
    )
