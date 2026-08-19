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

import importlib.metadata
import logging
import re
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any

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

SEVERITY_ORDER = ("Medium", "Low", "Info")

# Sentinel's three enforcement levels, ordered strongest first. Only
# hard-mandatory actually stops a request outright: soft-mandatory can be
# overridden by a caller holding a sudo-capable token, and advisory merely logs.
SENTINEL_ENFORCEMENT_LEVELS = ("hard-mandatory", "soft-mandatory", "advisory")

# A main rule that is the literal `true` passes every request unconditionally.
# Vault will not store a policy with no main rule at all, so this — not an empty
# body — is what a do-nothing Sentinel policy looks like on a real cluster.
ALWAYS_TRUE_MAIN = re.compile(r"^main\s*=\s*rule\s*\{\s*true\s*\}$")

# EGP paths that cover every endpoint in the namespace. Worth surfacing not
# because it is wrong — a catch-all EGP is a legitimate pattern — but because
# the blast radius should be a deliberate choice.
BROAD_EGP_PATHS = frozenset({"*", "/*"})


@dataclass(frozen=True)
class Finding:
    """One security observation about a single mount, namespace or Sentinel policy.

    ``mount``/``mount_type`` carry the policy name and its kind (``egp``/``rgp``)
    for the Sentinel checks, which is why the rendered column is headed "Object"
    rather than "Mount".
    """

    severity: str
    namespace: str
    mount: str
    mount_type: str
    detail: str


def get_tool_version() -> str:
    """Resolve the installed vault-tools version.

    Read from package metadata rather than importing ``main.__version__``:
    ``main`` imports the auditor, so that import would be circular.
    """
    try:
        return importlib.metadata.version("vault-tools")
    except importlib.metadata.PackageNotFoundError:
        return "unknown"


def format_ttl(seconds: int) -> str:
    """Render a TTL the way the Vault CLI does — whole hours where possible."""
    if seconds % 3600 == 0:
        return f"{seconds // 3600}h"
    if seconds % 60 == 0:
        return f"{seconds // 60}m"
    return f"{seconds}s"


def _format_multiple(value: int, baseline: int) -> str:
    """How many times larger value is than baseline, e.g. '90x' or '1.5x'."""
    ratio = value / baseline
    return f"{ratio:.0f}x" if abs(ratio - round(ratio)) < 0.05 else f"{ratio:.1f}x"


def display_namespace(path: str) -> str:
    """Render a stored namespace key for humans: root is '/', others keep a slash."""
    return "/" if path == "" else f"{path.rstrip('/')}/"


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
    meaningful = [stripped for line in body.splitlines() if (stripped := line.strip()) and not stripped.startswith(("#", "//"))]
    if not meaningful:
        return True
    # Joined rather than matched line by line — the rule is often wrapped.
    return ALWAYS_TRUE_MAIN.match(" ".join(meaningful)) is not None


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
            row.append(_policy_line_count(policy.get("policy")))
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


def render_sentinel_policies(collection: dict[str, Any], kind: str, max_rows: int = MAX_REPORT_NODES) -> str:
    """Table of Sentinel policies of one kind, across every namespace.

    The body itself is deliberately not rendered — a Sentinel policy runs to
    dozens of lines and there can be one per namespace, so the report reports a
    line count and the JSON dump carries the source for diffing.
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
        for namespace, policies in collection.items():
            for name, policy in policies.items():
                if not isinstance(policy, dict):
                    continue
                level = policy.get("enforcement_level")
                if level == "advisory":
                    findings.append(
                        Finding(
                            "Low",
                            namespace,
                            name,
                            kind,
                            "Enforcement level is `advisory` — the policy logs violations but never blocks a request.",
                        )
                    )
                elif level == "soft-mandatory":
                    findings.append(
                        Finding(
                            "Info",
                            namespace,
                            name,
                            kind,
                            "Enforcement level is `soft-mandatory` — a caller with a `sudo`-capable token can override it.",
                        )
                    )

                paths = policy.get("paths")
                if kind == "egp" and isinstance(paths, list) and any(p in BROAD_EGP_PATHS for p in paths):
                    findings.append(
                        Finding(
                            "Info",
                            namespace,
                            name,
                            kind,
                            "Endpoint path is a wildcard — the policy applies to every request in this namespace.",
                        )
                    )

                if _is_trivial_policy(policy.get("policy")):
                    findings.append(
                        Finding(
                            "Low",
                            namespace,
                            name,
                            kind,
                            "Policy body always evaluates to true — it enforces nothing despite appearing in the policy list.",
                        )
                    )
    return findings


def collect_findings(data: AuditData, system_max_lease_ttl: int | None = None) -> list[Finding]:
    """Derive security observations from the mount metadata already collected.

    These are prompts for review, not a compliance verdict — several are
    informational by design.

    ``system_max_lease_ttl`` is the cluster's own ``max_lease_ttl`` from
    sys/config/state/sanitized. When known, the lease check reports mounts that
    *override* it, which is the actionable question; without it the check falls
    back to the fixed LONG_MAX_LEASE_TTL_SECONDS threshold.

    Two checks Vault users often expect are deliberately absent because they
    would be pure noise rather than signal. ``max_lease_ttl == 0`` means "inherit
    the system default", not "unlimited" — on a real cluster 99.7% of mounts sit
    at 0, so flagging them buries every other finding. ``seal_wrap: false`` is
    the default for almost every mount type.
    """
    findings: list[Finding] = []
    # Compare against the cluster's real ceiling where available.
    ttl_baseline = system_max_lease_ttl if system_max_lease_ttl else LONG_MAX_LEASE_TTL_SECONDS

    for kind, collection in (("auth", data.auth_methods), ("secrets", data.secret_engines)):
        for namespace, mounts in collection.items():
            for mount_path, mount_data in mounts.items():
                if not isinstance(mount_data, dict):
                    continue
                mount_type = mount_data.get("type", "unknown")
                config = mount_data.get("config") or {}

                status = (mount_data.get("deprecation_status") or "").lower()
                if status in DEPRECATED_STATUSES:
                    findings.append(
                        Finding(
                            "Medium",
                            namespace,
                            mount_path,
                            mount_type,
                            f"Plugin lifecycle status is `{status}` — plan a migration before it stops working.",
                        )
                    )

                if kind == "auth" and config.get("listing_visibility") == "unauth":
                    findings.append(
                        Finding(
                            "Low",
                            namespace,
                            mount_path,
                            mount_type,
                            "`listing_visibility: unauth` — this mount is enumerable by unauthenticated callers.",
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
                    findings.append(Finding("Low", namespace, mount_path, mount_type, detail))

                # Built-ins are excluded because cubbyhole is *always* local —
                # it is per-token storage. Flagging it produced one noise row per
                # namespace and no signal at all.
                if mount_data.get("local") is True and mount_type not in BUILTIN_ENGINE_TYPES:
                    findings.append(
                        Finding(
                            "Info",
                            namespace,
                            mount_path,
                            mount_type,
                            "Mount is `local` — it is not replicated to performance secondaries or DR.",
                        )
                    )

    for namespace, mounts in data.auth_methods.items():
        external = {m.get("type") for m in mounts.values() if isinstance(m, dict) and m.get("type") not in BUILTIN_AUTH_TYPES}
        if not external:
            findings.append(
                Finding(
                    "Info",
                    namespace,
                    "—",
                    "—",
                    "No auth method beyond the built-in token backend — nothing can log in to this namespace directly.",
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
                Finding(
                    "Info",
                    namespace,
                    "—",
                    "—",
                    "No secrets engine beyond the Vault built-ins, and no child namespaces — the namespace appears unused.",
                )
            )

    findings.extend(_collect_sentinel_findings(data))

    findings.sort(key=lambda f: (SEVERITY_ORDER.index(f.severity), f.namespace, f.mount))
    return findings


def render_findings(findings: list[Finding]) -> str:
    """Findings grouped by severity, most severe first."""
    if not findings:
        return "_No observations — no deprecated plugins, publicly listed auth mounts, long leases, empty namespaces or non-blocking Sentinel policies were found._"

    sections: list[str] = []
    for severity in SEVERITY_ORDER:
        group = [f for f in findings if f.severity == severity]
        if not group:
            continue
        rows = [[display_namespace(f.namespace), f.mount, f.mount_type, f.detail] for f in group]
        # "Object", not "Mount": the Sentinel checks put a policy name in this
        # column, and findings that name a whole namespace put a dash in it.
        sections.append(f"#### {severity} ({len(group)})\n\n" + md_table(["Namespace", "Object", "Type", "Observation"], rows))
    return "\n\n".join(sections)


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


def render_access_gaps(stats: AuditStats, start_namespace: str) -> str:
    """What the audit could not reach — denials first, then errors."""
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
    findings = collect_findings(data, system_max_lease_ttl=system_max)

    header_rows = [
        ["Cluster", cluster_name],
        ["Generated", generated.strftime("%Y-%m-%d %H:%M:%S UTC")],
        ["Tool version", f"vault-tools {get_tool_version()}"],
        ["Starting namespace", display_namespace(start_namespace)],
    ]
    # Omitted rather than rendered empty when unknown: a blank address row would
    # read as "audited a cluster with no address" instead of "not recorded".
    if vault_addr:
        header_rows.insert(1, ["Vault address", vault_addr])

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
                "The token was denied access to the Sentinel policy endpoints in every namespace, so none were collected. See **Access gaps** above, and grant the `sys/policies/egp` and `sys/policies/rgp` rules from `audit-policy.hcl`."
            )
        else:
            sentinel_sections.append("Sentinel collection was skipped, so this run says nothing about the governing policies in place.")
    else:
        egp_total = sum(len(p) for p in data.egp_policies.values())
        rgp_total = sum(len(p) for p in data.rgp_policies.values())
        sentinel_sections.extend(
            [
                f"{egp_total} endpoint governing polic{'y' if egp_total == 1 else 'ies'} and {rgp_total} role governing polic{'y' if rgp_total == 1 else 'ies'} across the namespaces audited. "
                "Only `hard-mandatory` policies actually block a request.",
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

    sections = [
        f"# Vault Namespace Audit — {cluster_name}",
        "",
        md_table(["Field", "Value"], header_rows),
        "",
        "## Summary",
        "",
        md_table(["Metric", "Value"], _summary_rows(data, stats, worker_threads, system_lease_ttls, sentinel_supported)),
        "",
        "## Access gaps",
        "",
        render_access_gaps(stats, start_namespace),
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
