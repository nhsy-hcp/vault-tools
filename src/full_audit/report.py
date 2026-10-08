"""The full-audit report, laid out like the vault-ops skill's audit report.

The skill's report is written by a model reading the JSON; this one is
generated deterministically from the same data, so every sentence below is
built from a measured value and no section claims more than was collected.

Pure functions: no Vault calls, no filesystem.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from src.cluster_audit.findings import license_expiry_days, parse_license_time
from src.cluster_audit.report import render_cluster_health
from src.common.findings import RULES, SEVERITY_ORDER, Finding, display_namespace, finding_from_dict, format_ttl, get_tool_version
from src.common.markdown import md_escape, md_table
from src.common.remediation import CATALOGUE, fill_commands, rank_key

# Built-in engines, excluded from the secrets inventory like the skill does.
BUILTIN_ENGINE_TYPES = frozenset({"cubbyhole", "identity", "system", "ns_cubbyhole", "ns_identity", "ns_system", "ns_agent_registry", "agent_registry"})

# How many examples a ranked finding shows, and how many filled commands.
MAX_EXAMPLES = 3
# Rows in the hierarchy table before the rest are summarised.
MAX_SHAPES = 15
# Namespaces listed in the "busiest" style tables.
TOP_N = 10


@dataclass
class StepSummary:
    name: str
    status: str
    reason: str = ""
    findings: int | None = None
    duration: float | None = None


@dataclass
class FullAuditContext:
    """Everything the report reads. Built by full_audit.main; tests build it by hand."""

    cluster_name: str
    cluster_id: str | None
    vault_addr: str
    started_at: datetime
    finished_at: datetime
    workers: int
    window: tuple[str, str]
    merged: dict[str, Any]
    steps: list[StepSummary]
    health: dict[str, Any] | None = None
    license_status: dict[str, Any] | None = None
    license_reason: str | None = None
    lease_ttls: tuple[int, int] | None = None
    # namespace-audit's AuditData / AuditStats; None when the step did not run.
    audit_data: Any = None
    audit_stats: Any = None
    identity_rows: list[dict[str, Any]] | None = None
    activity_log: dict[str, Any] | None = None
    activity_ran: bool = False
    total_clients: int = 0
    current_month_clients: int | None = None
    activity_namespaces: list[dict[str, Any]] | None = None
    # "acl" / "sentinel" -> assessed, partial, not readable, names only, skipped, none found.
    policy_bodies: dict[str, str] = field(default_factory=dict)
    previous_diff: dict[str, Any] | None = None
    previous_path: str | None = None
    output_files: list[str] = field(default_factory=list)


@dataclass
class FindingGroup:
    rule_id: str
    severity: str
    findings: list[Finding]

    @property
    def count(self) -> int:
        return len(self.findings)

    @property
    def title(self) -> str:
        rule = RULES.get(self.rule_id)
        return rule.title if rule else self.rule_id


def group_findings(findings: list[Finding]) -> list[FindingGroup]:
    """One group per rule (and severity, since VT-LIC-001 can escalate), ranked like the skill does."""
    buckets: dict[tuple[str, str], list[Finding]] = defaultdict(list)
    for f in findings:
        buckets[(f.rule_id, f.severity)].append(f)
    groups = [FindingGroup(rule_id, severity, items) for (rule_id, severity), items in buckets.items()]
    return sorted(groups, key=lambda g: (*rank_key(g.rule_id, g.severity, g.count), g.rule_id))


def _plural(n: int, word: str, plural: str | None = None) -> str:
    return f"{n} {word if n == 1 else (plural or word + 's')}"


def _join(items: list[str]) -> str:
    if len(items) <= 1:
        return "".join(items)
    return ", ".join(items[:-1]) + f" and {items[-1]}"


def _severity_line(by_severity: dict[str, int]) -> str:
    parts = [f"{by_severity.get(s.lower(), 0)} {s.lower()}" for s in SEVERITY_ORDER if by_severity.get(s.lower())]
    return ", ".join(parts) or "none"


# --------------------------------------------------------------------------- header


_BODY_LABELS = {
    "assessed": "assessed",
    "partial": "partly assessed",
    "not readable": "not readable with this token",
    "names only": "names only (`--names-only`)",
    "skipped": "skipped (`--no-sentinel`)",
    "none found": "none to read",
}


def _bodies_line(policy_bodies: dict[str, str]) -> str:
    if not policy_bodies:
        return "Not collected"
    return f"ACL {_BODY_LABELS.get(policy_bodies.get('acl', ''), 'unknown')}; Sentinel {_BODY_LABELS.get(policy_bodies.get('sentinel', ''), 'unknown')}"


def _header(ctx: FullAuditContext) -> str:
    coverage = ctx.merged["coverage"]
    namespaces = len(ctx.audit_data.auth_methods) if ctx.audit_data is not None else coverage.get("namespaces_processed", 0)
    if coverage["complete"]:
        coverage_text = f"**Complete**: {_plural(namespaces, 'namespace')}, no denied scopes, no errors"
    else:
        coverage_text = f"**Partial**: {_plural(namespaces, 'namespace')}, {_plural(len(coverage['denied']), 'denied scope')}, {_plural(len(coverage['errors']), 'error')}"
    health = ctx.health or {}
    version = health.get("version") or "unknown"
    if health.get("enterprise") is not None:
        version += " (Enterprise)" if health["enterprise"] else " (Community Edition)"
    duration = (ctx.finished_at - ctx.started_at).total_seconds()
    sentinel = {"supported": "Assessed", "unsupported": "Not available on this cluster", "skipped": "Not assessed"}.get(ctx.merged["cluster_context"].get("sentinel"), "Not assessed")
    summary = ctx.merged["summary"]
    rows = [
        ["Cluster", f"`{ctx.cluster_name}`"],
        ["Cluster ID", f"`{ctx.cluster_id}`" if ctx.cluster_id else "unknown (a sealed node reports none)"],
        ["Address", f"`{ctx.vault_addr}`"],
        ["Vault version", version],
        ["Run time", f"{ctx.started_at.strftime('%Y-%m-%d %H:%M UTC')}, about {max(duration, 1):.0f}s"],
        ["Start namespace / workers", f"`/` (whole tree) / {ctx.workers}"],
        ["Coverage", coverage_text],
        ["Sentinel", sentinel],
        ["Policy bodies", _bodies_line(ctx.policy_bodies)],
        ["Activity window", f"{ctx.window[0]} to {ctx.window[1]}"],
        ["Findings", f"**{summary['total']}**: {_severity_line(summary['by_severity'])}"],
        ["Tool", f"vault-tools {get_tool_version()}"],
    ]
    return md_table(["", ""], rows)


# --------------------------------------------------------------------------- executive summary


def _license_sentence(ctx: FullAuditContext) -> str | None:
    lic = ctx.license_status
    if not isinstance(lic, dict) or not lic.get("expiration_time"):
        return None
    days = license_expiry_days(lic["expiration_time"], ctx.finished_at)
    if days is None:
        return None
    expiry = lic["expiration_time"][:10]
    termination = parse_license_time(lic.get("termination_time"))
    term_date = termination.strftime("%Y-%m-%d") if termination else None
    if days < 0:
        return f"The **licence expired on {expiry}**" + (f"; Vault stops serving at termination on **{term_date}**." if term_date else ".")
    if days > 90:
        return None
    if term_date == expiry:
        return f"The urgent item is the **licence**: it expires and terminates on the same day, **{expiry} ({_plural(days, 'day')})**, so there is no grace period."
    return f"The **licence** expires on **{expiry} ({_plural(days, 'day')})**" + (f", with a grace period until termination on {term_date}." if term_date else ".")


def _health_sentence(health: dict[str, Any]) -> str:
    if health.get("sealed"):
        return "The node is **sealed**: only its seal status could be read, so every other check was skipped."
    if health.get("initialized") is False:
        return "The node is **not initialized**: only its seal status could be read."
    leader = health.get("leader") or {}
    if leader.get("ha_enabled") and not leader.get("leader_address_present"):
        state = "is unsealed but HA has **no active leader**"
    elif leader:
        state = "is unsealed and has a healthy leader"
    else:
        state = "is unsealed"
    sentence = f"The cluster {state}."
    parts = []
    for kind, label in (("dr", "DR"), ("performance", "Performance")):
        status = (health.get("replication") or {}).get(kind) or {}
        mode = status.get("mode")
        if mode and mode not in ("disabled", "unknown"):
            peers = status.get("secondaries") or status.get("primaries") or []
            connected = sum(1 for p in peers if p.get("connection_status") == "connected")
            parts.append(f"{label} replication is `{mode}` in state `{status.get('state')}` with {connected} of {len(peers)} peer(s) connected")
    if parts:
        sentence += " " + "; ".join(parts) + "."
    return sentence


def _raft_sentence(health: dict[str, Any], groups: list[FindingGroup]) -> str | None:
    raft = health.get("raft") or {}
    peers = raft.get("peers") or []
    state = (raft.get("autopilot") or {}).get("state") or {}
    voters = sum(1 for p in peers if p.get("voter"))
    local_snapshots = any(g.rule_id == "VT-SNAP-003" for g in groups)
    if peers and (voters == 1 or state.get("failure_tolerance") == 0):
        sentence = f"Raft has {_plural(voters, 'voter')} (failure tolerance {state.get('failure_tolerance', 0)}): losing {'it' if voters == 1 else 'one'} loses quorum."
        if local_snapshots:
            sentence += " Automated snapshots are kept on that same node's disk."
        return sentence
    return None


def _clustering_sentence(groups: list[FindingGroup], findings: list[Finding]) -> str | None:
    # Only groups about one named object (a policy copied everywhere); a
    # whole-namespace rule like VT-NS-001 has no object to call out.
    copied = [g for g in groups if g.findings[0].object_path and len({f.namespace for f in g.findings}) > TOP_N and len({(f.object_path, f.detail) for f in g.findings}) == 1]
    parts = [f"`{g.findings[0].object_path}` accounts for {_plural(g.count, 'finding')} ({g.rule_id}), one copy per namespace" for g in copied[:2]]
    scoped = Counter(f.namespace.strip("/").split("/")[0] for f in findings if f.namespace.strip("/") and f.rule_id not in {g.rule_id for g in copied})
    if scoped:
        top, n = scoped.most_common(1)[0]
        total = sum(scoped.values())
        if total >= 3 and n / total >= 0.3:
            parts.append(f"{n} of the {total} remaining namespace-level findings sit under `{top}/`")
    return (_join(parts)[0].upper() + _join(parts)[1:] + ".") if parts else None


def executive_summary(ctx: FullAuditContext, groups: list[FindingGroup], findings: list[Finding]) -> str:
    paragraphs: list[str] = []
    coverage = ctx.merged["coverage"]
    if not coverage["complete"]:
        paragraphs.append(
            f"**Coverage is incomplete** ({_plural(len(coverage['denied']), 'denied scope')}, {_plural(len(coverage['errors']), 'error')}), so every conclusion below is partial. See **Not covered**."
        )
    health = ctx.health or {}
    if health:
        paragraphs.append(_health_sentence(health))
    urgent = [s for s in (_license_sentence(ctx),) if s]
    serious = [g for g in groups if g.severity in ("High", "Medium") and g.rule_id != "VT-LIC-001"]
    if serious:
        items = [f"{g.title} ({g.rule_id}{', ×' + str(g.count) if g.count > 1 else ''})" for g in serious[:3]]
        lead = "The other item" if len(serious) == 1 else f"The top {len(items)} other items"
        urgent.append(f"{lead} at medium or high severity: {_join(items)}.")
    if raft := _raft_sentence(health, groups):
        urgent.append(raft)
    if urgent:
        paragraphs.append(" ".join(urgent))
    if clustering := _clustering_sentence(groups, findings):
        paragraphs.append(clustering)
    if not findings:
        paragraphs.append("No findings were raised by any step.")
    return "\n\n".join(paragraphs)


# --------------------------------------------------------------------------- metrics and inventory


def _depth(ns: str) -> int:
    return 0 if not ns else len(ns.strip("/").split("/"))


def _types(mounts: dict[str, Any], exclude: frozenset[str] = frozenset()) -> list[str]:
    return sorted({m.get("type") for m in mounts.values() if isinstance(m, dict) and m.get("type") and m.get("type") not in exclude})


def summary_metrics(ctx: FullAuditContext) -> str:
    rows: list[list[Any]] = []
    data = ctx.audit_data
    if data is not None:
        namespaces = sorted(data.auth_methods)
        auth = [m for mounts in data.auth_methods.values() for m in mounts.values() if isinstance(m, dict)]
        secrets = [m for mounts in data.secret_engines.values() for m in mounts.values() if isinstance(m, dict) and m.get("type") not in BUILTIN_ENGINE_TYPES]
        rows += [
            ["Namespaces / max depth", f"{len(namespaces)} / {max((_depth(n) for n in namespaces), default=0)}"],
            ["Auth mounts", f"{len(auth):,}, across {len({m.get('type') for m in auth})} types"],
            ["Secrets engines", f"{len(secrets):,}, across {len({m.get('type') for m in secrets})} types (built-in engines excluded)"],
            ["ACL policies", f"{sum(len(p) for p in data.acl_policies.values()):,} (built-ins excluded)"],
        ]
        if ctx.merged["cluster_context"].get("sentinel") == "supported":
            rows.append(["Sentinel EGP / RGP", f"{sum(len(p) for p in data.egp_policies.values())} / {sum(len(p) for p in data.rgp_policies.values())}"])
    if ctx.lease_ttls:
        rows.append(["System lease TTLs", f"{format_ttl(ctx.lease_ttls[0])} default / {format_ttl(ctx.lease_ttls[1])} max"])
    elif ctx.health and not ctx.health.get("sealed"):
        rows.append(["System lease TTLs", "Not set or unreadable, so mount TTL checks used Vault's built-in 768h"])
    lic = ctx.license_status
    if isinstance(lic, dict):
        rows.append(["Licence", f"Expires {(lic.get('expiration_time') or '—')[:10]}, terminates {(lic.get('termination_time') or '—')[:10]}"])
    metrics = (ctx.health or {}).get("metrics") or {}
    if metrics:
        rows.append(["Leases / irrevocable (queried node)", f"{_num(metrics.get('leases'))} / {_num(metrics.get('irrevocable_leases'))}"])
    if ctx.identity_rows is not None:
        rows.append(["Identity entities", f"{sum(r['entities'] for r in ctx.identity_rows):,} in {sum(1 for r in ctx.identity_rows if r['entities'])} namespaces"])
    if ctx.activity_ran:
        clients = f"{ctx.total_clients:,} in the window"
        if ctx.current_month_clients is not None:
            clients += f", {ctx.current_month_clients:,} this month"
        rows.append(["Clients", clients])
    coverage = ctx.merged["coverage"]
    rows.append(["Denied / errors", f"{len(coverage['denied'])} / {len(coverage['errors'])}"])
    return md_table(["Metric", "Value"], rows)


def _num(value: Any) -> str:
    return f"{value:,}" if isinstance(value, int) else "not reported"


def hierarchy_shapes(data: Any) -> str:
    """Namespaces grouped by identical depth and mount types, like the skill's inventory."""
    shapes: dict[tuple[int, tuple[str, ...], tuple[str, ...]], list[str]] = defaultdict(list)
    for ns in sorted(data.auth_methods, key=lambda n: (_depth(n), n)):
        auth = tuple(_types(data.auth_methods.get(ns, {})))
        engines = tuple(_types(data.secret_engines.get(ns, {}), BUILTIN_ENGINE_TYPES))
        shapes[(_depth(ns), auth, engines)].append(ns)
    ordered = sorted(shapes.items(), key=lambda item: (item[0][0], -len(item[1])))
    rows = [
        [depth, ", ".join(auth) or "none", ", ".join(engines) or "none", len(members), ", ".join(f"`{display_namespace(m)}`" for m in members[:MAX_EXAMPLES])]
        for (depth, auth, engines), members in ordered[:MAX_SHAPES]
    ]
    table = md_table(["Depth", "Auth types", "Engine types", "Count", "Examples"], rows)
    if len(ordered) > MAX_SHAPES:
        rest = sum(len(m) for _, m in ordered[MAX_SHAPES:])
        table += f"\n\n_{len(ordered) - MAX_SHAPES} more shapes covering {rest} namespaces — see the namespace summary CSV._"
    return table


def inventory(ctx: FullAuditContext) -> str:
    parts: list[str] = []
    data = ctx.audit_data
    if data is not None:

        def type_table(collection: dict[str, Any], exclude: frozenset[str] = frozenset()) -> str:
            mounts: Counter[str] = Counter()
            spread: dict[str, set[str]] = defaultdict(set)
            for ns, items in collection.items():
                for m in items.values():
                    t = m.get("type") if isinstance(m, dict) else None
                    if t and t not in exclude:
                        mounts[t] += 1
                        spread[t].add(ns)
            return md_table(["Type", "Mounts", "Namespaces"], [[t, n, len(spread[t])] for t, n in sorted(mounts.items(), key=lambda i: (-i[1], i[0]))])

        parts += [
            "**Auth methods**",
            type_table(data.auth_methods),
            "**Secrets engines** (built-in cubbyhole, identity, system and agent registry engines excluded)",
            type_table(data.secret_engines, BUILTIN_ENGINE_TYPES),
            "**Hierarchy** (namespaces grouped by depth and mount types)",
            hierarchy_shapes(data),
        ]
        policies = sorted(data.acl_policies.items(), key=lambda i: (-len(i[1]), i[0]))
        total = sum(len(p) for p in data.acl_policies.values())
        busiest = [f"`{display_namespace(ns)}` ({len(p)})" for ns, p in policies[:TOP_N] if p]
        parts.append(f"**ACL policies:** {total:,} in total (built-ins excluded)." + (f" Busiest namespaces: {', '.join(busiest)}." if busiest else ""))
        if ctx.merged["cluster_context"].get("sentinel") == "supported":
            levels = Counter(p.get("enforcement_level", "unknown") for coll in (data.egp_policies, data.rgp_policies) for ns in coll.values() for p in ns.values() if isinstance(p, dict))
            parts.append("**Sentinel by enforcement level:** " + (", ".join(f"{n} {lvl}" for lvl, n in levels.most_common()) or "no policies") + ".")
    if ctx.identity_rows is not None:
        rows = sorted(ctx.identity_rows, key=lambda r: (-r["entities"], r["namespace"]))
        total = sum(r["entities"] for r in rows)
        parts.append(
            f"**Identity entities:** {total:,} in total; {sum(r['disabled'] for r in rows)} disabled, {sum(r['without_aliases'] for r in rows)} without aliases, "
            f"{sum(r['with_direct_policies'] for r in rows)} with direct policies. Entities are identified by ID only."
        )
        if total:
            parts.append(md_table(["Namespace", "Entities", "Alias mount types"], [[f"`{r['namespace']}`", r["entities"], r["alias_mount_types"] or "—"] for r in rows[:TOP_N] if r["entities"]]))
    if ctx.activity_ran:
        log = ctx.activity_log
        state = "unreadable" if log is None else f"`{log.get('enabled')}`" + (" — nothing is recorded, so zero counts are not real" if log.get("recording") is False else "")
        line = f"**Client usage:** activity log {state}; {ctx.total_clients:,} clients in {ctx.window[0]} to {ctx.window[1]}"
        if ctx.current_month_clients is not None:
            line += f", {ctx.current_month_clients:,} in the month in progress"
        parts.append(line + ".")
        busy = sorted((r for r in ctx.activity_namespaces or [] if r.get("clients")), key=lambda r: -r["clients"])
        if busy:
            parts.append(
                md_table(["Namespace", "Clients", "Entity", "Non-entity"], [[f"`{r['namespace_path'] or '/'}`", r["clients"], r["entity_clients"], r["non_entity_clients"]] for r in busy[:TOP_N]])
            )
    return "\n\n".join(parts) or "_Not collected: the namespace walk did not run._"


# --------------------------------------------------------------------------- findings


def _example(f: Finding) -> str:
    ns = display_namespace(f.namespace)
    return f"`{ns}` `{f.object_path}`" if f.object_path else f"`{ns}`"


def render_group(index: int, group: FindingGroup) -> str:
    remediation = CATALOGUE.get(group.rule_id)
    heading = f"### {index}. {group.title} ({group.rule_id}, {group.severity.lower()}{', ×' + str(group.count) if group.count > 1 else ''})"
    lines = [heading]
    namespaces = {f.namespace for f in group.findings}
    objects = {(f.object_path, f.detail) for f in group.findings}
    single_cluster = group.count == 1 and not group.findings[0].namespace and not group.findings[0].object_path
    # A single cluster-level finding's own detail already says what the rule
    # means, with the specifics; repeating the generic meaning above it reads twice.
    if remediation and not single_cluster:
        lines.append(remediation.meaning)
    if group.count > 1 and len(objects) == 1:
        lines.append(f"The same finding in {_plural(len(namespaces), 'namespace')}, e.g. {', '.join(_example(f) for f in group.findings[:MAX_EXAMPLES])}: {group.findings[0].detail}")
    elif group.count == 1:
        f = group.findings[0]
        lines.append(f.detail if single_cluster else f"{_example(f)}: {f.detail}")
    else:
        examples = [f"- {_example(f)}: {f.detail}" for f in group.findings[:MAX_EXAMPLES]]
        if group.count > MAX_EXAMPLES:
            examples.append(f"- …and {group.count - MAX_EXAMPLES} more in the findings JSON.")
        lines.append(f"{_plural(group.count, 'finding')} across {_plural(len(namespaces), 'namespace')}. Examples:\n\n" + "\n".join(examples))
    if remediation:
        commands: list[str] = []
        for f in group.findings[:MAX_EXAMPLES]:
            for command in fill_commands(f):
                if command not in commands:
                    commands.append(command)
        if commands:
            intro = f"For an operator to run: {remediation.action}" if remediation.action else "For an operator to run:"
            lines.append(intro.strip())
            more = f"\n# …and {group.count - MAX_EXAMPLES} more, one per finding" if group.count > MAX_EXAMPLES and len(commands) > 1 else ""
            lines.append("```\n" + "\n".join(commands) + more + "\n```")
        elif remediation.action:
            lines.append(f"For an operator (no catalogue command): {remediation.action}")
        if remediation.watch_out:
            lines.append(f"**Watch out:** {remediation.watch_out}")
    return "\n\n".join(lines)


def _rule_summary(groups: list[FindingGroup]) -> str:
    return md_table(["Rule", "Severity", "Count", "Title"], [[g.rule_id, g.severity.lower(), g.count, g.title] for g in groups])


# --------------------------------------------------------------------------- not covered, changes, sources


def not_covered(ctx: FullAuditContext) -> list[str]:
    items: list[str] = []
    for step in ctx.steps:
        if step.status != "ok":
            items.append(f"**{step.name}** {step.status}: {md_escape(step.reason)}")
    acl = ctx.policy_bodies.get("acl")
    if ctx.audit_data is not None and acl in ("not readable", "partial"):
        items.append(
            "**ACL permissions:** the token cannot read "
            + ("some " if acl == "partial" else "")
            + "policy bodies, so VT-POL rules were not judged there. Attach `policies/audit-policy-acl-reader.hcl` to the token to assess them."
        )
    elif ctx.audit_data is not None and acl == "names only":
        items.append("**ACL permissions:** `--names-only` was set, so VT-POL rules were not judged.")
    sentinel_bodies = ctx.policy_bodies.get("sentinel")
    sentinel = ctx.merged["cluster_context"].get("sentinel")
    if ctx.audit_data is not None and sentinel == "supported" and sentinel_bodies in ("not readable", "partial", "names only"):
        why = (
            "`--names-only` was set"
            if sentinel_bodies == "names only"
            else "the token cannot read " + ("some " if sentinel_bodies == "partial" else "") + "Sentinel bodies (attach `policies/audit-policy-sentinel-reader.hcl`)"
        )
        items.append(f"**Sentinel policies:** listed, but {why}, so enforcement levels and VT-SNT rules were not judged.")
    if ctx.audit_data is not None and sentinel == "unsupported":
        items.append("**Sentinel:** not available on this cluster (Community, or Enterprise without Governance & Policy), so VT-SNT rules do not apply.")
    elif ctx.audit_data is not None and sentinel == "skipped":
        items.append("**Sentinel:** collection was skipped or denied, so VT-SNT rules were not judged.")
    if ctx.activity_ran and ctx.activity_log and ctx.activity_log.get("recording") is False:
        items.append("**Client usage:** the activity log is off, so VT-CLI-001..004 and VT-ID-004 could not be judged.")
    elif ctx.activity_ran and not ctx.total_clients and not ctx.current_month_clients:
        items.append("**Client usage:** no clients were recorded in the window, so the client checks had nothing to judge.")
    coverage = ctx.merged["coverage"]
    if coverage["denied"]:
        scopes = Counter(d["scope"] for d in coverage["denied"])
        items.append("**Denied reads:** " + ", ".join(f"{scope} ({_plural(n, 'namespace')})" for scope, n in scopes.most_common(5)) + ". Check the token carries `policies/audit-policy.hcl`.")
    if coverage["errors"]:
        items.append(f"**Errors:** {_plural(len(coverage['errors']), 'read')} failed, e.g. {md_escape(coverage['errors'][0]['message'])}.")
    if ctx.previous_diff is None:
        items.append("**Comparison with an earlier audit:** no earlier full-audit findings file for this cluster in the output directory, so nothing to compare against.")
    return items


def changes_since_last_run(ctx: FullAuditContext) -> str | None:
    diff = ctx.previous_diff
    if diff is None:
        return None
    s = diff["summary"]
    parts = [f"Compared with `{ctx.previous_path}`: **{s['new']} new**, **{s['resolved']} resolved**, {s['unchanged']} unchanged, {s['evidence_changed']} with changed evidence."]
    if diff["new"]:
        parts.append(
            md_table(
                ["Rule", "Severity", "Namespace", "Object", "Detail"],
                [[f["rule_id"], f["severity"], f["namespace"], (f.get("object") or {}).get("path") or "—", f["detail"]] for f in diff["new"][:TOP_N]],
            )
        )
        if len(diff["new"]) > TOP_N:
            parts.append(f"_…and {len(diff['new']) - TOP_N} more new findings in the diff._")
    return "\n\n".join(parts)


def build_full_report(ctx: FullAuditContext) -> str:
    findings = [finding_from_dict(f) for f in ctx.merged["findings"]]
    groups = group_findings(findings)
    sections = [
        f"# Vault audit report: `{ctx.cluster_name}`",
        _header(ctx),
        "## Executive summary",
        executive_summary(ctx, groups, findings),
        "## Summary metrics",
        summary_metrics(ctx),
    ]
    if ctx.health:
        health_md = render_cluster_health(ctx.health).replace("## Cluster health", "## Cluster health and licence", 1)
        sections.append(health_md)
        if isinstance(ctx.license_status, dict):
            features = ", ".join(sorted(ctx.license_status.get("features") or [])) or "none listed"
            sections.append(f"**Licence features:** {features}")
        elif ctx.license_reason:
            sections.append(f"_Licence data unavailable: {md_escape(ctx.license_reason)}._")
    sections += ["## Inventory", inventory(ctx), "## Findings, ranked"]
    if groups:
        sections += [render_group(i, g) for i, g in enumerate(groups, 1)]
    else:
        sections.append("_No findings._")
    sections += ["## Summary", _rule_summary(groups) if groups else "_No findings._"]
    if changes := changes_since_last_run(ctx):
        sections += ["## Changes since the last run", changes]
    steps = md_table(
        ["Step", "Status", "Findings", "Duration", "Notes"],
        [[s.name, s.status, "—" if s.findings is None else s.findings, f"{s.duration:.1f}s" if s.duration is not None else "—", md_escape(s.reason) or "—"] for s in ctx.steps],
    )
    sections += ["## Steps", steps]
    gaps = not_covered(ctx)
    sections += ["## Not covered", "\n".join(f"- {item}" for item in gaps) if gaps else "Nothing: every step ran and every read succeeded."]
    sections += ["## Source files", "\n".join(f"- `{f}`" for f in ctx.output_files) or "_None._"]
    sections.append("This review was read-only, and nothing in Vault was changed. Drafted commands are for an operator to run after review.")
    return "\n\n".join(sections) + "\n"


def top_groups(merged: dict[str, Any], n: int = 5) -> list[FindingGroup]:
    """The highest-ranked finding groups, for the console summary."""
    return group_findings([finding_from_dict(f) for f in merged["findings"]])[:n]


__all__ = ["FullAuditContext", "StepSummary", "build_full_report", "group_findings", "top_groups"]
