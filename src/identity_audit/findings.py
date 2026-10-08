"""Identity finding checks (VT-ID-001..005), ported from the vault-ops skill.

Findings identify an entity by its ID, never its name: entity names and alias
names can be emails, usernames or AppRole role_ids, and findings reach every
output. The skill puts the name in the object path, so VT-ID-001..003
fingerprints differ between the two tools; the per-namespace rules match.

Pure functions only.
"""

from __future__ import annotations

from src.common.findings import Finding, finding
from src.identity_audit.collector import Entity

# VT-ID-004: a namespace with at least this many entities, and more than this
# multiple of its active entity clients, is creating identities per login or
# never cleaning them up. Both bounds keep small namespaces out of it.
ENTITY_RULE_MIN_ENTITIES = 100
ENTITY_ACTIVE_RATIO_WARNING = 3


def entity_findings(entities: dict[str, list[Entity]], active: dict[str, int] | None = None) -> list[Finding]:
    findings: list[Finding] = []
    for ns, items in entities.items():
        if active is not None and len(items) >= ENTITY_RULE_MIN_ENTITIES and len(items) > ENTITY_ACTIVE_RATIO_WARNING * active.get(ns, 0):
            used = active.get(ns, 0)
            ratio = f"{len(items) / used:.0f} per active client" if used else "none active"
            findings.append(
                finding(
                    "VT-ID-004",
                    ns,
                    "namespace",
                    None,
                    None,
                    f"{len(items)} entities but {used} active entity clients ({ratio}) — identities are created per login or run, or never cleaned up.",
                    entities=len(items),
                    active_entity_clients=used,
                )
            )
        # Counts only: the alias names themselves can be emails or role_ids.
        owners: dict[str, set[str]] = {}
        for e in items:
            for alias in e.aliases:
                if alias.get("name"):
                    owners.setdefault(str(alias["name"]).casefold(), set()).add(e.id)
        shared = [ids for ids in owners.values() if len(ids) > 1]
        if shared:
            affected = set().union(*shared)
            findings.append(
                finding(
                    "VT-ID-005",
                    ns,
                    "namespace",
                    None,
                    None,
                    f"{len(shared)} alias name(s) appear on {len(affected)} separate entities — the same user logging in through different auth mounts is counted as separate clients.",
                    shared_alias_names=len(shared),
                    entities_affected=len(affected),
                )
            )
        for e in items:
            # Only judged when the body was read: a denied read has no aliases
            # to show, and that is not evidence of an orphan.
            if e.disabled is not None and not e.aliases:
                findings.append(
                    finding(
                        "VT-ID-001",
                        ns,
                        "entity",
                        e.id,
                        None,
                        "Entity has no aliases — no login maps to it, so it is orphaned or was created by hand and never linked.",
                        entity_id=e.id,
                        group_count=e.group_count,
                    )
                )
            if e.policies:
                findings.append(
                    finding(
                        "VT-ID-002",
                        ns,
                        "entity",
                        e.id,
                        None,
                        f"Policies attached directly to the entity ({', '.join(e.policies)}) — prefer granting through groups so access is reviewable in one place.",
                        entity_id=e.id,
                        policies=e.policies,
                    )
                )
            if e.disabled:
                findings.append(
                    finding(
                        "VT-ID-003",
                        ns,
                        "entity",
                        e.id,
                        None,
                        "Entity is disabled — its tokens are refused; remove it if the identity is gone for good.",
                        entity_id=e.id,
                        alias_count=len(e.aliases),
                    )
                )
    return findings
