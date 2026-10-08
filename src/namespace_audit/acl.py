"""ACL policy body assessment, ported from the vault-ops skill.

Opt-in only (``namespace-audit --acl-bodies`` plus the read-only
``audit-policy-acl-reader.hcl`` add-on). Bodies are parsed in memory and
reduced to an ``AclAssessment``: a hash, a rule count and the flagged rules'
paths and capabilities. The body itself — and every allowed/denied parameter
value inside it — never leaves this module, never reaches AuditData and is
never written to disk.

Each ``path`` rule is judged on its own. A ``deny`` elsewhere in the policy, or
another policy on the same token, can narrow a flagged rule, and nothing here
knows which tokens or entities hold the policy: findings are prompts for review.

Pure functions: no Vault calls, no filesystem.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from typing import Any

from src.common.findings import Finding, drift_findings, finding

# Capabilities that change state; sudo is judged separately (VT-POL-003).
WRITE_CAPABILITIES = frozenset({"create", "update", "patch", "delete"})

# Representative paths whose write access lets a holder grant itself or others
# more access (VT-POL-002). A rule is flagged when its glob matches one of
# them; the value labels the area in the finding. "x" stands for any name.
ESCALATION_PATHS = {
    "sys/policies/acl/x": "ACL policies",
    "sys/policy/x": "ACL policies",
    "sys/auth/x": "auth methods",
    "sys/mounts/x": "secrets engines",
    "sys/namespaces/x": "namespaces",
    "auth/token/create": "token creation",
    "auth/token/create-orphan": "token creation",
    "auth/token/create/x": "token creation",
    "auth/token/roles/x": "token roles",
    "identity/entity": "identity entities",
    "identity/entity/id/x": "identity entities",
    "identity/entity/name/x": "identity entities",
    "identity/entity-alias": "identity entity aliases",
    "identity/entity-alias/id/x": "identity entity aliases",
    "identity/group": "identity groups",
    "identity/group/id/x": "identity groups",
    "identity/group/name/x": "identity groups",
}

# The legacy `policy = "..."` attribute, as Vault expands it into capabilities.
LEGACY_POLICY_CAPABILITIES = {
    "deny": ("deny",),
    "read": ("read", "list"),
    "write": ("create", "read", "update", "delete", "list"),
    "sudo": ("create", "read", "update", "delete", "list", "sudo"),
}

# The access-gap scope a denied body read records, naming the fix.
BODY_DENIED_SCOPE = "ACL policy bodies (attach audit-policy-acl-reader)"

_HCL_TOKEN = re.compile(r'\s+|#[^\n]*|//[^\n]*|/\*.*?\*/|"(?:[^"\\]|\\.)*"|[A-Za-z_][\w.-]*|-?\d+(?:\.\d+)?|[{}\[\]=,:]', re.S)


@dataclass(frozen=True)
class AclRule:
    path: str
    capabilities: tuple[str, ...]


@dataclass(frozen=True)
class AclAssessment:
    """What is kept of one policy: never its body."""

    sha256: str
    parsed: bool
    rule_count: int
    # [{"path", "capabilities", "rules"}] for every rule that tripped a check.
    flagged: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {"sha256": self.sha256, "parsed": self.parsed, "rule_count": self.rule_count, "flagged": self.flagged}


def parse_acl_policy(text: str) -> tuple[AclRule, ...] | None:
    """Path rules of an HCL or JSON ACL policy; None when it cannot be parsed. Never raises.

    Only ``path`` blocks, their ``capabilities`` and the legacy ``policy``
    attribute are kept: other attributes (allowed/denied parameters, wrapping
    TTLs) are skipped unread.
    """
    try:
        if text.lstrip().startswith("{"):
            paths = json.loads(text).get("path") or {}
            return tuple(
                AclRule(str(glob), tuple(str(c) for c in (body or {}).get("capabilities") or []) + LEGACY_POLICY_CAPABILITIES.get(str((body or {}).get("policy")), ())) for glob, body in paths.items()
            )
        return _parse_hcl_policy(text)
    except (ValueError, TypeError, IndexError, AttributeError):
        return None


def _parse_hcl_policy(text: str) -> tuple[AclRule, ...] | None:
    tokens, pos = [], 0
    while pos < len(text):
        match = _HCL_TOKEN.match(text, pos)
        if not match:
            return None
        pos = match.end()
        if not match.group()[0].isspace() and not match.group().startswith(("#", "//", "/*")):
            tokens.append(match.group())

    def skip_value(i: int) -> int:
        if tokens[i] not in ("{", "["):
            return i + 1
        depth = 0
        while True:
            depth += {"{": 1, "[": 1, "}": -1, "]": -1}.get(tokens[i], 0)
            i += 1
            if depth == 0:
                return i

    rules, i = [], 0
    while i < len(tokens):
        if tokens[i] != "path" or not tokens[i + 1].startswith('"') or tokens[i + 2] != "{":
            return None
        glob, capabilities, i = json.loads(tokens[i + 1]), [], i + 3
        while tokens[i] != "}":
            key = tokens[i].strip('"')
            i += 2 if tokens[i + 1] == "=" else 1
            if key == "capabilities" and tokens[i] == "[":
                i += 1
                while tokens[i] != "]":
                    if tokens[i] != ",":
                        capabilities.append(json.loads(tokens[i]))
                    i += 1
                i += 1
            elif key == "policy" and tokens[i].startswith('"'):
                # Pre-0.9 syntax, still accepted: `policy = "sudo"` is the
                # full capability set, so skipping it hid root-level grants.
                capabilities.extend(LEGACY_POLICY_CAPABILITIES.get(json.loads(tokens[i]), ()))
                i += 1
            else:
                i = skip_value(i)
            if tokens[i] == ",":
                i += 1
        rules.append(AclRule(glob, tuple(capabilities)))
        i += 1
    return tuple(rules)


def glob_matches(glob: str, path: str) -> bool:
    """Vault ACL path matching: ``+`` is one whole segment, a trailing ``*`` is a prefix match."""
    prefix = glob.endswith("*")
    pattern = "/".join("[^/]+" if part == "+" else re.escape(part) for part in (glob[:-1] if prefix else glob).split("/"))
    return re.fullmatch(pattern + (".*" if prefix else ""), path) is not None


def matches_everything(glob: str) -> bool:
    """``*``, ``+/*``, ``+/+/*``...: every path in the namespace (and, past the ``+`` levels, its children)."""
    return glob.endswith("*") and all(part in ("+", "") for part in glob[:-1].split("/"))


def _as_concrete_path(glob: str) -> str:
    """A representative concrete path for a rule glob: ``+`` and a trailing ``*`` become ``x``."""
    concrete = "/".join("x" if part == "+" else part for part in glob.split("/"))
    return concrete[:-1] + "x" if concrete.endswith("*") else concrete


def escalation_areas(glob: str) -> set[str]:
    """The access-control areas a rule glob touches, in either direction.

    A broad glob (``sys/*``) covers the representative targets; a narrow one
    (``sys/policies/acl/admin``, ``auth/token/roles/ci``) falls inside a target's
    area. Checking only the first direction missed every rule that names one
    specific policy, mount or role — the most common way such grants are written.
    The narrow check also ignores leading namespace segments, so a grant on a
    child namespace's policies from the root is caught too.
    """
    segments = _as_concrete_path(glob).split("/")
    # Every suffix too: a root-namespace policy reaches child namespaces through
    # prefixed paths (`+/sys/policies/acl/*`, `team-a/auth/token/create`).
    suffixes = ["/".join(segments[i:]) for i in range(len(segments))]
    areas = set()
    for target, label in ESCALATION_PATHS.items():
        area = "/".join("+" if part == "x" else part for part in target.split("/"))
        if glob_matches(glob, target) or any(glob_matches(area, suffix) for suffix in suffixes):
            areas.add(label)
    return areas


def rule_flags(rule: AclRule) -> list[str]:
    """VT-POL rule IDs one path rule trips. A rule containing ``deny`` grants nothing.

    ``sudo`` on a match-everything path is VT-POL-001 alone, not also VT-POL-003:
    the admin finding already covers it. Reporting both doubled every copy of
    an ``admin`` policy — 124 of 167 findings on a 78-namespace dev cluster.
    """
    capabilities = set(rule.capabilities)
    if "deny" in capabilities:
        return []
    if matches_everything(rule.path) and capabilities & (WRITE_CAPABILITIES | {"sudo"}):
        return ["VT-POL-001"]
    flags = []
    if capabilities & WRITE_CAPABILITIES and escalation_areas(rule.path):
        flags.append("VT-POL-002")
    if "sudo" in capabilities:
        flags.append("VT-POL-003")
    return flags


def assess_policy(body: str) -> AclAssessment:
    """Reduce a policy body to what may be kept. The caller must drop ``body`` afterwards."""
    digest = hashlib.sha256(body.encode()).hexdigest()[:16]
    rules = parse_acl_policy(body)
    if rules is None:
        return AclAssessment(digest, False, 0)
    flagged = [{"path": r.path, "capabilities": sorted(r.capabilities), "rules": ids} for r in rules if (ids := rule_flags(r))]
    return AclAssessment(digest, True, len(rules), flagged)


def _flagged_paths(assessment: AclAssessment, rule_id: str) -> list[str]:
    return sorted({f["path"] for f in assessment.flagged if rule_id in f["rules"]})


def acl_policy_findings(assessments: dict[str, dict[str, AclAssessment]]) -> list[Finding]:
    """VT-POL-001..005 from ``{namespace: {policy name: AclAssessment}}``."""
    findings: list[Finding] = []
    for namespace in sorted(assessments):
        for name, a in sorted(assessments[namespace].items()):
            if not a.parsed:
                findings.append(finding("VT-POL-005", namespace, "acl_policy", name, None, "Policy body could not be parsed, so its permissions were not assessed — review it by hand."))
                continue
            if paths := _flagged_paths(a, "VT-POL-001"):
                detail = f"Grants write or sudo on every path ({', '.join(f'`{x}`' for x in paths)}) — effectively admin in this namespace."
                findings.append(finding("VT-POL-001", namespace, "acl_policy", name, None, detail, paths=paths))
            if paths := _flagged_paths(a, "VT-POL-002"):
                areas = sorted({label for p in paths for label in escalation_areas(p)})
                detail = f"Can write {', '.join(areas)} ({', '.join(f'`{x}`' for x in paths)}) — a holder can grant itself or others more access."
                findings.append(finding("VT-POL-002", namespace, "acl_policy", name, None, detail, areas=areas, paths=paths))
            if paths := _flagged_paths(a, "VT-POL-003"):
                findings.append(finding("VT-POL-003", namespace, "acl_policy", name, None, f"Grants `sudo` on {', '.join(f'`{x}`' for x in paths)}.", sudo_paths=paths))

    copies: dict[str, list[tuple[str, str]]] = {}
    for namespace, policies in assessments.items():
        for name, a in policies.items():
            copies.setdefault(name, []).append((namespace, a.sha256))
    findings.extend(drift_findings("VT-POL-004", "acl_policy", None, copies))
    return findings
