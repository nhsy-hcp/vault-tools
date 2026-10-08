"""Shared findings model, findings.json document, run diffing and exit codes.

Every audit produces ``Finding`` objects and serialises them through
``build_findings_document``. The document follows the vault-ops skill's
``findings.schema.json`` (vendored in ``schemas/``), so either tool can read
the other's output and ``diff`` works across runs of both. Rule IDs, severities
and categories come from the skill's catalogue and must not be renumbered: the
fingerprint is derived from the rule ID, so a rename reads as "resolved" plus
"new" in every diff.

Pure functions only — no Vault calls and no filesystem access.
"""

from __future__ import annotations

import hashlib
import importlib.metadata
from collections import Counter
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from types import MappingProxyType
from typing import Any

# Version of the vendored schema. Bump together with schemas/findings.schema.json.
FINDINGS_SCHEMA_VERSION = "1.10.0"
TOOL_NAME = "vault-tools"

# Title case is what the markdown renders; the JSON uses the lower-case form.
SEVERITY_ORDER = ("High", "Medium", "Low", "Info")

# Exit codes for --fail-on / --fail-on-gaps. 1 stays the generic fatal error.
EXIT_OK = 0
EXIT_GAPS = 2
EXIT_FINDINGS = 3

# The schema caps coverage error messages; a full hvac error can run to KBs.
MAX_ERROR_MESSAGE_LENGTH = 200


@dataclass(frozen=True)
class Rule:
    severity: str
    category: str
    title: str


# Only the rules vault-tools emits. IDs, severities and titles match the skill's
# references/rules.md; later rules are added as their checks are ported.
RULES: dict[str, Rule] = {
    "VT-MOUNT-001": Rule("Medium", "lifecycle", "Plugin deprecated or pending removal"),
    "VT-AUTH-001": Rule("Low", "exposure", "Auth mount listed to unauthenticated callers"),
    "VT-MOUNT-002": Rule("Low", "lease", "Mount max lease TTL overrides cluster ceiling"),
    "VT-MOUNT-003": Rule("Info", "replication", "Mount is local (not replicated)"),
    "VT-MOUNT-004": Rule("Low", "lease", "Mount default lease TTL is long"),
    "VT-MOUNT-005": Rule("Info", "hygiene", "Many mounts of one type in a namespace"),
    "VT-MOUNT-006": Rule("Info", "hygiene", "KV version 1 mount"),
    "VT-NS-001": Rule("Info", "hygiene", "Namespace has no auth method beyond token"),
    "VT-NS-002": Rule("Info", "hygiene", "Leaf namespace appears unused"),
    "VT-SNT-001": Rule("Low", "governance", "Sentinel policy is advisory"),
    "VT-SNT-002": Rule("Info", "governance", "Sentinel policy is overridable"),
    "VT-SNT-003": Rule("Info", "governance", "EGP applies to every path"),
    "VT-SNT-004": Rule("Low", "governance", "Sentinel policy always evaluates true"),
    "VT-SNT-005": Rule("Low", "governance", "Same-named Sentinel policy differs across namespaces"),
    "VT-SNT-006": Rule("Medium", "governance", "Hard-mandatory Sentinel policy always evaluates false"),
    "VT-SNT-007": Rule("Info", "governance", "Sentinel policy makes outbound HTTP calls"),
    "VT-LIC-001": Rule("Medium", "lifecycle", "License expires soon"),
    "VT-LEASE-001": Rule("Low", "lease", "Cluster default lease TTL is long"),
    "VT-HLTH-001": Rule("Medium", "availability", "Node sealed or no active leader"),
    "VT-HLTH-002": Rule("Medium", "replication", "Replication enabled but not healthy"),
    "VT-HLTH-003": Rule("Info", "lifecycle", "Vault version below supported window"),
    "VT-HLTH-004": Rule("Medium", "availability", "Raft autopilot reports the cluster or a server unhealthy"),
    "VT-HLTH-005": Rule("Low", "lease", "Irrevocable leases present"),
    "VT-HLTH-006": Rule("Medium", "lease", "Lease count is high"),
    "VT-REPL-001": Rule("Medium", "replication", "Replication peer is lagging"),
    "VT-REPL-002": Rule("Low", "replication", "Known secondary has no heartbeat (never connected, or down since the primary started)"),
    "VT-REPL-003": Rule("Medium", "replication", "Clock skew between replication peers"),
    "VT-REPL-004": Rule("High", "replication", "Replication merkle tree reported corrupted"),
    "VT-REPL-005": Rule("Info", "replication", "Performance replication paths filter in use"),
    "VT-AUD-001": Rule("Medium", "audit", "No audit device enabled"),
    "VT-AUD-002": Rule("Low", "audit", "Only one audit device enabled"),
    "VT-AUD-003": Rule("Medium", "audit", "Audit device logs raw values or unhashed accessors"),
    "VT-SNAP-001": Rule("Medium", "backup", "No automated Raft snapshots configured"),
    "VT-SNAP-002": Rule("Medium", "backup", "Automated snapshot failing or overdue"),
    "VT-SNAP-003": Rule("Info", "backup", "Automated snapshots stored on the node's local disk"),
    "VT-POL-001": Rule("Medium", "access", "ACL policy grants write or sudo on every path"),
    "VT-POL-002": Rule("Medium", "access", "ACL policy can change access control"),
    "VT-POL-003": Rule("Low", "access", "ACL policy grants sudo"),
    "VT-POL-004": Rule("Low", "access", "Same-named ACL policy differs across namespaces"),
    "VT-POL-005": Rule("Info", "access", "ACL policy could not be parsed"),
}


def get_tool_version() -> str:
    """Resolve the installed vault-tools version.

    Read from package metadata rather than importing ``main.__version__``:
    ``main`` imports the auditors, so that import would be circular.
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


def display_namespace(path: str) -> str:
    """Render a stored namespace key for humans: root is '/', others keep a slash."""
    return "/" if path == "" else f"{path.rstrip('/')}/"


def _coverage_namespace(path: str) -> str:
    """The auditor labels the root "root" in its denial and error records."""
    return "/" if path in ("", "/", "root") else display_namespace(path)


def fingerprint(rule_id: str, namespace: str, kind: str, path: str | None) -> str:
    """Stable identity of a finding across runs; identical to the skill's."""
    raw = f"{rule_id}|{display_namespace(namespace)}|{kind}|{path or ''}"
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


@dataclass(frozen=True)
class Finding:
    """One observation about a mount, namespace, policy or the cluster.

    ``severity`` is normally the rule's own, but a rule may escalate it — an
    already-expired license is VT-LIC-001 at High rather than a separate rule,
    so a diff shows the same finding getting worse instead of one resolving and
    another appearing.
    """

    rule_id: str
    severity: str
    namespace: str
    object_kind: str
    object_path: str | None
    object_type: str | None
    detail: str
    evidence: Mapping[str, Any] = field(default_factory=lambda: MappingProxyType({}), compare=False, hash=False)

    @property
    def rule(self) -> Rule:
        return RULES[self.rule_id]

    @property
    def mount(self) -> str:
        """Object column for the markdown tables; a dash for whole-namespace findings."""
        return self.object_path or "—"

    @property
    def mount_type(self) -> str:
        return self.object_type or "—"

    @property
    def fingerprint(self) -> str:
        return fingerprint(self.rule_id, self.namespace, self.object_kind, self.object_path)

    def to_dict(self) -> dict[str, Any]:
        return {
            "fingerprint": self.fingerprint,
            "rule_id": self.rule_id,
            "severity": self.severity.lower(),
            "category": self.rule.category,
            "namespace": display_namespace(self.namespace),
            "object": {"kind": self.object_kind, "path": self.object_path, "type": self.object_type},
            "title": self.rule.title,
            "detail": self.detail,
            "evidence": dict(sorted(self.evidence.items())),
        }


def finding(
    rule_id: str,
    namespace: str,
    object_kind: str,
    object_path: str | None,
    object_type: str | None,
    detail: str,
    *,
    severity: str | None = None,
    **evidence: Any,
) -> Finding:
    """Build a Finding with the rule's default severity unless one is given."""
    return Finding(
        rule_id,
        severity or RULES[rule_id].severity,
        namespace,
        object_kind,
        object_path,
        object_type,
        detail,
        MappingProxyType(evidence),
    )


def sort_findings(findings: list[Finding]) -> list[Finding]:
    """Most severe first, then by namespace, object and rule."""
    return sorted(
        findings,
        key=lambda f: (SEVERITY_ORDER.index(f.severity), f.namespace, f.mount, f.rule_id),
    )


def _iso(ts: datetime) -> str:
    # Naive timestamps (AuditStats uses datetime.now()) are local time.
    aware = ts if ts.tzinfo else ts.astimezone()
    return aware.astimezone(UTC).isoformat().replace("+00:00", "Z")


def run_block(
    cluster_name: str,
    vault_addr: str,
    start_namespace: str,
    started_at: datetime,
    finished_at: datetime,
    worker_threads: int | None = None,
) -> dict[str, Any]:
    block: dict[str, Any] = {
        "cluster_name": cluster_name,
        "vault_addr": vault_addr,
        "start_namespace": display_namespace(start_namespace),
        "started_at": _iso(started_at),
        "finished_at": _iso(finished_at),
        "duration_seconds": max(round((finished_at - started_at).total_seconds(), 1), 0.0),
    }
    if worker_threads:
        block["worker_threads"] = worker_threads
    return block


def coverage_block(
    namespaces_processed: int,
    denied: list[tuple[str, str]],
    errors: list[tuple[str, str]],
    *,
    unattributed_denials: int = 0,
    unattributed_errors: int = 0,
) -> dict[str, Any]:
    """Coverage in the schema's shape.

    The unattributed counts are failures recorded without a namespace. They have
    no row to go in, but they still make the run incomplete — dropping them
    would let --fail-on-gaps pass a run that missed data.
    """
    return {
        "namespaces_processed": namespaces_processed,
        "complete": not denied and not errors and not unattributed_denials and not unattributed_errors,
        "denied": sorted(
            ({"namespace": _coverage_namespace(ns), "scope": scope} for ns, scope in denied),
            key=lambda d: (d["namespace"], d["scope"]),
        ),
        "errors": sorted(
            ({"namespace": _coverage_namespace(ns), "message": message[:MAX_ERROR_MESSAGE_LENGTH]} for ns, message in errors),
            key=lambda d: (d["namespace"], d["message"]),
        ),
    }


def build_findings_document(
    findings: list[Finding],
    *,
    run: dict[str, Any],
    cluster_context: dict[str, Any],
    coverage: dict[str, Any],
    tool_version: str,
) -> dict[str, Any]:
    ordered = sort_findings(findings)
    by_severity = {s.lower(): 0 for s in SEVERITY_ORDER}
    by_severity.update(Counter(f.severity.lower() for f in ordered))
    return {
        "schema_version": FINDINGS_SCHEMA_VERSION,
        "tool": {"name": TOOL_NAME, "version": tool_version},
        "run": run,
        "cluster_context": cluster_context,
        "coverage": coverage,
        "summary": {
            "total": len(ordered),
            "by_severity": by_severity,
            "by_rule": dict(sorted(Counter(f.rule_id for f in ordered).items())),
        },
        "findings": [f.to_dict() for f in ordered],
    }


def diff_documents(old: dict[str, Any], new: dict[str, Any]) -> dict[str, Any]:
    """Compare two findings documents by fingerprint.

    Evidence changes on an unchanged fingerprint are reported separately: the
    same mount with a longer TTL is still one finding, but worth seeing.
    """
    old_f = {f["fingerprint"]: f for f in old.get("findings", [])}
    new_f = {f["fingerprint"]: f for f in new.get("findings", [])}

    def brief(f: dict[str, Any]) -> dict[str, Any]:
        return {k: f.get(k) for k in ("fingerprint", "rule_id", "severity", "namespace", "object", "detail")}

    common = sorted(old_f.keys() & new_f.keys())
    changed = [
        {"fingerprint": fp, "rule_id": new_f[fp]["rule_id"], "old": old_f[fp].get("evidence"), "new": new_f[fp].get("evidence")}
        for fp in common
        if old_f[fp].get("evidence") != new_f[fp].get("evidence")
    ]
    added = sorted(new_f.keys() - old_f.keys())
    resolved = sorted(old_f.keys() - new_f.keys())
    return {
        "schema_version": FINDINGS_SCHEMA_VERSION,
        "tool": {"name": TOOL_NAME},
        "old_run": old.get("run", {}),
        "new_run": new.get("run", {}),
        "coverage": {
            "old_complete": old.get("coverage", {}).get("complete"),
            "new_complete": new.get("coverage", {}).get("complete"),
        },
        "summary": {"new": len(added), "resolved": len(resolved), "unchanged": len(common), "evidence_changed": len(changed)},
        "new": [brief(new_f[fp]) for fp in added],
        "resolved": [brief(old_f[fp]) for fp in resolved],
        "unchanged": common,
        "evidence_changed": changed,
    }


def exit_code_for(document: dict[str, Any], fail_on: str | None, fail_on_gaps: bool) -> int:
    """3 when a finding is at or above ``fail_on``; else 2 on incomplete coverage.

    Findings win over gaps because they are the stronger signal: a CI gate that
    sees 3 knows something actionable was found, not merely that it was blind.
    """
    if fail_on:
        threshold = SEVERITY_ORDER.index(fail_on.capitalize())
        if any(SEVERITY_ORDER.index(f["severity"].capitalize()) <= threshold for f in document.get("findings", [])):
            return EXIT_FINDINGS
    if fail_on_gaps and not document.get("coverage", {}).get("complete", True):
        return EXIT_GAPS
    return EXIT_OK
