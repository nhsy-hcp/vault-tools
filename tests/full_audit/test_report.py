"""The full-audit report: sections, executive summary, ranking and drafted commands."""

import dataclasses
from datetime import UTC, datetime, timedelta

import pytest

from src.cluster_audit.collector import collect_cluster_health
from src.common.findings import finding, merge_documents
from src.common.remediation import CATALOGUE, fill_commands
from src.full_audit.report import FullAuditContext, StepSummary, build_full_report, executive_summary, group_findings
from src.namespace_audit.main import AuditData
from tests.cluster_audit.fakes import HEALTHY, enterprise_routes, fake_vault_client
from tests.namespace_audit.report_fixtures import mount

NOW = datetime(2026, 10, 8, 12, 0, tzinfo=UTC)


def _doc(findings, complete=True, denied=(), sentinel="supported"):
    items = [f.to_dict() for f in findings]
    return {
        "findings": items,
        "summary": {"total": len(items)},
        "coverage": {"namespaces_processed": 3, "complete": complete, "denied": list(denied), "errors": []},
        "cluster_context": {"sentinel": sentinel},
    }


def _merged(findings, **kw):
    return merge_documents([_doc(findings, **kw)], run={}, cluster_context={"sentinel": kw.get("sentinel", "supported")}, tool_version="t")


def _data():
    data = AuditData()
    data.auth_methods = {"": {"token/": mount("token")}, "tn001": {"ns_token/": mount("ns_token"), "jwt/": mount("jwt")}, "tn001/dev": {"ns_token/": mount("ns_token"), "jwt/": mount("jwt")}}
    data.secret_engines = {"": {"cubbyhole/": mount("cubbyhole")}, "tn001": {"kv/": mount("kv")}, "tn001/dev": {"kv/": mount("kv")}}
    data.acl_policies = {"": [], "tn001": ["admin", "reader"], "tn001/dev": ["admin"]}
    return data


def _ctx(findings, license_status=None, health=None, **kw):
    if health is None:
        health, _ = collect_cluster_health(fake_vault_client(enterprise_routes()))
    return FullAuditContext(
        cluster_name="vault-cluster",
        cluster_id="d33099d9-206e-53c2-4e50-44fb62ac69a6",
        vault_addr="https://vault:8200",
        started_at=NOW,
        finished_at=NOW + timedelta(seconds=3),
        workers=4,
        window=("2025-11-01", "2026-10-08"),
        merged=kw.pop("merged", None) or _merged(findings),
        steps=kw.pop("steps", None) or [StepSummary("cluster-audit", "ok", "", 1, 0.4), StepSummary("namespace-audit", "ok", "", len(findings), 1.2)],
        health=health,
        license_status=license_status,
        audit_data=kw.pop("audit_data", _data()),
        output_files=["vault-cluster-d33099d9-full-findings-20261008.json"],
        **kw,
    )


LIC_SAME_DAY = {"expiration_time": "2026-10-31T00:00:00Z", "termination_time": "2026-10-31T00:00:00Z", "features": ["Namespaces", "DR Replication"]}
ADMIN = [finding("VT-POL-001", ns, "acl_policy", "admin", None, "Grants write or sudo on every path (`*`).", paths=["*"]) for ns in [f"tn{i:03d}" for i in range(12)]]
KV1 = finding("VT-MOUNT-006", "tn009/soc2/dev", "secrets_mount", "kv-v1/", "kv", "KV version 1.", kv_version=1)
AUD3 = finding("VT-AUD-003", "", "audit_device", "stdout/", "file", "Audit device `stdout/`: hmac_accessor=false.", log_raw=False, hmac_accessor=False)
LIC = finding("VT-LIC-001", "", "cluster", None, "license", "License expires on 2026-10-31 (23 days remaining).", days_remaining=23)


class TestSections:
    def test_has_every_section_of_the_skill_report(self):
        report = build_full_report(_ctx([LIC, AUD3, KV1], license_status=LIC_SAME_DAY))
        for heading in (
            "# Vault audit report: `vault-cluster`",
            "## Executive summary",
            "## Summary metrics",
            "## Cluster health and licence",
            "## Inventory",
            "## Findings, ranked",
            "## Summary",
            "## Steps",
            "## Not covered",
            "## Source files",
        ):
            assert heading in report, heading
        assert report.rstrip().endswith("Drafted commands are for an operator to run after review.")
        assert "**Licence features:** DR Replication, Namespaces" in report
        assert "| Cluster ID | `d33099d9-206e-53c2-4e50-44fb62ac69a6` |" in report
        assert "(ID " not in report

    def test_unknown_cluster_id_has_its_own_row(self):
        report = build_full_report(dataclasses.replace(_ctx([]), cluster_id=None))
        assert "| Cluster ID | unknown (a sealed node reports none) |" in report

    def test_inventory_collapses_namespaces_into_shapes(self):
        report = build_full_report(_ctx([]))
        assert "| 1 | jwt, ns_token | kv | 1 | `tn001/` |" in report
        assert "**ACL policies:** 3 in total" in report and "`tn001/` (2)" in report

    def test_findings_are_ranked_and_carry_filled_commands(self):
        report = build_full_report(_ctx([KV1, AUD3, LIC], license_status=LIC_SAME_DAY))
        order = [report.index(f"({rule}, ") for rule in ("VT-LIC-001", "VT-AUD-003", "VT-MOUNT-006")]
        assert order == sorted(order)
        assert "vault kv enable-versioning -namespace=tn009/soc2/dev/ kv-v1/" in report
        assert "vault audit disable stdout/" in report
        assert "**Watch out:**" in report

    def test_copied_findings_render_as_one_item(self):
        report = build_full_report(_ctx(ADMIN))
        assert "### 1. " in report and "### 2. " not in report
        assert "The same finding in 12 namespaces" in report
        assert "(VT-POL-001, medium, ×12)" in report

    def test_not_covered_names_what_was_skipped(self):
        steps = [StepSummary("cluster-audit", "ok"), StepSummary("identity-audit", "failed", "RuntimeError: boom")]
        report = build_full_report(_ctx([], steps=steps, merged=_merged([], sentinel="unsupported"), policy_bodies={"acl": "not readable", "sentinel": "none found"}))
        assert "**identity-audit** failed: RuntimeError: boom" in report
        assert "Attach `policies/audit-policy-acl-reader.hcl` to the token" in report
        assert "ACL not readable with this token" in report
        assert "Sentinel:** not available" in report
        assert "no earlier full-audit findings file" in report

    def test_changes_since_last_run(self):
        diff = {"summary": {"new": 1, "resolved": 2, "unchanged": 5, "evidence_changed": 0}, "new": [KV1.to_dict()], "resolved": []}
        report = build_full_report(_ctx([KV1], previous_diff=diff, previous_path="vault-cluster-d33099d9-full-findings-20261001.json"))
        assert "## Changes since the last run" in report and "**1 new**, **2 resolved**" in report
        assert "no earlier full-audit findings file" not in report


class TestExecutiveSummary:
    def _summary(self, ctx):
        from src.common.findings import finding_from_dict

        objs = [finding_from_dict(f) for f in ctx.merged["findings"]]
        return executive_summary(ctx, group_findings(objs), objs)

    def test_licence_with_no_grace_period(self):
        text = self._summary(_ctx([LIC], license_status=LIC_SAME_DAY))
        # 12:00 on 8 October to midnight on 31 October is 22.5 days.
        assert "expires and terminates on the same day, **2026-10-31 (22 days)**, so there is no grace period" in text

    def test_single_voter_raft(self):
        text = self._summary(_ctx([]))
        assert "Raft has 1 voter (failure tolerance 0)" in text

    def test_sealed_node(self):
        health, _ = collect_cluster_health(fake_vault_client({"sys/health": {**HEALTHY, "sealed": True}, "sys/seal-status": {"type": "shamir", "t": 1, "n": 1}}))
        text = self._summary(_ctx([], health=health, audit_data=None))
        assert "The node is **sealed**" in text

    def test_partial_coverage_comes_first(self):
        ctx = _ctx([], merged=_merged([], complete=False, denied=[{"namespace": "/", "scope": "sys/audit"}]))
        assert self._summary(ctx).startswith("**Coverage is incomplete**")

    def test_copied_policy_is_called_out(self):
        assert "`admin` accounts for 12 findings (VT-POL-001)" in self._summary(_ctx(ADMIN))


class TestRemediation:
    def test_every_catalogued_rule_is_a_known_rule(self):
        from src.common.findings import RULES

        assert set(CATALOGUE) <= set(RULES)
        assert set(RULES) <= set(CATALOGUE), sorted(set(RULES) - set(CATALOGUE))

    @pytest.mark.parametrize(
        "f,expected",
        [
            (finding("VT-AUTH-001", "", "auth_mount", "public/", "oidc", "d"), "vault auth tune -listing-visibility=hidden public/"),
            (finding("VT-AUTH-001", "a/b", "auth_mount", "public/", "oidc", "d"), "vault auth tune -namespace=a/b/ -listing-visibility=hidden public/"),
            (finding("VT-MOUNT-002", "a", "secrets_mount", "kv/", "kv", "d", baseline_seconds=86400), "vault secrets tune -namespace=a/ -max-lease-ttl=24h kv/"),
            (finding("VT-NS-002", "tn010/prototypes/empty-leaf", "namespace", None, None, "d"), "vault namespace delete -namespace=tn010/prototypes/ empty-leaf"),
            (finding("VT-SNT-001", "tn009", "egp_policy", "adv", "egp", "d"), "vault write -namespace=tn009/ sys/policies/egp/adv enforcement_level=soft-mandatory policy=@<file> paths=<paths>"),
            (finding("VT-ID-001", "a", "entity", "e-123", None, "d", entity_id="e-123"), "vault delete -namespace=a/ identity/entity/id/e-123"),
        ],
    )
    def test_commands_are_filled_from_the_finding(self, f, expected):
        assert expected in fill_commands(f)

    def test_unknown_placeholders_stay_visible(self):
        f = finding("VT-REPL-002", "", "cluster", "dr:sec-1", "dr", "d")
        assert "vault write sys/replication/dr/primary/revoke-secondary id=sec-1" in fill_commands(f)


def test_cluster_wide_items_rank_above_copied_access_findings():
    """The skill lists licence and audit-trail items before policy findings, however many copies."""
    groups = group_findings([*ADMIN, AUD3, LIC])
    assert [g.rule_id for g in groups] == ["VT-LIC-001", "VT-POL-001", "VT-AUD-003"]
    high = finding("VT-REPL-004", "", "cluster", "dr", "dr", "corrupted")
    assert group_findings([LIC, high])[0].rule_id == "VT-REPL-004"


def test_single_cluster_finding_does_not_repeat_its_meaning():
    report = build_full_report(_ctx([LIC], license_status=LIC_SAME_DAY))
    item = report.split("### 1. ")[1].split("###")[0]
    assert CATALOGUE["VT-LIC-001"].meaning not in item
    assert "License expires on 2026-10-31" in item


def test_sentinel_listed_but_not_assessed_is_called_out():
    report = build_full_report(_ctx([], policy_bodies={"acl": "assessed", "sentinel": "not readable"}))
    assert "**Sentinel policies:** listed, but the token cannot read Sentinel bodies (attach `policies/audit-policy-sentinel-reader.hcl`)" in report
    assert "ACL assessed; Sentinel not readable with this token" in report
