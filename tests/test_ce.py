"""CE smoke tests against a throwaway Vault Community dev server.

Run with `task test:ce` (scripts/test-ce.sh), which starts compose.ce.yaml, seeds
a KV v1 mount and an `admin` policy, mints an audit token from policies/ with
both body-reader add-ons, and runs this file twice: VAULT_TOOLS_CE=1 against the
unsealed server, then VAULT_TOOLS_CE=sealed after sealing it. Skipped otherwise,
so `task test` and CI never need a server.

The CLI runs as a subprocess, exactly as a user runs it, with every output file
written to the test's tmp_path.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from datetime import date, timedelta
from pathlib import Path

import jsonschema
import pytest

MODE = os.environ.get("VAULT_TOOLS_CE")
REPO_ROOT = Path(__file__).resolve().parents[1]

pytestmark = [pytest.mark.ce, pytest.mark.skipif(MODE not in ("1", "sealed"), reason="run with task test:ce")]
unsealed = pytest.mark.skipif(MODE != "1", reason="unsealed pass only")
sealed = pytest.mark.skipif(MODE != "sealed", reason="sealed pass only")

END = date.today()
START = END - timedelta(days=90)
DATES = ["-s", START.isoformat(), "-e", END.isoformat()]


@pytest.fixture(scope="module")
def schema() -> dict:
    return json.loads((REPO_ROOT / "schemas" / "findings.schema.json").read_text())


def run(tmp_path: Path, *args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(REPO_ROOT / "main.py"), *args, "--output-dir", str(tmp_path)],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        timeout=300,
    )


def findings(tmp_path: Path, kind: str) -> dict:
    (path,) = tmp_path.glob(f"*-{kind}-findings-*.json")
    return json.loads(path.read_text())


def one(tmp_path: Path, pattern: str) -> Path:
    (path,) = tmp_path.glob(pattern)
    return path


@unsealed
def test_namespace_audit(tmp_path, schema):
    result = run(tmp_path, "namespace-audit", "--fail-on-gaps")
    assert result.returncode == 0, result.stderr
    doc = findings(tmp_path, "namespace")
    jsonschema.validate(doc, schema)
    assert doc["coverage"] == {"namespaces_processed": 1, "complete": True, "denied": [], "errors": []}
    context = doc["cluster_context"]
    assert context["enterprise"] is False
    assert context["sentinel"] == "unsupported"
    assert context["policy_bodies"] == {"acl": "assessed", "sentinel": "none found"}
    rules = set(doc["summary"]["by_rule"])
    assert {"VT-AUD-001", "VT-MOUNT-006", "VT-POL-001"} <= rules
    assert not any(rule.startswith("VT-SNT-") for rule in rules)
    assert ("VT-POL-001", "admin") in {(f["rule_id"], f["object"]["path"]) for f in doc["findings"]}
    one(tmp_path, "*-audit-report-*.md")
    one(tmp_path, "*-acl-policy-review-*.json")


@unsealed
def test_names_only_skips_bodies(tmp_path):
    result = run(tmp_path, "namespace-audit", "--names-only")
    assert result.returncode == 0, result.stderr
    doc = findings(tmp_path, "namespace")
    assert doc["cluster_context"]["policy_bodies"]["acl"] == "names only"
    assert not any(f["rule_id"].startswith("VT-POL-") for f in doc["findings"])
    assert not list(tmp_path.glob("*-acl-policy-review-*.json"))


@unsealed
def test_cluster_audit(tmp_path, schema):
    result = run(tmp_path, "cluster-audit", "--fail-on-gaps")
    assert result.returncode == 0, result.stderr
    jsonschema.validate(findings(tmp_path, "cluster"), schema)
    health = json.loads(one(tmp_path, "*-cluster-health-*.json").read_text())
    assert health["enterprise"] is False and health["sealed"] is False
    assert (health["raft"], health["snapshots"]) == (None, None)
    assert health["replication"]["mode"] == "disabled"
    assert health["audit_devices"] == []


@unsealed
@pytest.mark.parametrize("args", [["identity-audit"], ["identity-audit", "--list"]])
def test_identity_audit(tmp_path, schema, args):
    result = run(tmp_path, *args, "--fail-on-gaps")
    assert result.returncode == 0, result.stderr
    doc = findings(tmp_path, "identity")
    jsonschema.validate(doc, schema)
    assert doc["coverage"]["complete"] is True, doc["coverage"]
    assert bool(list(tmp_path.glob("*-identity-entities-*.json"))) == ("--list" in args)


@unsealed
def test_activity_export_reports_disabled_log(tmp_path, schema):
    # A Community dev server keeps the activity log off, so zero counts must come with VT-CLI-005.
    result = run(tmp_path, "activity-export", *DATES, "--fail-on-gaps")
    assert result.returncode == 0, result.stderr
    doc = findings(tmp_path, "activity")
    jsonschema.validate(doc, schema)
    assert doc["coverage"]["complete"] is True, doc["coverage"]
    assert [f["rule_id"] for f in doc["findings"]] == ["VT-CLI-005"]


@unsealed
def test_entity_export(tmp_path):
    result = run(tmp_path, "entity-export", *DATES)
    assert result.returncode == 0, result.stderr


@unsealed
def test_full_audit(tmp_path, schema):
    result = run(tmp_path, "full-audit", "--fail-on-gaps")
    assert result.returncode == 0, result.stderr
    doc = findings(tmp_path, "full")
    jsonschema.validate(doc, schema)
    assert doc["coverage"]["complete"] is True, doc["coverage"]
    assert {"VT-AUD-001", "VT-CLI-005", "VT-MOUNT-006", "VT-POL-001"} <= set(doc["summary"]["by_rule"])
    report = one(tmp_path, "*-full-audit-*.md").read_text()
    for step in ("cluster-audit", "namespace-audit", "identity-audit", "activity-export", "entity-export"):
        assert step in report
    for kind in ("cluster", "namespace", "identity", "activity"):
        findings(tmp_path, kind)


@unsealed
def test_fail_on_exits_3(tmp_path):
    assert run(tmp_path, "namespace-audit", "--fail-on", "medium").returncode == 3


@sealed
def test_sealed_cluster_audit(tmp_path, schema):
    result = run(tmp_path, "cluster-audit", "--fail-on-gaps")
    assert result.returncode == 0, result.stderr
    doc = findings(tmp_path, "cluster")
    jsonschema.validate(doc, schema)
    assert doc["coverage"]["complete"] is True
    assert [f["rule_id"] for f in doc["findings"]] == ["VT-HLTH-001"]
    health = json.loads(one(tmp_path, "*-cluster-health-*.json").read_text())
    assert health["sealed"] is True and health["seal"]["type"] == "shamir"


@sealed
@pytest.mark.parametrize(
    "args",
    [["namespace-audit"], ["identity-audit"], ["activity-export", *DATES], ["entity-export", *DATES]],
)
def test_sealed_refuses_authenticated_subcommands(tmp_path, args):
    result = run(tmp_path, *args)
    assert result.returncode == 1
    assert "sealed" in result.stderr + result.stdout


@sealed
def test_sealed_full_audit_runs_cluster_audit_only(tmp_path):
    result = run(tmp_path, "full-audit")
    assert result.returncode == 0, result.stderr
    assert [f["rule_id"] for f in findings(tmp_path, "full")["findings"]] == ["VT-HLTH-001"]
    assert not list(tmp_path.glob("*-namespace-findings-*.json"))
    report = one(tmp_path, "*-full-audit-*.md").read_text()
    assert report.count("skipped") >= 4
