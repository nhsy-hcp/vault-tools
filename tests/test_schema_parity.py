"""The vendored findings schema and FINDINGS_SCHEMA_VERSION must match vault-ops-skill's.

The skill's schema comes from VAULT_OPS_SCHEMA_JSON and its version from
rules.json's `schema_version` (VAULT_OPS_RULES_JSON), each a URL or a file
path, or else the skill's main branch on GitHub; see
tests/vault_ops_catalogue.py for when the tests skip and when they fail. On a
failure, re-vendor the schema and bump FINDINGS_SCHEMA_VERSION together.
"""

import json
from pathlib import Path

from src.common.findings import FINDINGS_SCHEMA_VERSION
from tests.vault_ops_catalogue import RULES_URL, SCHEMA_URL, load_json, source

VENDORED = Path(__file__).resolve().parents[1] / "schemas" / "findings.schema.json"


def _differences(ours, theirs, path: str = "") -> list[str]:
    """JSON-pointer-style paths where the two documents differ, so a failure names what drifted."""
    if isinstance(ours, dict) and isinstance(theirs, dict):
        out = []
        for key in sorted(set(ours) | set(theirs)):
            where = f"{path}/{key}"
            if key not in ours:
                out.append(f"{where} (only in vault-ops)")
            elif key not in theirs:
                out.append(f"{where} (only in vault-tools)")
            else:
                out.extend(_differences(ours[key], theirs[key], where))
        return out
    return [] if ours == theirs else [path or "/"]


def test_vendored_schema_matches_vault_ops():
    canon = load_json(source("VAULT_OPS_SCHEMA_JSON", SCHEMA_URL))
    diffs = _differences(json.loads(VENDORED.read_text()), canon)
    assert not diffs, f"schemas/findings.schema.json differs from vault-ops at: {diffs}"


def test_schema_version_matches_vault_ops():
    canon = load_json(source("VAULT_OPS_RULES_JSON", RULES_URL)).get("schema_version")
    assert canon == FINDINGS_SCHEMA_VERSION, f"FINDINGS_SCHEMA_VERSION {FINDINGS_SCHEMA_VERSION} != vault-ops {canon}"
