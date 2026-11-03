"""VT-* rules must match the canonical catalogue exported by vault-ops-skill (references/rules.json).

The catalogue comes from VAULT_OPS_RULES_JSON (a URL or a file path), or else
from the skill's main branch on GitHub; see tests/vault_ops_catalogue.py for
when the test skips and when it fails.
"""

import pytest

from src.common.findings import RULES
from tests.vault_ops_catalogue import RULES_URL, load_json, source

SOURCE = source("VAULT_OPS_RULES_JSON", RULES_URL)


def test_rules_match_vault_ops():
    canon = load_json(SOURCE).get("rules")
    if not isinstance(canon, dict):
        pytest.fail(f"{SOURCE} is not rules.json: 'rules' is {type(canon).__name__}, expected an object")
    assert set(RULES) <= set(canon), f"rule IDs unknown to vault-ops: {sorted(set(RULES) - set(canon))}"
    for rid, r in RULES.items():
        c = canon[rid]
        assert (r.severity.lower(), r.category, r.title) == (str(c.get("severity", "")).lower(), c.get("category"), c.get("title")), rid
