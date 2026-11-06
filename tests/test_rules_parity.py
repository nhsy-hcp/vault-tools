"""VT-* rules and their remediation must match the canonical catalogue exported by vault-ops-skill (references/rules.json).

The catalogue comes from VAULT_OPS_RULES_JSON (a URL or a file path), or else
from the skill's main branch on GitHub; see tests/vault_ops_catalogue.py for
when the test skips and when it fails.
"""

import pytest

from src.common.findings import RULES
from src.common.remediation import CATALOGUE, RANK_ORDER
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


def test_remediation_matches_vault_ops():
    """meaning, commands, action and watch_out are the skill's, verbatim."""
    canon = load_json(SOURCE).get("rules")
    if not isinstance(canon, dict):
        pytest.fail(f"{SOURCE} is not rules.json: 'rules' is {type(canon).__name__}, expected an object")
    for rid, r in CATALOGUE.items():
        if rid not in canon:
            continue
        c = canon[rid]
        local = (r.meaning, list(r.commands), r.action, r.watch_out)
        skill = (c.get("meaning", ""), list(c.get("commands") or []), c.get("action") or "", c.get("watch_out") or "")
        assert local == skill, rid


def test_rank_order_matches_vault_ops():
    canon = load_json(SOURCE).get("rank_order")
    if not isinstance(canon, list):
        pytest.fail(f"{SOURCE} has no rank_order list")
    assert list(RANK_ORDER) == canon
