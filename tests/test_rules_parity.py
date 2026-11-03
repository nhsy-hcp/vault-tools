"""VT-* rules must match the canonical catalogue exported by vault-ops-skill (references/rules.json).

The catalogue is read from VAULT_OPS_RULES_JSON (a URL or a file path), or else
from the skill's main branch on GitHub. The test skips when that source cannot
be reached or GitHub is having trouble (HTTP 429 or 5xx), so an offline run
stays green. It fails on any other HTTP error (a 404 means the catalogue has
moved) and on a response that is not rules.json.
"""

import http.client
import json
import os
import urllib.error
import urllib.request
from pathlib import Path

import pytest

from src.common.findings import RULES

DEFAULT_URL = "https://raw.githubusercontent.com/nhsy-hcp/vault-ops-skill/main/skills/vault-ops/references/rules.json"
# `or`, not a get() default: an empty variable falls back to the URL instead of Path("") (the cwd).
SOURCE = os.environ.get("VAULT_OPS_RULES_JSON") or DEFAULT_URL


def _fetch(url: str) -> bytes:
    try:
        with urllib.request.urlopen(url, timeout=10) as resp:
            return resp.read()
    except urllib.error.HTTPError as e:  # before URLError, its base class
        if e.code == 429 or e.code >= 500:
            pytest.skip(f"{url} returned HTTP {e.code}, likely transient; set VAULT_OPS_RULES_JSON to a local copy")
        raise
    except (urllib.error.URLError, http.client.HTTPException, TimeoutError, OSError) as e:
        pytest.skip(f"{url} unreachable ({e!r}); set VAULT_OPS_RULES_JSON to a local copy")


def _load_canon() -> dict:
    if SOURCE.startswith(("https://", "http://")):
        raw = _fetch(SOURCE)
    else:
        path = Path(SOURCE)
        if not path.is_file():
            pytest.skip(f"{path} not found (set VAULT_OPS_RULES_JSON)")
        raw = path.read_bytes()
    try:
        rules = json.loads(raw)["rules"]
    except (ValueError, KeyError, TypeError) as e:  # ValueError covers JSONDecodeError and bad UTF-8
        pytest.fail(f"{SOURCE} is not rules.json ({type(e).__name__}: {e})")
    if not isinstance(rules, dict):
        pytest.fail(f"{SOURCE}: 'rules' is a {type(rules).__name__}, expected an object")
    return rules


def test_rules_match_vault_ops():
    canon = _load_canon()
    assert set(RULES) <= set(canon), f"rule IDs unknown to vault-ops: {sorted(set(RULES) - set(canon))}"
    for rid, r in RULES.items():
        c = canon[rid]
        assert (r.severity.lower(), r.category, r.title) == (str(c.get("severity", "")).lower(), c.get("category"), c.get("title")), rid
