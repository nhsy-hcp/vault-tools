"""Load vault-ops-skill's published catalogue files for the parity tests.

Each file is read from an environment variable (a URL or a file path), or else
from the skill's main branch on GitHub. A source that cannot be reached, is
missing, or answers HTTP 429/5xx skips the calling test, so an offline run
stays green. Any other HTTP error (a 404 means the file moved) or a response
that is not a JSON object fails it.
"""

import http.client
import json
import os
import urllib.error
import urllib.request
from pathlib import Path

import pytest

BASE_URL = "https://raw.githubusercontent.com/nhsy-hcp/vault-ops-skill/main/skills/vault-ops/"
RULES_URL = BASE_URL + "references/rules.json"
SCHEMA_URL = BASE_URL + "schemas/findings.schema.json"


def source(env_var: str, default_url: str) -> str:
    """The env var's value, or the URL. `or`, not a get() default: an empty variable falls back instead of becoming Path("")."""
    return os.environ.get(env_var) or default_url


def _fetch(url: str) -> bytes:
    try:
        with urllib.request.urlopen(url, timeout=10) as resp:
            return resp.read()
    except urllib.error.HTTPError as e:  # before URLError, its base class
        if e.code == 429 or e.code >= 500:
            pytest.skip(f"{url} returned HTTP {e.code}, likely transient; point the env var at a local copy")
        raise
    except (urllib.error.URLError, http.client.HTTPException, TimeoutError, OSError) as e:
        pytest.skip(f"{url} unreachable ({e!r}); point the env var at a local copy")


def load_json(src: str) -> dict:
    """Read and parse `src` (a URL or a file path); skip or fail as described in the module docstring."""
    if src.startswith(("https://", "http://")):
        raw = _fetch(src)
    else:
        path = Path(src)
        if not path.is_file():
            pytest.skip(f"{path} not found")
        raw = path.read_bytes()
    try:
        doc = json.loads(raw)
    except ValueError as e:  # JSONDecodeError and bad UTF-8
        pytest.fail(f"{src} is not JSON ({type(e).__name__}: {e})")
    if not isinstance(doc, dict):
        pytest.fail(f"{src} is a JSON {type(doc).__name__}, expected an object")
    return doc
