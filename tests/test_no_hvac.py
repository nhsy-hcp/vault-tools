"""Guard: hvac was replaced by src/common/vault_http.py and must not come back.

hvac replaced its own `verify` with the session's (silently ignoring
VAULT_SKIP_VERIFY), mixed dict and Response return types, and carried write
helpers the read-only tool never needs. vault_http's NamespacedClient has no
write methods; tests/common/test_vault_http.py pins that.
"""

import re
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
IMPORT = re.compile(r"^\s*(import\s+hvac\b|from\s+hvac\b)", re.MULTILINE)


def _python_files():
    yield ROOT / "main.py"
    for folder in ("src", "scripts"):
        yield from (ROOT / folder).rglob("*.py")


def test_hvac_is_not_imported():
    offenders = [str(path.relative_to(ROOT)) for path in _python_files() if IMPORT.search(path.read_text())]
    assert offenders == []


def test_hvac_is_not_a_dependency():
    project = tomllib.loads((ROOT / "pyproject.toml").read_text())["project"]
    declared = project["dependencies"] + [dep for extra in project.get("optional-dependencies", {}).values() for dep in extra]
    assert not [dep for dep in declared if re.match(r"hvac\b", dep, re.IGNORECASE)]


def test_inline_script_metadata_has_no_hvac():
    for path in (ROOT / "main.py", ROOT / "scripts" / "seed-vault.py"):
        header = path.read_text().split("# ///", 2)[1] if "# ///" in path.read_text() else ""
        assert "hvac" not in header, path.name
