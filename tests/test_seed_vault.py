"""scripts/seed-vault.py: its in-file VaultAPI and the skip checks that read its errors.

The seeder is a standalone PEP 723 script (it cannot import src), so it is
loaded by path. No request reaches a network: the class-level session is
patched per test.
"""

import importlib.util
import json
from pathlib import Path
from unittest.mock import patch

import pytest
import requests

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "seed-vault.py"


@pytest.fixture(scope="module")
def seed():
    spec = importlib.util.spec_from_file_location("seed_vault", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def response(status: int, body=None, *, raw: bytes | None = None) -> requests.Response:
    r = requests.Response()
    r.status_code = status
    r._content = raw if raw is not None else (json.dumps(body).encode() if body is not None else b"")
    return r


def answering(seed, *responses):
    return patch.object(seed.VaultAPI._session, "request", side_effect=list(responses))


class TestErrorParsing:
    @pytest.mark.parametrize("body", [["a", "b"], "just a string", 42])
    def test_non_object_json_error_is_a_vault_error(self, seed, body):
        """Not an AttributeError: that escaped every step's VAULT_ERRORS handler."""
        with answering(seed, response(502, body)), pytest.raises(seed.VaultError) as excinfo:
            seed.VaultAPI().request("GET", "sys/mounts")
        assert excinfo.value.status == 502

    def test_vault_errors_are_kept(self, seed):
        with answering(seed, response(400, {"errors": ["path is already in use at kv/"]})), pytest.raises(seed.VaultError) as excinfo:
            seed.VaultAPI().write("sys/mounts/kv", {"type": "kv"})
        assert excinfo.value.errors == ["path is already in use at kv/"]

    def test_404_is_invalid_path(self, seed):
        with answering(seed, response(404, {"errors": []})), pytest.raises(seed.InvalidPathError):
            seed.VaultAPI().list("pki/issuers")

    def test_error_text_excludes_the_request_path(self, seed):
        exc = seed.VaultError(500, ["internal error"], "POST", "sys/namespaces/existing-404-unsupported")
        assert seed.VaultAPI.error_text(exc) == "internal error"


class TestAuthentication:
    @pytest.mark.parametrize("status", [400, 401, 403])
    def test_rejected_token_is_not_authenticated(self, seed, status):
        with answering(seed, response(status, {"errors": ["permission denied"]})):
            assert seed.VaultAPI().is_authenticated() is False

    def test_sealed_node_exits_cleanly(self, seed, capsys):
        """A 503 on lookup-self used to escape get_client() as a traceback."""
        with answering(seed, response(503, {"errors": ["Vault is sealed"]})), pytest.raises(SystemExit) as excinfo:
            seed.get_client()
        assert excinfo.value.code == 1
        assert "sealed" in capsys.readouterr().err

    def test_bad_token_exits_cleanly(self, seed, capsys):
        with answering(seed, response(403, {"errors": ["permission denied"]})), pytest.raises(SystemExit):
            seed.get_client()
        assert "not authenticated" in capsys.readouterr().err


class TestSkipChecks:
    def test_unrelated_failure_on_a_path_naming_existing_is_not_a_skip(self, seed):
        """The request path is in str(exc); the skip check must not read it."""
        with answering(seed, response(500, {"errors": ["internal error"]})), pytest.raises(RuntimeError, match="cannot create namespace"):
            seed.create_namespace(seed.VaultAPI(), "existing-404-unsupported")

    def test_existing_namespace_is_skipped(self, seed):
        with answering(seed, response(400, {"errors": ['namespace "tn001/" already exists']})):
            assert seed.create_namespace(seed.VaultAPI(), "tn001") is True

    def test_namespaces_unsupported_on_404(self, seed):
        with answering(seed, response(404, {"errors": ["1 error occurred:\n\t* unsupported path\n\n"]})):
            assert seed.create_namespace(seed.VaultAPI(), "tn001") is False

    def test_mount_in_use_is_skipped(self, seed):
        with answering(seed, response(400, {"errors": ["path is already in use at kv/"]})):
            seed.enable_secrets_engine(seed.VaultAPI(), "kv", "kv", {}, "")

    def test_mount_failure_on_a_path_naming_existing_mount_raises(self, seed):
        with answering(seed, response(500, {"errors": ["internal error"]})), pytest.raises(seed.VaultError):
            seed.enable_secrets_engine(seed.VaultAPI(), "existing mount", "kv", {}, "")
