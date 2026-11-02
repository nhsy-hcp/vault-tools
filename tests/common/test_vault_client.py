"""Tests for src/common/vault_client.py."""

import json
from unittest.mock import patch

import pytest
import requests

from src.common import vault_http
from src.common.exceptions import (
    VaultAPIError,
    VaultConnectionError,
    VaultDataError,
    VaultPermissionError,
)
from src.common.vault_client import ConnectionInfo, VaultClient
from src.common.vault_http import NamespacedClient
from tests.fake_secrets import fake_token

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def client():
    """Return a VaultClient with no real network calls."""
    return VaultClient(vault_addr="https://vault.example.com", vault_token="s.testtoken1234")


# ---------------------------------------------------------------------------
# Initialisation
# ---------------------------------------------------------------------------


class TestVaultClientInit:
    @pytest.fixture
    def no_vault_env(self, monkeypatch):
        """Clear the ambient Vault env vars.

        VaultClient falls back to VAULT_ADDR/VAULT_TOKEN when an argument is
        empty, so these tests only exercise the missing-value path if the
        environment is genuinely unset. The Taskfile loads .env, which is why
        they passed under bare pytest but failed under `task test:ci`.
        """
        monkeypatch.delenv("VAULT_ADDR", raising=False)
        monkeypatch.delenv("VAULT_TOKEN", raising=False)

    def test_missing_addr_raises(self, no_vault_env):
        with pytest.raises(ValueError, match="VAULT_ADDR"):
            VaultClient(vault_addr="", vault_token="s.test")

    def test_missing_token_raises(self, no_vault_env):
        with pytest.raises(ValueError, match="VAULT_TOKEN"):
            VaultClient(vault_addr="https://vault.example.com", vault_token="")

    def test_env_fallback(self, monkeypatch):
        monkeypatch.setenv("VAULT_ADDR", "https://vault.env.com")
        monkeypatch.setenv("VAULT_TOKEN", "s.envtoken")
        c = VaultClient()
        assert c.vault_addr == "https://vault.env.com"
        assert c.vault_token == "s.envtoken"

    def test_skip_verify_disables_warnings(self):
        with patch("urllib3.disable_warnings") as mock_dw:
            VaultClient(
                vault_addr="https://vault.example.com",
                vault_token="s.test",
                vault_skip_verify=True,
            )
            mock_dw.assert_called_once()


def make_response(status: int = 200, body=None, *, raw: bytes | None = None) -> requests.Response:
    """A real requests.Response, as session.request would return it."""
    response = requests.Response()
    response.status_code = status
    if raw is not None:
        response._content = raw
    elif body is None:
        response._content = b""
    else:
        response._content = json.dumps(body).encode()
        response.headers["Content-Type"] = "application/json"
    return response


def route(responses: dict):
    """A session.request side effect answering by URL path suffix."""

    def _request(method, url, **kwargs):
        for suffix, response in responses.items():
            if url.endswith(suffix):
                if isinstance(response, BaseException):
                    raise response
                return response
        return make_response(404, {"errors": []})

    return _request


class TestTlsVerification:
    """VAULT_SKIP_VERIFY and VAULT_CACERT must reach every request.

    Verification is set on the pooled session, which NamespacedClient sends
    through without a `verify` of its own. Under hvac, a value passed only to
    hvac.Client was silently replaced by the session's, and skip-verify never
    took effect; these tests pin that the session carries it.
    """

    @pytest.mark.parametrize(
        "skip,cacert,expected",
        [
            (False, None, True),
            (True, None, False),
            (False, "/tmp/ca.pem", "/tmp/ca.pem"),
            (True, "/tmp/ca.pem", False),
        ],
    )
    def test_verify_is_on_the_session(self, skip, cacert, expected):
        c = VaultClient(vault_addr="https://vault.example.com", vault_token="s.test", vault_skip_verify=skip, vault_cacert=cacert)
        assert c.verify == expected
        assert c.session.verify == expected
        with c.get_client() as nc:
            assert nc.session is c.session

    @pytest.mark.parametrize("skip,cacert,expected", [(True, None, False), (False, "/tmp/ca.pem", "/tmp/ca.pem")])
    def test_request_is_sent_with_verify(self, skip, cacert, expected):
        """Through the real Session.request, so merge_environment_settings applies the session's verify."""
        c = VaultClient(vault_addr="https://vault.example.com", vault_token="s.test", vault_skip_verify=skip, vault_cacert=cacert)
        with patch.object(c.session, "send", return_value=make_response(200, {})) as send:
            c.get("sys/health")
        assert send.call_args.kwargs["verify"] == expected


# ---------------------------------------------------------------------------
# get_client context manager
# ---------------------------------------------------------------------------


class TestGetClient:
    def test_yields_namespaced_client(self, client):
        with client.get_client("") as c:
            assert isinstance(c, NamespacedClient)
            assert c.session is client.session
            assert c.addr == "https://vault.example.com"
            assert c.token == "s.testtoken1234"
            assert c.namespace == ""

    def test_namespace_forwarded(self, client):
        with client.get_client("team-a/") as c:
            assert c.namespace == "team-a/"

    def test_root_sends_no_namespace_header(self, client):
        with patch.object(client.session, "request", return_value=make_response(200, {})) as request:
            client.get("sys/mounts")
        headers = request.call_args.kwargs["headers"]
        assert "X-Vault-Namespace" not in headers
        assert headers["X-Vault-Token"] == "s.testtoken1234"

    def test_namespace_header_sent(self, client):
        with patch.object(client.session, "request", return_value=make_response(200, {})) as request:
            client.get("sys/mounts", namespace="team-a/")
        assert request.call_args.kwargs["headers"]["X-Vault-Namespace"] == "team-a/"


# ---------------------------------------------------------------------------
# validate_connection
# ---------------------------------------------------------------------------


class TestValidateConnection:
    def _make_health(self, cluster_name="test-cluster", version="1.17.0+ent", cluster_id="d33099d9-206e-53c2-4e50-44fb62ac69a6", **overrides):
        health = {
            "cluster_name": cluster_name,
            "cluster_id": cluster_id,
            "sealed": False,
            "initialized": True,
            "version": version,
        }
        health.update(overrides)
        return health

    def _validate(self, client, health, lookup=None):
        responses = {"/v1/sys/health": make_response(200, health) if isinstance(health, dict) else health}
        responses["/v1/auth/token/lookup-self"] = lookup if lookup is not None else make_response(200, {"data": {}})
        with patch.object(client.session, "request", side_effect=route(responses)) as request:
            return client.validate_connection(), request

    def test_success(self, client):
        info, _ = self._validate(client, self._make_health())
        assert isinstance(info, ConnectionInfo)
        assert info.cluster_name == "test-cluster"
        assert info.vault_version == "1.17.0+ent"
        assert info.is_enterprise is True
        assert info.cluster_id == "d33099d9-206e-53c2-4e50-44fb62ac69a6"

    def test_reads_health_with_every_state_code_and_lookup_self(self, client):
        _, request = self._validate(client, self._make_health())
        urls = [call.kwargs["url"] for call in request.call_args_list]
        assert urls == ["https://vault.example.com/v1/sys/health", "https://vault.example.com/v1/auth/token/lookup-self"]
        assert request.call_args_list[0].kwargs["params"] == vault_http.HEALTH_PARAMS
        assert all(call.kwargs["method"] == "GET" for call in request.call_args_list)

    def test_success_ce(self, client):
        info, _ = self._validate(client, self._make_health(version="1.16.0"))
        assert info.vault_version == "1.16.0"
        assert info.is_enterprise is False

    def test_cluster_id_none_when_absent(self, client):
        health = self._make_health()
        health.pop("cluster_id")
        info, _ = self._validate(client, health)
        assert info.cluster_id is None

    def test_edition_unknown_when_version_absent(self, client):
        health = self._make_health()
        health.pop("version")
        info, _ = self._validate(client, health)
        assert info.vault_version is None
        assert info.is_enterprise is None

    def test_sealed_raises(self, client):
        with pytest.raises(VaultConnectionError, match="sealed"):
            self._validate(client, self._make_health(sealed=True))

    def test_uninitialised_reports_sealed_first(self, client):
        """An uninitialised node is also sealed; that check comes first, as it did."""
        with pytest.raises(VaultConnectionError, match="sealed"):
            self._validate(client, self._make_health(sealed=True, initialized=False))

    def test_not_authenticated_raises(self, client):
        with pytest.raises(VaultConnectionError, match="not authenticated"):
            self._validate(client, self._make_health(), lookup=make_response(403, {"errors": ["permission denied"]}))

    def test_not_initialized_raises(self, client):
        with pytest.raises(VaultConnectionError, match="not initialized"):
            self._validate(client, self._make_health(initialized=False))

    def test_invalid_health_response_raises(self, client):
        with pytest.raises(VaultConnectionError):
            self._validate(client, make_response(200, ["not-a-dict"]))

    def test_vault_error_wrapped(self, client):
        with pytest.raises(VaultConnectionError, match="Vault API error") as excinfo:
            self._validate(client, make_response(500, {"errors": ["boom"]}))
        assert isinstance(excinfo.value.__cause__, vault_http.InternalServerError)

    def test_lookup_self_other_error_wrapped(self, client):
        with pytest.raises(VaultConnectionError, match="Vault API error"):
            self._validate(client, self._make_health(), lookup=make_response(500, {"errors": ["boom"]}))

    def test_generic_exception_wrapped(self, client):
        with patch.object(client.session, "request", side_effect=OSError("network down")), pytest.raises(VaultConnectionError, match="Connection error"):
            client.validate_connection()


# ---------------------------------------------------------------------------
# get()
# ---------------------------------------------------------------------------


class TestVaultClientGet:
    def _patched(self, client, response):
        if isinstance(response, BaseException):
            return patch.object(client.session, "request", side_effect=response)
        return patch.object(client.session, "request", return_value=response)

    def test_successful_get_returns_dict(self, client):
        with self._patched(client, make_response(200, {"data": {"key": "val"}})):
            assert client.get("sys/internal/counters/activity") == {"data": {"key": "val"}}

    def test_get_strips_leading_slash_and_v1(self, client):
        with self._patched(client, make_response(200, {})) as request:
            client.get("/v1/sys/mounts")
        assert request.call_args.kwargs["url"] == "https://vault.example.com/v1/sys/mounts"

    def test_get_keeps_v1_inside_a_path(self, client):
        with self._patched(client, make_response(200, {})) as request:
            client.get("kv/v1/data")
        assert request.call_args.kwargs["url"] == "https://vault.example.com/v1/kv/v1/data"

    def test_get_is_a_get(self, client):
        with self._patched(client, make_response(200, {})) as request:
            client.get("sys/mounts")
        assert request.call_args.kwargs["method"] == "GET"

    def test_non_200_success_raises_api_error(self, client):
        with self._patched(client, make_response(202, {})), pytest.raises(VaultAPIError, match="202"):
            client.get("sys/whatever")

    def test_get_204_no_content_returns_empty(self, client):
        """204 means the query matched nothing, which is a success, not a failure."""
        with self._patched(client, make_response(204)):
            assert client.get("sys/internal/counters/activity/export") == []

    def test_ndjson_response_parsed_as_list(self, client):
        with self._patched(client, make_response(200, raw=b'{"a":1}\n{"b":2}\n')):
            result = client.get("sys/internal/counters/activity/export")
        assert result == [{"a": 1}, {"b": 2}]

    def test_bad_json_raises_api_error(self, client):
        with self._patched(client, make_response(200, raw=b"not json at all")), pytest.raises((VaultDataError, VaultAPIError)):
            client.get("sys/internal/counters")

    def test_forbidden_raises_permission_error(self, client):
        with self._patched(client, make_response(403, {"errors": ["permission denied"]})), pytest.raises(VaultPermissionError) as excinfo:
            client.get("secret/restricted")
        assert isinstance(excinfo.value.__cause__, vault_http.Forbidden)

    def test_invalid_path_raises_api_error_chained(self, client):
        """activity_export and fetch_license_status test __cause__ for InvalidPath."""
        with self._patched(client, make_response(404, {"errors": []})), pytest.raises(VaultAPIError) as excinfo:
            client.get("sys/license/status")
        assert isinstance(excinfo.value.__cause__, vault_http.InvalidPath)
        assert not isinstance(excinfo.value, VaultPermissionError)

    def test_other_vault_error_raises_api_error(self, client):
        with self._patched(client, make_response(500, {"errors": ["boom"]})), pytest.raises(VaultAPIError, match="boom") as excinfo:
            client.get("sys/mounts")
        assert isinstance(excinfo.value.__cause__, vault_http.InternalServerError)

    def test_connection_error_raises_connection_error(self, client):
        with self._patched(client, requests.exceptions.ConnectionError("down")), pytest.raises(VaultConnectionError):
            client.get("sys/health")

    def test_timeout_raises_connection_error(self, client):
        with self._patched(client, requests.exceptions.Timeout("timed out")), pytest.raises(VaultConnectionError):
            client.get("sys/health")

    def test_unexpected_error_raises_api_error(self, client):
        with self._patched(client, RuntimeError("unexpected")), pytest.raises(VaultAPIError):
            client.get("sys/health")

    def test_get_with_params(self, client):
        with self._patched(client, make_response(200, {"data": {}})) as request:
            result = client.get("sys/internal/counters/activity", params={"start_time": "2024-01-01"})
        assert isinstance(result, dict)
        assert request.call_args.kwargs["params"] == {"start_time": "2024-01-01"}


class TestReadOnly:
    def test_no_post_method(self, client):
        assert not hasattr(client, "post")


class TestErrorBodySummarisation:
    """Vault error bodies must not be interpolated verbatim into exceptions.

    Exception text reaches the audit log via `error=str(e)`, so a raw
    response.text could carry token material or wrapped secrets into a file
    that is explicitly meant to be safe to retain and ship.
    """

    def test_keeps_vault_error_strings(self):
        assert vault_http._summarise_error_body(make_response(403, {"errors": ["permission denied"]})) == "permission denied"

    def test_joins_multiple_errors(self):
        assert vault_http._summarise_error_body(make_response(400, {"errors": ["a", "b"]})) == "a; b"

    def test_does_not_quote_non_json_body(self):
        token = fake_token("hvs", "CAESIJq3mNotARealTokenValue123")
        summary = vault_http._summarise_error_body(make_response(500, raw=token.encode()))
        assert token not in summary
        assert "non-JSON body" in summary

    def test_does_not_quote_unrecognised_json_body(self):
        token = fake_token("hvs", "CAESIJnotarealvalue")
        summary = vault_http._summarise_error_body(make_response(500, {"data": {"token": token}}))
        assert token not in summary
        assert "unrecognised JSON body" in summary

    def test_truncates_oversized_error_list(self):
        summary = vault_http._summarise_error_body(make_response(400, {"errors": ["x" * 2000]}))
        assert len(summary) < 2000
        assert summary.endswith("...[truncated]")

    def test_get_failure_message_excludes_raw_body(self, client):
        token = fake_token("hvs", "CAESIJnotarealvalue")
        with patch.object(client.session, "request", return_value=make_response(500, raw=token.encode())), pytest.raises(VaultAPIError) as excinfo:
            client.get("sys/mounts")
        assert token not in str(excinfo.value)

    def test_get_failure_message_keeps_vault_errors(self, client):
        with patch.object(client.session, "request", return_value=make_response(403, {"errors": ["permission denied"]})), pytest.raises(VaultPermissionError) as excinfo:
            client.get("sys/mounts")
        assert "permission denied" in str(excinfo.value.__cause__)


class TestPerRequestTimeout:
    """V4: a single heavy call can get more headroom than the client default."""

    def test_get_client_defaults_to_client_timeout(self, client):
        with client.get_client("ns") as c:
            assert c.timeout == client.request_timeout == 30

    def test_get_client_honours_override(self, client):
        with client.get_client("ns", timeout=120) as c:
            assert c.timeout == 120

    def test_constructor_timeout(self):
        c = VaultClient(vault_addr="https://vault.example.com", vault_token="s.test", request_timeout=5)
        with patch.object(c.session, "request", return_value=make_response(200, {})) as request:
            c.get("sys/mounts")
        assert request.call_args.kwargs["timeout"] == 5

    def test_get_passes_timeout_through(self, client):
        with patch.object(client.session, "request", return_value=make_response(200, {})) as request:
            client.get("sys/mounts", timeout=99)
        assert request.call_args.kwargs["timeout"] == 99

    def test_get_defaults_timeout_to_client_default(self, client):
        with patch.object(client.session, "request", return_value=make_response(200, {})) as request:
            client.get("sys/mounts")
        assert request.call_args.kwargs["timeout"] == client.request_timeout


class TestAdapterRetryConfiguration:
    """V2: retryable statuses must surface as precise errors, not RetryError."""

    def test_raise_on_status_disabled(self, client):
        adapter = client.session.get_adapter("https://vault.example.com")
        assert adapter.max_retries.raise_on_status is False

    def test_request_timeout_status_is_retryable(self, client):
        adapter = client.session.get_adapter("https://vault.example.com")
        assert 408 in adapter.max_retries.status_forcelist

    def test_server_error_statuses_retryable(self, client):
        adapter = client.session.get_adapter("https://vault.example.com")
        for status in (429, 500, 502, 503, 504):
            assert status in adapter.max_retries.status_forcelist

    def test_get_is_retryable(self, client):
        adapter = client.session.get_adapter("https://vault.example.com")
        assert "GET" in adapter.max_retries.allowed_methods

    def test_exhausted_retries_raise_vault_connection_error(self, client):
        """RetryError would otherwise land in the generic 'Unexpected error' branch."""
        with patch.object(client.session, "request", side_effect=requests.exceptions.RetryError("too many retries")), pytest.raises(VaultConnectionError, match="Retries exhausted"):
            client.get("sys/mounts")
