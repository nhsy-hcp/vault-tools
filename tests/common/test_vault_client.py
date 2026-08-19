"""Tests for src/common/vault_client.py."""

import json
from unittest.mock import MagicMock, Mock, patch

import pytest
import requests

from src.common.exceptions import (
    VaultAPIError,
    VaultConnectionError,
    VaultDataError,
    VaultPermissionError,
)
from src.common.vault_client import VaultClient
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


# ---------------------------------------------------------------------------
# get_client context manager
# ---------------------------------------------------------------------------


class TestGetClient:
    def test_yields_hvac_client(self, client):
        import hvac

        with client.get_client("") as c:
            assert isinstance(c, hvac.Client)

    def test_namespace_forwarded(self, client):
        with client.get_client("team-a/") as _:
            assert True  # just verify no error


# ---------------------------------------------------------------------------
# validate_connection
# ---------------------------------------------------------------------------


class TestValidateConnection:
    def _make_health(self, cluster_name="test-cluster"):
        return {
            "cluster_name": cluster_name,
            "sealed": False,
            "initialized": True,
        }

    def test_success(self, client):
        mock_hvac = MagicMock()
        mock_hvac.sys.read_health_status.return_value = self._make_health()
        mock_hvac.sys.is_sealed.return_value = False
        mock_hvac.is_authenticated.return_value = True
        mock_hvac.sys.is_initialized.return_value = True

        with patch.object(client, "get_client") as mock_gc:
            mock_gc.return_value.__enter__ = Mock(return_value=mock_hvac)
            mock_gc.return_value.__exit__ = Mock(return_value=False)
            name = client.validate_connection()

        assert name == "test-cluster"

    def test_sealed_raises(self, client):
        mock_hvac = MagicMock()
        mock_hvac.sys.read_health_status.return_value = self._make_health()
        mock_hvac.sys.is_sealed.return_value = True

        with patch.object(client, "get_client") as mock_gc:
            mock_gc.return_value.__enter__ = Mock(return_value=mock_hvac)
            mock_gc.return_value.__exit__ = Mock(return_value=False)
            with pytest.raises(VaultConnectionError, match="sealed"):
                client.validate_connection()

    def test_not_authenticated_raises(self, client):
        mock_hvac = MagicMock()
        mock_hvac.sys.read_health_status.return_value = self._make_health()
        mock_hvac.sys.is_sealed.return_value = False
        mock_hvac.is_authenticated.return_value = False

        with patch.object(client, "get_client") as mock_gc:
            mock_gc.return_value.__enter__ = Mock(return_value=mock_hvac)
            mock_gc.return_value.__exit__ = Mock(return_value=False)
            with pytest.raises(VaultConnectionError, match="not authenticated"):
                client.validate_connection()

    def test_not_initialized_raises(self, client):
        mock_hvac = MagicMock()
        mock_hvac.sys.read_health_status.return_value = self._make_health()
        mock_hvac.sys.is_sealed.return_value = False
        mock_hvac.is_authenticated.return_value = True
        mock_hvac.sys.is_initialized.return_value = False

        with patch.object(client, "get_client") as mock_gc:
            mock_gc.return_value.__enter__ = Mock(return_value=mock_hvac)
            mock_gc.return_value.__exit__ = Mock(return_value=False)
            with pytest.raises(VaultConnectionError, match="not initialized"):
                client.validate_connection()

    def test_invalid_health_response_raises(self, client):
        mock_hvac = MagicMock()
        mock_hvac.sys.read_health_status.return_value = "not-a-dict"

        with patch.object(client, "get_client") as mock_gc:
            mock_gc.return_value.__enter__ = Mock(return_value=mock_hvac)
            mock_gc.return_value.__exit__ = Mock(return_value=False)
            with pytest.raises(VaultConnectionError):
                client.validate_connection()

    def test_vault_error_wrapped(self, client):
        import hvac

        with patch.object(client, "get_client") as mock_gc:
            mock_gc.return_value.__enter__ = Mock(side_effect=hvac.exceptions.VaultError("boom"))
            mock_gc.return_value.__exit__ = Mock(return_value=False)
            with pytest.raises(VaultConnectionError):
                client.validate_connection()

    def test_generic_exception_wrapped(self, client):
        with patch.object(client, "get_client") as mock_gc:
            mock_gc.return_value.__enter__ = Mock(side_effect=OSError("network down"))
            mock_gc.return_value.__exit__ = Mock(return_value=False)
            with pytest.raises(VaultConnectionError):
                client.validate_connection()


# ---------------------------------------------------------------------------
# get()
# ---------------------------------------------------------------------------


class TestVaultClientGet:
    def _mock_response(self, status=200, json_data=None, text="", content=b"{}"):
        r = Mock(spec=requests.Response)
        r.status_code = status
        r.text = text or json.dumps(json_data or {})
        r.json.return_value = json_data or {}
        r.content = content
        return r

    def _patched_get(self, client, response):
        mock_hvac = MagicMock()
        mock_hvac.adapter.request.return_value = response
        cm = MagicMock()
        cm.__enter__ = Mock(return_value=mock_hvac)
        cm.__exit__ = Mock(return_value=False)
        return patch.object(client, "get_client", return_value=cm)

    def test_successful_get_returns_dict(self, client):
        resp = self._mock_response(json_data={"data": {"key": "val"}})
        with self._patched_get(client, resp):
            result = client.get("sys/internal/counters/activity")
        assert result == {"data": {"key": "val"}}

    def test_non_200_raises_api_error(self, client):
        resp = self._mock_response(status=404, text="not found")
        with self._patched_get(client, resp), pytest.raises(VaultAPIError, match="404"):
            client.get("sys/nonexistent")

    def test_get_204_no_content_returns_empty(self, client):
        """204 means the query matched nothing, which is a success, not a failure."""
        resp = self._mock_response(status=204, text="", content=b"")
        with self._patched_get(client, resp):
            result = client.get("sys/internal/counters/activity/export")
        assert result == []

    def test_ndjson_response_parsed_as_list(self, client):
        ndjson = '{"a":1}\n{"b":2}\n'
        mock_resp = Mock(spec=requests.Response)
        mock_resp.status_code = 200
        mock_resp.text = ndjson
        mock_resp.json.side_effect = json.JSONDecodeError("Extra data", ndjson, 7)
        mock_resp.content = ndjson.encode()

        with self._patched_get(client, mock_resp):
            result = client.get("sys/internal/counters/activity/export")
        assert isinstance(result, list)
        assert result[0] == {"a": 1}

    def test_bad_json_raises_api_error(self, client):
        # VaultDataError is raised internally then wrapped by the outer except as VaultAPIError
        mock_resp = Mock(spec=requests.Response)
        mock_resp.status_code = 200
        mock_resp.text = "not json at all"
        mock_resp.json.side_effect = json.JSONDecodeError("bad", "x", 0)
        mock_resp.content = b"not json at all"

        with self._patched_get(client, mock_resp), pytest.raises((VaultDataError, VaultAPIError)):
            client.get("sys/internal/counters")

    def test_hvac_dict_response_returned_directly(self, client):
        mock_hvac = MagicMock()
        mock_hvac.adapter.request.return_value = {"direct": True}
        cm = MagicMock()
        cm.__enter__ = Mock(return_value=mock_hvac)
        cm.__exit__ = Mock(return_value=False)
        with patch.object(client, "get_client", return_value=cm):
            result = client.get("sys/internal/counters")
        assert result == {"direct": True}

    def test_forbidden_raises_permission_error(self, client):
        import hvac

        mock_hvac = MagicMock()
        mock_hvac.adapter.request.side_effect = hvac.exceptions.Forbidden("denied")
        cm = MagicMock()
        cm.__enter__ = Mock(return_value=mock_hvac)
        cm.__exit__ = Mock(return_value=False)
        with patch.object(client, "get_client", return_value=cm), pytest.raises(VaultPermissionError):
            client.get("secret/restricted")

    def test_invalid_path_raises_api_error(self, client):
        import hvac

        mock_hvac = MagicMock()
        mock_hvac.adapter.request.side_effect = hvac.exceptions.InvalidPath("bad path")
        cm = MagicMock()
        cm.__enter__ = Mock(return_value=mock_hvac)
        cm.__exit__ = Mock(return_value=False)
        with patch.object(client, "get_client", return_value=cm), pytest.raises(VaultAPIError):
            client.get("bad/path")

    def test_connection_error_raises_connection_error(self, client):
        mock_hvac = MagicMock()
        mock_hvac.adapter.request.side_effect = requests.exceptions.ConnectionError("down")
        cm = MagicMock()
        cm.__enter__ = Mock(return_value=mock_hvac)
        cm.__exit__ = Mock(return_value=False)
        with patch.object(client, "get_client", return_value=cm), pytest.raises(VaultConnectionError):
            client.get("sys/health")

    def test_timeout_raises_connection_error(self, client):
        mock_hvac = MagicMock()
        mock_hvac.adapter.request.side_effect = requests.exceptions.Timeout("timed out")
        cm = MagicMock()
        cm.__enter__ = Mock(return_value=mock_hvac)
        cm.__exit__ = Mock(return_value=False)
        with patch.object(client, "get_client", return_value=cm), pytest.raises(VaultConnectionError):
            client.get("sys/health")

    def test_unexpected_error_raises_api_error(self, client):
        mock_hvac = MagicMock()
        mock_hvac.adapter.request.side_effect = RuntimeError("unexpected")
        cm = MagicMock()
        cm.__enter__ = Mock(return_value=mock_hvac)
        cm.__exit__ = Mock(return_value=False)
        with patch.object(client, "get_client", return_value=cm), pytest.raises(VaultAPIError):
            client.get("sys/health")

    def test_unexpected_response_type_raises_data_or_api_error(self, client):
        # VaultDataError raised internally, propagates as VaultAPIError via outer except
        mock_hvac = MagicMock()
        mock_hvac.adapter.request.return_value = 12345  # neither dict nor Response
        cm = MagicMock()
        cm.__enter__ = Mock(return_value=mock_hvac)
        cm.__exit__ = Mock(return_value=False)
        with patch.object(client, "get_client", return_value=cm), pytest.raises((VaultDataError, VaultAPIError)):
            client.get("sys/health")

    def test_get_with_params(self, client):
        resp = self._mock_response(json_data={"data": {}})
        mock_hvac = MagicMock()
        mock_hvac.adapter.request.return_value = resp
        cm = MagicMock()
        cm.__enter__ = Mock(return_value=mock_hvac)
        cm.__exit__ = Mock(return_value=False)
        with patch.object(client, "get_client", return_value=cm):
            result = client.get("sys/internal/counters/activity", params={"start_time": "2024-01-01"})
        assert isinstance(result, dict)


# ---------------------------------------------------------------------------
# post()
# ---------------------------------------------------------------------------


class TestVaultClientPost:
    def _patched_post(self, client, response):
        mock_hvac = MagicMock()
        mock_hvac.adapter.request.return_value = response
        mock_hvac.url = "https://vault.example.com"
        cm = MagicMock()
        cm.__enter__ = Mock(return_value=mock_hvac)
        cm.__exit__ = Mock(return_value=False)
        return patch.object(client, "get_client", return_value=cm)

    def test_successful_post_returns_dict(self, client):
        r = Mock(spec=requests.Response)
        r.status_code = 200
        r.json.return_value = {"result": "ok"}
        r.content = b'{"result":"ok"}'

        with self._patched_post(client, r):
            result = client.post("auth/token/create", data={"ttl": "1h"})
        assert result == {"result": "ok"}

    def test_post_204_no_content_returns_empty(self, client):
        r = Mock(spec=requests.Response)
        r.status_code = 204
        r.content = b""

        with self._patched_post(client, r):
            result = client.post("sys/seal")
        assert result == {}

    def test_post_non_200_raises(self, client):
        r = Mock(spec=requests.Response)
        r.status_code = 403
        r.text = "forbidden"
        r.content = b"forbidden"

        with self._patched_post(client, r), pytest.raises(VaultAPIError, match="403"):
            client.post("auth/token/create")

    def test_post_bad_json_raises_data_or_api_error(self, client):
        # VaultDataError raised internally, propagates as VaultAPIError via outer except
        r = Mock(spec=requests.Response)
        r.status_code = 200
        r.json.side_effect = json.JSONDecodeError("bad", "x", 0)
        r.content = b"not-json"

        with self._patched_post(client, r), pytest.raises((VaultDataError, VaultAPIError)):
            client.post("auth/token/create")

    def test_post_forbidden_raises_permission_error(self, client):
        import hvac

        mock_hvac = MagicMock()
        mock_hvac.adapter.request.side_effect = hvac.exceptions.Forbidden("denied")
        mock_hvac.url = "https://vault.example.com"
        cm = MagicMock()
        cm.__enter__ = Mock(return_value=mock_hvac)
        cm.__exit__ = Mock(return_value=False)
        with patch.object(client, "get_client", return_value=cm), pytest.raises(VaultPermissionError):
            client.post("auth/token/create")

    def test_post_connection_error_raises(self, client):
        mock_hvac = MagicMock()
        mock_hvac.adapter.request.side_effect = requests.exceptions.ConnectionError("down")
        mock_hvac.url = "https://vault.example.com"
        cm = MagicMock()
        cm.__enter__ = Mock(return_value=mock_hvac)
        cm.__exit__ = Mock(return_value=False)
        with patch.object(client, "get_client", return_value=cm), pytest.raises(VaultConnectionError):
            client.post("auth/token/create")

    def test_post_timeout_raises(self, client):
        mock_hvac = MagicMock()
        mock_hvac.adapter.request.side_effect = requests.exceptions.Timeout("timed out")
        mock_hvac.url = "https://vault.example.com"
        cm = MagicMock()
        cm.__enter__ = Mock(return_value=mock_hvac)
        cm.__exit__ = Mock(return_value=False)
        with patch.object(client, "get_client", return_value=cm), pytest.raises(VaultConnectionError):
            client.post("auth/token/create")


class TestErrorBodySummarisation:
    """Vault error bodies must not be interpolated verbatim into exceptions.

    Exception text reaches the audit log via `error=str(e)`, so a raw
    response.text could carry token material or wrapped secrets into a file
    that is explicitly meant to be safe to retain and ship.
    """

    def _response(self, *, body: bytes, json_payload=None):
        response = MagicMock(spec=requests.Response)
        response.content = body
        if json_payload is None:
            response.json.side_effect = ValueError("no json")
        else:
            response.json.return_value = json_payload
        return response

    def test_keeps_vault_error_strings(self):
        from src.common.vault_client import _summarise_error_body

        response = self._response(body=b"{}", json_payload={"errors": ["permission denied"]})
        assert _summarise_error_body(response) == "permission denied"

    def test_joins_multiple_errors(self):
        from src.common.vault_client import _summarise_error_body

        response = self._response(body=b"{}", json_payload={"errors": ["a", "b"]})
        assert _summarise_error_body(response) == "a; b"

    def test_does_not_quote_non_json_body(self):
        from src.common.vault_client import _summarise_error_body

        token = fake_token("hvs", "CAESIJq3mNotARealTokenValue123")
        summary = _summarise_error_body(self._response(body=token.encode()))
        assert token not in summary
        assert "non-JSON body" in summary

    def test_does_not_quote_unrecognised_json_body(self):
        from src.common.vault_client import _summarise_error_body

        token = fake_token("hvs", "CAESIJnotarealvalue")
        response = self._response(body=b"{}", json_payload={"data": {"token": token}})
        summary = _summarise_error_body(response)
        assert token not in summary
        assert "unrecognised JSON body" in summary

    def test_truncates_oversized_error_list(self):
        from src.common.vault_client import _summarise_error_body

        response = self._response(body=b"{}", json_payload={"errors": ["x" * 2000]})
        summary = _summarise_error_body(response)
        assert len(summary) < 2000
        assert summary.endswith("...[truncated]")

    def test_get_failure_message_excludes_raw_body(self, client):
        response = MagicMock(spec=requests.Response)
        response.status_code = 403
        response.content = b'{"errors":["permission denied"]}'
        response.json.return_value = {"errors": ["permission denied"]}

        mock_hvac = MagicMock()
        mock_hvac.adapter.request.return_value = response
        mock_hvac.url = "https://vault.example.com"
        cm = MagicMock()
        cm.__enter__ = Mock(return_value=mock_hvac)
        cm.__exit__ = Mock(return_value=False)

        with patch.object(client, "get_client", return_value=cm), pytest.raises(VaultAPIError) as excinfo:
            client.get("sys/mounts")

        message = str(excinfo.value)
        assert "permission denied" in message
        assert "403" in message


class TestPerRequestTimeout:
    """V4: a single heavy call can get more headroom than the client default."""

    def test_get_client_defaults_to_client_timeout(self, client):
        with patch("src.common.vault_client.hvac.Client") as mock_client, client.get_client("ns"):
            pass
        assert mock_client.call_args.kwargs["timeout"] == client.hvac_timeout

    def test_get_client_honours_override(self, client):
        with patch("src.common.vault_client.hvac.Client") as mock_client, client.get_client("ns", timeout=120):
            pass
        assert mock_client.call_args.kwargs["timeout"] == 120

    def _ok_client_cm(self, payload):
        """A get_client() stand-in whose adapter returns a successful response."""
        mock_hvac = MagicMock()
        mock_hvac.adapter.request.return_value = payload
        mock_hvac.url = "https://vault.example.com"
        cm = MagicMock()
        cm.__enter__ = Mock(return_value=mock_hvac)
        cm.__exit__ = Mock(return_value=False)
        return cm

    def test_get_passes_timeout_through(self, client):
        cm = self._ok_client_cm({"data": {}})
        with patch.object(client, "get_client", return_value=cm) as mock_get_client:
            client.get("sys/mounts", timeout=99)
        assert mock_get_client.call_args.kwargs["timeout"] == 99

    def test_get_defaults_timeout_to_none(self, client):
        """None means 'use the client default', resolved inside get_client."""
        cm = self._ok_client_cm({"data": {}})
        with patch.object(client, "get_client", return_value=cm) as mock_get_client:
            client.get("sys/mounts")
        assert mock_get_client.call_args.kwargs["timeout"] is None

    def test_post_passes_timeout_through(self, client):
        response = MagicMock(spec=requests.Response)
        response.status_code = 204
        response.content = b""
        cm = self._ok_client_cm(response)
        with patch.object(client, "get_client", return_value=cm) as mock_get_client:
            client.post("auth/token/create", timeout=99)
        assert mock_get_client.call_args.kwargs["timeout"] == 99


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

    def test_post_is_retryable(self, client):
        adapter = client.session.get_adapter("https://vault.example.com")
        assert "POST" in adapter.max_retries.allowed_methods

    def test_exhausted_retries_raise_vault_connection_error(self, client):
        """RetryError would otherwise land in the generic 'Unexpected error' branch."""
        mock_hvac = MagicMock()
        mock_hvac.adapter.request.side_effect = requests.exceptions.RetryError("too many retries")
        mock_hvac.url = "https://vault.example.com"
        cm = MagicMock()
        cm.__enter__ = Mock(return_value=mock_hvac)
        cm.__exit__ = Mock(return_value=False)

        with patch.object(client, "get_client", return_value=cm), pytest.raises(VaultConnectionError, match="Retries exhausted"):
            client.get("sys/mounts")
