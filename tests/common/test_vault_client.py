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
    def test_missing_addr_raises(self):
        with pytest.raises(ValueError, match="VAULT_ADDR"):
            VaultClient(vault_addr="", vault_token="s.test")

    def test_missing_token_raises(self):
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

    def test_cache_initialised(self, client):
        assert client.cache_hits == 0
        assert client.cache_misses == 0
        assert len(client.cache) == 0


# ---------------------------------------------------------------------------
# Cache helpers
# ---------------------------------------------------------------------------


class TestCacheHelpers:
    def test_cache_key_includes_token_prefix(self, client):
        key = client._cache_key("sys/auth", "ns1", {"k": "v"})
        # token = "s.testtoken1234" → first 8 chars = "s.testto"
        token_prefix = client.vault_token[:8]
        assert key.startswith(f"{token_prefix}:")

    def test_cache_key_includes_namespace_and_path(self, client):
        key = client._cache_key("sys/auth", "team-a", None)
        assert "team-a" in key
        assert "sys/auth" in key

    def test_cache_key_no_token(self):
        c = VaultClient.__new__(VaultClient)
        c.vault_token = None
        key = c._cache_key("path", "ns", None)
        assert key.startswith(":")

    def test_is_cacheable_true(self, client):
        for path in ["sys/health", "sys/auth", "sys/mounts", "sys/policy", "sys/policies", "identity/entity", "identity/group"]:
            assert client._is_cacheable(path)

    def test_is_cacheable_false(self, client):
        assert not client._is_cacheable("sys/internal/counters/activity")
        assert not client._is_cacheable("secret/data/foo")

    def test_get_cache_stats_zero(self, client):
        stats = client.get_cache_stats()
        assert stats["hits"] == 0
        assert stats["misses"] == 0
        assert stats["hit_rate"] == "0.00%"

    def test_get_cache_stats_with_hits(self, client):
        client.cache_hits = 3
        client.cache_misses = 1
        stats = client.get_cache_stats()
        assert stats["hit_rate"] == "75.00%"


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

    def test_get_uses_cache_on_second_call(self, client):
        resp = self._mock_response(json_data={"data": {}})
        with self._patched_get(client, resp) as mock_gc:
            client.get("sys/auth")
            client.get("sys/auth")
            # adapter.request called only once — second call served from cache
            assert mock_gc.return_value.__enter__.return_value.adapter.request.call_count == 1
        assert client.cache_hits == 1

    def test_non_200_raises_api_error(self, client):
        resp = self._mock_response(status=404, text="not found")
        with self._patched_get(client, resp), pytest.raises(VaultAPIError, match="404"):
            client.get("sys/nonexistent")

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
