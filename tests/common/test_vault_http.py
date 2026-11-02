"""Tests for src/common/vault_http.py: status mapping, headers, TLS and timeouts."""

import json
from unittest.mock import Mock, patch

import pytest
import requests

from src.common import vault_http
from src.common.vault_http import NamespacedClient, raise_for_vault_status

ADDR = "https://vault.example.com:8200"
TOKEN = "test-token-not-a-secret"  # noqa: S105 - not token-shaped, safe for gitleaks


def make_response(status: int, body=None, *, raw: bytes | None = None) -> requests.Response:
    """A real requests.Response, as the session would return it."""
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


def make_client(response: requests.Response, namespace: str = "", timeout=30, verify=True):
    session = requests.Session()
    session.verify = verify
    session.request = Mock(return_value=response)
    return NamespacedClient(session, ADDR, TOKEN, namespace=namespace, timeout=timeout), session


# ---------------------------------------------------------------------------
# Status mapping
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("status", "cls"),
    [
        (400, vault_http.InvalidRequest),
        (401, vault_http.Unauthorized),
        (403, vault_http.Forbidden),
        (404, vault_http.InvalidPath),
        (429, vault_http.RateLimitExceeded),
        (500, vault_http.InternalServerError),
        (501, vault_http.VaultNotInitialized),
        (502, vault_http.BadGateway),
        (503, vault_http.VaultDown),
        (418, vault_http.UnexpectedError),
        (504, vault_http.UnexpectedError),
    ],
)
def test_status_maps_to_exception(status, cls):
    response = make_response(status, {"errors": ["boom"]})
    with pytest.raises(cls) as excinfo:
        raise_for_vault_status(response, "GET", "sys/mounts")
    assert isinstance(excinfo.value, vault_http.VaultError)
    assert excinfo.value.status == status
    assert excinfo.value.response is response
    assert excinfo.value.response.status_code == status


@pytest.mark.parametrize("status", [200, 204, 301])
def test_success_statuses_do_not_raise(status):
    raise_for_vault_status(make_response(status, {}))


def test_errors_text_is_in_str_for_the_sentinel_heuristic():
    """namespace_audit matches "unsupported path" in str(e); it must survive."""
    response = make_response(404, {"errors": ["1 error occurred:\n\t* unsupported path\n\n"]})
    with pytest.raises(vault_http.InvalidPath) as excinfo:
        raise_for_vault_status(response, "GET", "sys/policies/egp")
    assert "unsupported path" in str(excinfo.value)
    assert excinfo.value.errors == ["1 error occurred:\n\t* unsupported path\n\n"]
    assert str(excinfo.value).endswith("on GET sys/policies/egp")


def test_non_json_error_body_is_described_not_quoted():
    response = make_response(500, raw=b"secret-looking body")
    with pytest.raises(vault_http.InternalServerError) as excinfo:
        raise_for_vault_status(response)
    assert "secret-looking" not in str(excinfo.value)
    assert "non-JSON body" in str(excinfo.value)
    assert excinfo.value.errors == []


def test_long_errors_are_truncated():
    response = make_response(400, {"errors": ["x" * 2000]})
    with pytest.raises(vault_http.InvalidRequest) as excinfo:
        raise_for_vault_status(response)
    assert "[truncated]" in str(excinfo.value)
    assert len(str(excinfo.value)) < 600


def test_errors_that_are_not_a_list_are_kept_as_one_string():
    response = make_response(400, {"errors": "single message"})
    with pytest.raises(vault_http.InvalidRequest) as excinfo:
        raise_for_vault_status(response)
    assert excinfo.value.errors == ["single message"]
    assert "single message" in str(excinfo.value)


def test_error_body_is_parsed_once():
    response = make_response(404, {"errors": ["x"]})
    with patch.object(requests.Response, "json", autospec=True, side_effect=lambda self: {"errors": ["x"]}) as parsed, pytest.raises(vault_http.InvalidPath):
        raise_for_vault_status(response)
    assert parsed.call_count == 1


def test_unrecognised_json_error_body_is_described():
    response = make_response(500, {"data": {"token": "x"}})
    with pytest.raises(vault_http.InternalServerError) as excinfo:
        raise_for_vault_status(response)
    assert "unrecognised JSON body" in str(excinfo.value)


# ---------------------------------------------------------------------------
# Request construction
# ---------------------------------------------------------------------------


def test_root_namespace_sends_no_namespace_header():
    client, session = make_client(make_response(200, {"data": {}}))
    client.read("sys/mounts")
    headers = session.request.call_args.kwargs["headers"]
    assert "X-Vault-Namespace" not in headers
    assert headers["X-Vault-Token"] == TOKEN
    assert headers["X-Vault-Request"] == "true"


def test_namespace_header_is_sent_for_a_namespace():
    client, session = make_client(make_response(200, {"data": {}}), namespace="team-a/")
    client.read("sys/mounts")
    assert session.request.call_args.kwargs["headers"]["X-Vault-Namespace"] == "team-a/"


def test_url_and_method():
    client, session = make_client(make_response(200, {"data": {}}))
    client.read("/v1/sys//mounts")
    kwargs = session.request.call_args.kwargs
    assert kwargs["method"] == "GET"
    assert kwargs["url"] == f"{ADDR}/v1/sys/mounts"


def test_v1_inside_a_path_is_kept():
    client, session = make_client(make_response(200, {"data": {}}))
    client.read("kv/v1/data")
    assert session.request.call_args.kwargs["url"] == f"{ADDR}/v1/kv/v1/data"


def test_timeout_reaches_the_request():
    client, session = make_client(make_response(200, {}), timeout=7)
    client.read("sys/health")
    assert session.request.call_args.kwargs["timeout"] == 7


@pytest.mark.parametrize("verify", [False, "/path/to/ca.pem", True])
def test_verify_is_the_sessions(verify):
    """TLS settings travel on the session; request() never overrides them."""
    client, session = make_client(make_response(200, {}), verify=verify)
    client.read("sys/health")
    assert "verify" not in session.request.call_args.kwargs
    assert client.session.verify == verify


def test_params_are_passed():
    client, session = make_client(make_response(200, {}))
    client.read("sys/health", params={"standbyok": "true"})
    assert session.request.call_args.kwargs["params"] == {"standbyok": "true"}


def test_list_is_a_get_with_list_true():
    client, session = make_client(make_response(200, {"data": {"keys": ["a", "b"]}}))
    assert client.list("sys/policies/acl") == {"data": {"keys": ["a", "b"]}}
    kwargs = session.request.call_args.kwargs
    assert kwargs["method"] == "GET"
    assert kwargs["params"] == {"list": "true"}


def test_list_404_raises_invalid_path():
    client, _ = make_client(make_response(404, {"errors": []}))
    with pytest.raises(vault_http.InvalidPath):
        client.list("sys/namespaces")


# ---------------------------------------------------------------------------
# Response decoding
# ---------------------------------------------------------------------------


def test_read_decodes_json():
    client, _ = make_client(make_response(200, {"data": {"policy": "x"}}))
    assert client.read("sys/policies/acl/x") == {"data": {"policy": "x"}}


def test_read_204_is_empty():
    client, _ = make_client(make_response(204))
    assert client.read("sys/internal/counters/activity/export") == {}


def test_read_non_dict_json_is_empty():
    client, _ = make_client(make_response(200, ["a"]))
    assert client.read("x") == {}


def test_request_returns_the_response():
    response = make_response(200, {"a": 1})
    client, _ = make_client(response)
    assert client.request("GET", "x") is response


def test_request_raises_mapped_error():
    client, _ = make_client(make_response(403, {"errors": ["permission denied"]}))
    with pytest.raises(vault_http.Forbidden, match="permission denied"):
        client.read("sys/audit")


# ---------------------------------------------------------------------------
# Read-only guarantee
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("method", ["POST", "PUT", "PATCH", "DELETE", "LIST", "post"])
def test_write_methods_are_refused(method):
    client, session = make_client(make_response(200, {}))
    with pytest.raises(ValueError, match="read-only"):
        client.request(method, "sys/mounts/x")
    session.request.assert_not_called()


def test_client_has_no_write_methods():
    for name in ("write", "post", "put", "patch", "delete", "create", "update"):
        assert not hasattr(NamespacedClient, name)


# ---------------------------------------------------------------------------
# Response helpers
# ---------------------------------------------------------------------------


def test_data_of_unwraps_the_data_block():
    assert vault_http.data_of({"data": {"a": 1}, "lease_id": ""}) == {"a": 1}


@pytest.mark.parametrize("payload", [{"initialized": True}, {"data": None, "x": 1}, {"data": ["not", "a", "dict"]}, {}])
def test_data_of_returns_the_payload_without_a_data_dict(payload):
    """sys/health, sys/metrics and some sys/ reads answer at the top level."""
    assert vault_http.data_of(payload) is payload


@pytest.mark.parametrize(
    ("payload", "keys"),
    [({"data": {"keys": ["a", "b/"]}}, ["a", "b/"]), ({"data": {"keys": None}}, []), ({"data": None}, []), ({}, [])],
)
def test_keys_of(payload, keys):
    assert vault_http.keys_of(payload) == keys
