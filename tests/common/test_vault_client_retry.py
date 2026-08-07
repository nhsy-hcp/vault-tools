"""Tests for src/common/vault_client_retry.py — CircuitBreaker and VaultClientWithRetry."""

import time
from unittest.mock import MagicMock, Mock, patch

import pytest

from src.common.exceptions import VaultPermissionError
from src.common.vault_client_retry import CircuitBreaker, CircuitBreakerOpenError, VaultClientWithRetry

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def client():
    return VaultClientWithRetry(
        vault_addr="https://vault.example.com",
        vault_token="s.testtoken1234",
    )


def _make_mock_get_client(json_data=None, status=200):
    """Return a context-manager patch for get_client that yields a mock hvac client."""
    import json

    import requests

    r = Mock(spec=requests.Response)
    r.status_code = status
    r.json.return_value = json_data or {}
    r.text = json.dumps(json_data or {})
    r.content = json.dumps(json_data or {}).encode()

    mock_hvac = MagicMock()
    mock_hvac.adapter.request.return_value = r
    mock_hvac.url = "https://vault.example.com"

    cm = MagicMock()
    cm.__enter__ = Mock(return_value=mock_hvac)
    cm.__exit__ = Mock(return_value=False)
    return cm


# ---------------------------------------------------------------------------
# CircuitBreaker state machine
# ---------------------------------------------------------------------------


def _raise_value_error():
    raise ValueError("fail")


class TestCircuitBreakerStateMachine:
    def test_starts_closed(self):
        cb = CircuitBreaker(failure_threshold=2, recovery_timeout=1)
        assert cb.state == "closed"

    def test_success_keeps_closed(self):
        cb = CircuitBreaker(failure_threshold=2)
        cb.call(lambda: "ok")
        assert cb.state == "closed"
        assert cb.failure_count == 0

    def test_failures_open_circuit(self):
        cb = CircuitBreaker(failure_threshold=2, recovery_timeout=60)

        for _ in range(2):
            with pytest.raises(ValueError):
                cb.call(_raise_value_error)

        assert cb.state == "open"

    def test_open_circuit_raises_open_error(self):
        cb = CircuitBreaker(failure_threshold=1, recovery_timeout=60)
        with pytest.raises(ValueError):
            cb.call(_raise_value_error)

        with pytest.raises(CircuitBreakerOpenError):
            cb.call(lambda: "ok")

    def test_recovery_timeout_transitions_to_half_open(self):
        cb = CircuitBreaker(failure_threshold=1, recovery_timeout=0)
        with pytest.raises(ValueError):
            cb.call(_raise_value_error)

        assert cb.state == "open"
        # With recovery_timeout=0 the next call should transition to half-open
        time.sleep(0.01)
        result = cb.call(lambda: "recovered")
        assert result == "recovered"
        assert cb.state == "closed"

    def test_half_open_success_closes_circuit(self):
        cb = CircuitBreaker(failure_threshold=1, recovery_timeout=0)
        with pytest.raises(ValueError):
            cb.call(_raise_value_error)

        time.sleep(0.01)
        cb.call(lambda: "ok")
        assert cb.state == "closed"
        assert cb.failure_count == 0

    def test_concurrent_calls_are_safe(self):
        """Multiple threads incrementing failure count must not corrupt state."""
        import threading

        cb = CircuitBreaker(failure_threshold=100, recovery_timeout=60)
        errors = []

        def do_fail():
            try:
                cb.call(_raise_value_error)
            except ValueError:
                pass
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=do_fail) for _ in range(20)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert not errors
        assert cb.failure_count == 20


# ---------------------------------------------------------------------------
# VaultClientWithRetry — initialisation
# ---------------------------------------------------------------------------


class TestVaultClientWithRetryInit:
    def test_inherits_vault_client(self, client):
        from src.common.vault_client import VaultClient

        assert isinstance(client, VaultClient)

    def test_has_cache(self, client):
        assert hasattr(client, "cache")

    def test_defaults(self, client):
        assert client.max_retry_attempts == 3
        assert client.enable_circuit_breaker is True
        assert client.circuit_breaker_failure_threshold == 5
        assert client.circuit_breaker_recovery_timeout == 60

    def test_custom_threshold_stored(self):
        c = VaultClientWithRetry(
            vault_addr="https://vault.example.com",
            vault_token="s.test",
            circuit_breaker_failure_threshold=3,
            circuit_breaker_recovery_timeout=30,
        )
        assert c.circuit_breaker_failure_threshold == 3
        assert c.circuit_breaker_recovery_timeout == 30


# ---------------------------------------------------------------------------
# VaultClientWithRetry — get / post with circuit breaker
# ---------------------------------------------------------------------------


class TestVaultClientWithRetryRequests:
    def test_get_success_no_circuit_breaker(self):
        c = VaultClientWithRetry(
            vault_addr="https://vault.example.com",
            vault_token="s.test",
            enable_circuit_breaker=False,
        )
        cm = _make_mock_get_client(json_data={"data": "ok"})
        with patch.object(c, "get_client", return_value=cm):
            result = c.get("sys/internal/counters")
        assert result == {"data": "ok"}

    def test_get_success_with_circuit_breaker(self, client):
        cm = _make_mock_get_client(json_data={"data": "ok"})
        with patch.object(client, "get_client", return_value=cm):
            result = client.get("sys/internal/counters")
        assert result == {"data": "ok"}

    def test_post_success_no_circuit_breaker(self):
        c = VaultClientWithRetry(
            vault_addr="https://vault.example.com",
            vault_token="s.test",
            enable_circuit_breaker=False,
        )
        cm = _make_mock_get_client(json_data={"result": "ok"})
        with patch.object(c, "get_client", return_value=cm):
            result = c.post("auth/token/create", data={"ttl": "1h"})
        assert result == {"result": "ok"}

    def test_get_raises_circuit_breaker_open_when_open(self, client):
        cb = client._get_circuit_breaker("sys/internal")
        cb.state = "open"
        cb.last_failure_time = time.time()  # recent — won't recover yet
        cb.failure_count = 5

        with pytest.raises(CircuitBreakerOpenError):
            client.get("sys/internal/counters")

    def test_get_permission_error_not_retried(self, client):
        import hvac

        mock_hvac = MagicMock()
        mock_hvac.adapter.request.side_effect = hvac.exceptions.Forbidden("denied")
        cm = MagicMock()
        cm.__enter__ = Mock(return_value=mock_hvac)
        cm.__exit__ = Mock(return_value=False)
        with patch.object(client, "get_client", return_value=cm), pytest.raises(VaultPermissionError):
            client.get("secret/restricted")
