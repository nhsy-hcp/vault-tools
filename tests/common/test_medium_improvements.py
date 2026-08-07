"""Tests for medium-severity improvements.

Covers:
- normalise_namespace_path (ST6 / C1)
- process_activity_data null guard (ST4 / A2)
- entity_export REQUIRED_COLUMNS schema validation (ST5 / E2+E4)
- CircuitBreaker configurable settings + two-segment grouping (ST7 / R3+R4)
- worker queue timeout warning (ST8 / N2)
"""

import queue
import threading
from unittest.mock import Mock, patch

from src.common.utils import normalise_namespace_path
from src.common.vault_client import VaultClient

# ---------------------------------------------------------------------------
# ST6 — normalise_namespace_path
# ---------------------------------------------------------------------------


class TestNormaliseNamespacePath:
    def test_none_returns_root(self):
        assert normalise_namespace_path(None) == ""

    def test_empty_string_returns_root(self):
        assert normalise_namespace_path("") == ""

    def test_single_slash_returns_root(self):
        assert normalise_namespace_path("/") == ""

    def test_plain_name_unchanged(self):
        assert normalise_namespace_path("foo") == "foo"

    def test_trailing_slash_stripped(self):
        assert normalise_namespace_path("foo/") == "foo"

    def test_nested_trailing_slash_stripped(self):
        assert normalise_namespace_path("foo/bar/") == "foo/bar"

    def test_deep_nesting_preserved(self):
        assert normalise_namespace_path("a/b/c/") == "a/b/c"

    def test_whitespace_stripped(self):
        assert normalise_namespace_path("  foo/ ") == "foo"

    def test_only_slashes_returns_root(self):
        assert normalise_namespace_path("///") == ""


# ---------------------------------------------------------------------------
# ST4 — process_activity_data null guard
# ---------------------------------------------------------------------------


class TestProcessActivityDataNullGuard:
    def test_none_input_returns_empty(self):
        from src.activity_export.main import process_activity_data

        ns, mounts = process_activity_data(None, "cluster")  # type: ignore[arg-type]
        assert ns == []
        assert mounts == []

    def test_list_input_returns_empty(self):
        from src.activity_export.main import process_activity_data

        ns, mounts = process_activity_data([], "cluster")  # type: ignore[arg-type]
        assert ns == []
        assert mounts == []

    def test_missing_by_namespace_key_returns_empty(self):
        from src.activity_export.main import process_activity_data

        with patch("src.activity_export.main.write_json"), patch("src.activity_export.main.write_csv"):
            ns, mounts = process_activity_data({}, "cluster")
        assert ns == []
        assert mounts == []


# ---------------------------------------------------------------------------
# ST5 — entity_export REQUIRED_COLUMNS schema validation
# ---------------------------------------------------------------------------


class TestEntityExportSchemaValidation:
    def test_missing_client_type_returns_none(self):
        from src.entity_export.main import process_entity_export_data

        data = [{"namespace_id": "root", "namespace_path": "root/"}]
        result = process_entity_export_data(data, "cluster")
        assert result is None

    def test_missing_namespace_id_returns_none(self):
        from src.entity_export.main import process_entity_export_data

        data = [{"namespace_path": "root/", "client_type": "entity"}]
        result = process_entity_export_data(data, "cluster")
        assert result is None

    def test_missing_namespace_path_returns_none(self):
        from src.entity_export.main import process_entity_export_data

        data = [{"namespace_id": "root", "client_type": "entity"}]
        result = process_entity_export_data(data, "cluster")
        assert result is None

    def test_all_required_columns_present_succeeds(self):
        from src.entity_export.main import process_entity_export_data

        data = [
            {
                "namespace_id": "root",
                "namespace_path": "",
                "client_type": "entity",
            }
        ]
        with patch("src.entity_export.main.write_json"), patch("src.entity_export.main.write_csv"):
            result = process_entity_export_data(data, "cluster")
        assert result is not None
        assert len(result) == 1


# ---------------------------------------------------------------------------
# ST7 — CircuitBreaker configurable settings + two-segment grouping
# ---------------------------------------------------------------------------


class TestCircuitBreakerConfig:
    def test_custom_threshold_propagated(self):
        from src.common.vault_client_retry import VaultClientWithRetry

        with patch.dict("os.environ", {"VAULT_ADDR": "https://vault.example.com", "VAULT_TOKEN": "test-token"}):
            client = VaultClientWithRetry(
                circuit_breaker_failure_threshold=3,
                circuit_breaker_recovery_timeout=120,
            )
            cb = client._get_circuit_breaker("sys/health")
            assert cb.failure_threshold == 3
            assert cb.recovery_timeout == 120

    def test_two_segment_grouping_separates_breakers(self):
        from src.common.vault_client_retry import VaultClientWithRetry

        with patch.dict("os.environ", {"VAULT_ADDR": "https://vault.example.com", "VAULT_TOKEN": "test-token"}):
            client = VaultClientWithRetry()
            cb_entity = client._get_circuit_breaker("identity/entity")
            cb_group = client._get_circuit_breaker("identity/group")
            cb_sys = client._get_circuit_breaker("sys")

            # Different two-segment paths → different breaker instances
            assert cb_entity is not cb_group
            # Single-segment path still works
            assert cb_sys is not None

    def test_same_prefix_reuses_breaker(self):
        from src.common.vault_client_retry import VaultClientWithRetry

        with patch.dict("os.environ", {"VAULT_ADDR": "https://vault.example.com", "VAULT_TOKEN": "test-token"}):
            client = VaultClientWithRetry()
            cb1 = client._get_circuit_breaker("identity/entity")
            cb2 = client._get_circuit_breaker("identity/entity")
            assert cb1 is cb2

    def test_circuit_breaker_disabled_returns_none(self):
        from src.common.vault_client_retry import VaultClientWithRetry

        with patch.dict("os.environ", {"VAULT_ADDR": "https://vault.example.com", "VAULT_TOKEN": "test-token"}):
            client = VaultClientWithRetry(enable_circuit_breaker=False)
            assert client._get_circuit_breaker("identity/entity") is None


# ---------------------------------------------------------------------------
# ST8 — Worker queue timeout warning
# ---------------------------------------------------------------------------


class TestWorkerQueueTimeoutWarning:
    def test_queue_empty_emits_warning(self):
        from src.namespace_audit.main import NamespaceAuditor

        mock_client = Mock(spec=VaultClient)
        auditor = NamespaceAuditor(mock_client, worker_queue_timeout=1)
        auditor._traverse_namespace = Mock()

        test_queue = queue.Queue()

        # Do not put anything — let the get() time out once, then send shutdown
        def send_shutdown():
            import time

            time.sleep(1.2)
            test_queue.put(None)

        t = threading.Thread(target=send_shutdown)
        t.start()

        with patch("src.namespace_audit.main.logger") as mock_logger:
            worker_thread = threading.Thread(target=auditor._worker, args=(test_queue,))
            worker_thread.start()
            worker_thread.join(timeout=5)

        t.join()

        # warning should have been called for the timeout
        warning_calls = [str(c) for c in mock_logger.warning.call_args_list]
        assert any("timed out" in msg for msg in warning_calls)
