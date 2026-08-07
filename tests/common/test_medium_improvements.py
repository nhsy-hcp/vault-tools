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

    # Canonical form carries a trailing slash on non-root paths: that is what
    # Vault's namespace API expects, and what NamespaceAuditConfig produces.
    # The helper previously stripped the slash, contradicting both.

    def test_plain_name_gains_trailing_slash(self):
        assert normalise_namespace_path("foo") == "foo/"

    def test_trailing_slash_preserved(self):
        assert normalise_namespace_path("foo/") == "foo/"

    def test_nested_trailing_slash_preserved(self):
        assert normalise_namespace_path("foo/bar/") == "foo/bar/"

    def test_deep_nesting_preserved(self):
        assert normalise_namespace_path("a/b/c/") == "a/b/c/"

    def test_whitespace_stripped(self):
        assert normalise_namespace_path("  foo/ ") == "foo/"

    def test_duplicate_trailing_slashes_collapsed(self):
        assert normalise_namespace_path("foo//") == "foo/"

    def test_only_slashes_returns_root(self):
        assert normalise_namespace_path("///") == ""

    def test_is_idempotent(self):
        once = normalise_namespace_path("foo/bar")
        assert normalise_namespace_path(once) == once

    def test_matches_config_post_init_convention(self):
        """The helper and NamespaceAuditConfig must not disagree (C1)."""
        from src.common.config import NamespaceAuditConfig

        cfg = NamespaceAuditConfig(
            vault_addr="https://vault.example.com",
            vault_token="s.test",
            namespace_path="team-a",
        )
        assert cfg.namespace_path == normalise_namespace_path("team-a")


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

    def test_missing_namespace_id_still_exports(self, tmp_path):
        """Namespace columns are optional — Vault omits them on OSS clusters.

        E4's schema check is preserved, but it guards client_type only. Treating
        the namespace columns as required made this a silent no-op export.
        """
        from src.entity_export.main import process_entity_export_data

        data = [{"namespace_path": "root/", "client_type": "entity"}]
        result = process_entity_export_data(data, "cluster", output_dir=str(tmp_path))
        assert result is not None

    def test_missing_namespace_path_still_exports(self, tmp_path):
        from src.entity_export.main import process_entity_export_data

        data = [{"namespace_id": "root", "client_type": "entity"}]
        result = process_entity_export_data(data, "cluster", output_dir=str(tmp_path))
        assert result is not None

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


class TestWorkerQueueTimeout:
    def test_worker_survives_queue_empty_timeout(self):
        """A get() timeout must not call task_done().

        Regression test: calling task_done() on the queue.Empty path either
        raises ValueError('task_done() called too many times') from the finally
        block — killing the worker — or decrements another worker's count, which
        lets path_queue.join() return while namespaces are still in flight and
        reports get written from incomplete data.
        """
        import time

        from src.namespace_audit.main import NamespaceAuditor

        mock_client = Mock(spec=VaultClient)
        auditor = NamespaceAuditor(mock_client, worker_queue_timeout=1)
        auditor._traverse_namespace = Mock()

        test_queue = queue.Queue()

        # Force one Empty timeout, then hand the worker real work.
        def feed():
            time.sleep(1.2)
            test_queue.put("child/")
            test_queue.put(None)

        feeder = threading.Thread(target=feed)
        feeder.start()

        worker_thread = threading.Thread(target=auditor._worker, args=(test_queue,))
        worker_thread.start()
        worker_thread.join(timeout=10)
        feeder.join()

        assert not worker_thread.is_alive(), "worker did not exit cleanly"
        # The worker survived the timeout and went on to process the real item.
        auditor._traverse_namespace.assert_called_once_with("child/", test_queue)
        # Balanced counters: join() returns immediately rather than hanging.
        test_queue.join()

    def test_queue_empty_logs_at_debug(self):
        """A tail-end timeout is normal, so it must not log at warning."""
        import time

        from src.namespace_audit.main import NamespaceAuditor

        mock_client = Mock(spec=VaultClient)
        auditor = NamespaceAuditor(mock_client, worker_queue_timeout=1)
        auditor._traverse_namespace = Mock()

        test_queue = queue.Queue()

        def send_shutdown():
            time.sleep(1.2)
            test_queue.put(None)

        t = threading.Thread(target=send_shutdown)
        t.start()

        with patch("src.namespace_audit.main.logger") as mock_logger:
            worker_thread = threading.Thread(target=auditor._worker, args=(test_queue,))
            worker_thread.start()
            worker_thread.join(timeout=5)

        t.join()

        debug_calls = [str(c) for c in mock_logger.debug.call_args_list]
        assert any("timed out" in msg for msg in debug_calls)
        warning_calls = [str(c) for c in mock_logger.warning.call_args_list]
        assert not any("timed out" in msg for msg in warning_calls)


class TestQueueDepthWarning:
    def test_warns_once_above_threshold(self):
        """Unbounded queue keeps memory visibility via a one-shot warning."""
        from src.namespace_audit.main import NamespaceAuditor

        auditor = NamespaceAuditor(Mock(spec=VaultClient), queue_depth_warn_threshold=2)
        test_queue = queue.Queue()
        for i in range(5):
            test_queue.put(f"ns{i}/")

        with patch("src.namespace_audit.main.logger") as mock_logger:
            auditor._warn_on_queue_depth(test_queue)
            auditor._warn_on_queue_depth(test_queue)

        assert mock_logger.warning.call_count == 1

    def test_silent_below_threshold(self):
        from src.namespace_audit.main import NamespaceAuditor

        auditor = NamespaceAuditor(Mock(spec=VaultClient), queue_depth_warn_threshold=100)
        test_queue = queue.Queue()
        test_queue.put("ns/")

        with patch("src.namespace_audit.main.logger") as mock_logger:
            auditor._warn_on_queue_depth(test_queue)

        mock_logger.warning.assert_not_called()


# ---------------------------------------------------------------------------
# U2 — get_last_month timezone contract
# ---------------------------------------------------------------------------


class TestDateHelperTimezoneContract:
    def test_get_last_month_is_timezone_aware(self):
        """The return type changed from naive to aware; pin it deliberately."""
        from src.common.utils import get_last_month

        assert get_last_month().tzinfo is not None

    def test_get_last_month_is_last_day_of_previous_month(self):
        from datetime import UTC, datetime

        from src.common.utils import get_last_month

        result = get_last_month()
        today = datetime.now(UTC)
        assert result < today.replace(day=1)
        # Adding a day must roll into the current month.
        from datetime import timedelta

        assert (result + timedelta(days=1)).month == today.month

    def test_month_helpers_preserve_tzinfo(self):
        """get_first/last_day_of_month use .replace(), so awareness carries."""
        from datetime import UTC, datetime

        from src.common.utils import get_first_day_of_month, get_last_day_of_month

        aware = datetime(2026, 2, 15, 12, 30, tzinfo=UTC)
        assert get_first_day_of_month(aware).tzinfo is UTC
        assert get_last_day_of_month(aware).tzinfo is UTC
        assert get_last_day_of_month(aware).day == 28  # 2026 is not a leap year

    def test_mixing_with_naive_datetime_raises(self):
        """Documents the trap the docstring now warns about."""
        from datetime import datetime

        import pytest

        from src.common.utils import get_last_month

        with pytest.raises(TypeError):
            _ = get_last_month() - datetime.now()
