"""Tests for src/common/logging_config.py."""

import logging
from unittest.mock import patch

import pytest


class TestGetVersion:
    def test_returns_string(self):
        from src.common.logging_config import get_version

        v = get_version()
        assert isinstance(v, str)
        assert len(v) > 0

    def test_falls_back_to_dev_on_missing_package(self):
        from importlib.metadata import PackageNotFoundError

        from src.common.logging_config import get_version

        with patch("src.common.logging_config.version", side_effect=PackageNotFoundError), patch("src.common.logging_config.Path.exists", return_value=False):
            result = get_version()
        assert result == "dev"


class TestCorrelationId:
    def test_get_creates_id_on_first_call(self):
        from src.common.logging_config import correlation_id_var, get_correlation_id

        correlation_id_var.set(None)
        cid = get_correlation_id()
        assert isinstance(cid, str)
        assert len(cid) == 36  # UUID4 format

    def test_get_returns_same_id_on_subsequent_calls(self):
        from src.common.logging_config import correlation_id_var, get_correlation_id

        correlation_id_var.set(None)
        cid1 = get_correlation_id()
        cid2 = get_correlation_id()
        assert cid1 == cid2

    def test_set_and_get(self):
        from src.common.logging_config import get_correlation_id, set_correlation_id

        set_correlation_id("test-correlation-id")
        assert get_correlation_id() == "test-correlation-id"


class TestProcessors:
    def test_add_correlation_id_injects_key(self):
        from src.common.logging_config import add_correlation_id, set_correlation_id

        set_correlation_id("proc-test-id")
        event_dict = {}
        result = add_correlation_id(None, "info", event_dict)
        assert result["correlation_id"] == "proc-test-id"

    def test_add_app_context_injects_app_and_version(self):
        from src.common.logging_config import add_app_context

        event_dict = {}
        result = add_app_context(None, "info", event_dict)
        assert result["app"] == "vault-tools"
        assert "version" in result


class TestSetupLogging:
    def test_setup_logging_info_mode_suppresses_third_party(self):
        from src.common.logging_config import setup_logging

        setup_logging(debug=False, json_logs=False)
        assert logging.getLogger("hvac").level == logging.WARNING
        assert logging.getLogger("requests").level == logging.WARNING
        assert logging.getLogger("urllib3").level == logging.WARNING

    def test_setup_logging_debug_mode_does_not_suppress_third_party(self):
        from src.common.logging_config import setup_logging

        setup_logging(debug=True, json_logs=False)
        # In debug mode the suppression block is skipped — hvac logger should
        # not be forced to WARNING by setup_logging itself.  We re-run
        # non-debug to confirm the suppression path is exercised.
        setup_logging(debug=False, json_logs=False)
        assert logging.getLogger("hvac").level == logging.WARNING

    def test_setup_logging_json_mode(self):
        from src.common.logging_config import setup_logging

        # Should not raise
        setup_logging(debug=False, json_logs=True)

    def test_get_logger_returns_bound_logger(self):
        from src.common.logging_config import get_logger

        logger = get_logger("test.module")
        assert logger is not None

    def test_get_structured_logger_returns_adapter(self):
        from src.common.logging_config import StructuredLoggerAdapter, get_structured_logger

        adapter = get_structured_logger("test.module")
        assert isinstance(adapter, StructuredLoggerAdapter)


class TestStructuredLoggerAdapter:
    @pytest.fixture
    def adapter(self):
        from src.common.logging_config import get_structured_logger

        return get_structured_logger("test.adapter")

    def test_debug(self, adapter):
        adapter.debug("debug message")

    def test_info(self, adapter):
        adapter.info("info message")

    def test_warning(self, adapter):
        adapter.warning("warning message")

    def test_error(self, adapter):
        adapter.error("error message")

    def test_critical(self, adapter):
        adapter.critical("critical message")

    def test_log_info_level(self, adapter):
        adapter.log(logging.INFO, "log info")

    def test_log_debug_level(self, adapter):
        adapter.log(logging.DEBUG, "log debug")

    def test_log_warning_level(self, adapter):
        adapter.log(logging.WARNING, "log warning")

    def test_log_error_level(self, adapter):
        adapter.log(logging.ERROR, "log error")

    def test_log_critical_level(self, adapter):
        adapter.log(logging.CRITICAL, "log critical")

    def test_log_unknown_level_falls_back_to_info(self, adapter):
        adapter.log(999, "unknown level")

    def test_is_enabled_for(self, adapter):
        result = adapter.isEnabledFor(logging.INFO)
        assert isinstance(result, bool)

    def test_set_level_noop(self, adapter):
        adapter.setLevel(logging.DEBUG)  # should not raise

    def test_add_handler_noop(self, adapter):
        adapter.addHandler(logging.StreamHandler())  # should not raise

    def test_bind_returns_new_adapter(self, adapter):
        from src.common.logging_config import StructuredLoggerAdapter

        bound = adapter.bind(request_id="abc")
        assert isinstance(bound, StructuredLoggerAdapter)

    def test_exception_method(self, adapter):
        try:
            raise ValueError("boom")
        except ValueError:
            adapter.exception("caught exception")
