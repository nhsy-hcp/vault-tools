"""Tests for AuditLogger — thread safety, lifecycle, and sensitive field redaction."""

import json
import threading
import time

import pytest

from src.common.audit_logger import (
    AuditLogger,
    _redact,
    get_audit_logger,
    reset_audit_logger,
)
from tests.fake_secrets import fake_token


@pytest.fixture(autouse=True)
def _reset_global_audit_logger():
    """Keep the process-wide singleton from leaking between tests."""
    yield
    reset_audit_logger()


class TestRedact:
    """Unit tests for the _redact helper."""

    def test_redacts_known_sensitive_keys(self):
        data = {"token": "s.abc123", "username": "alice"}
        result = _redact(data)
        assert result["token"] == "[REDACTED]"
        assert result["username"] == "alice"

    def test_redacts_vault_token(self):
        data = {"vault_token": "hvs.supersecret", "namespace": "root"}
        result = _redact(data)
        assert result["vault_token"] == "[REDACTED]"
        assert result["namespace"] == "root"

    def test_redacts_password(self):
        data = {"password": "hunter2", "user": "bob"}
        result = _redact(data)
        assert result["password"] == "[REDACTED]"

    def test_redacts_case_insensitively(self):
        data = {"TOKEN": "abc", "Password": "xyz", "normal": "ok"}
        result = _redact(data)
        assert result["TOKEN"] == "[REDACTED]"
        assert result["Password"] == "[REDACTED]"
        assert result["normal"] == "ok"

    def test_redacts_nested_dicts(self):
        data = {"config": {"token": "s.secret", "host": "vault.example.com"}}
        result = _redact(data)
        assert result["config"]["token"] == "[REDACTED]"
        assert result["config"]["host"] == "vault.example.com"

    def test_redacts_values_inside_lists(self):
        data = {"items": [{"token": "abc"}, {"name": "ok"}]}
        result = _redact(data)
        assert result["items"][0]["token"] == "[REDACTED]"
        assert result["items"][1]["name"] == "ok"

    def test_does_not_mutate_original(self):
        original = {"token": "s.secret", "key": "value"}
        _redact(original)
        assert original["token"] == "s.secret"

    def test_non_dict_passthrough(self):
        assert _redact("plain string") == "plain string"
        assert _redact(42) == 42
        assert _redact(None) is None


class TestRedactValueScrubbing:
    """Key names alone are not enough — tokens hide in free-text values.

    Regression tests: callers pass `error=str(e)`, and VaultAPIError messages
    used to carry the raw Vault response body under the non-sensitive key
    "error", so key-name matching let token material through untouched.
    """

    @pytest.mark.parametrize(
        "scheme,body",
        [
            ("hvs", "CAESIJq3mNotARealTokenValue123"),
            ("hvb", "AAAAAQpNotARealBatchTokenValue456"),
            ("hvr", "NotARealRecoveryTokenValue789"),
            ("s", "abcdefghij0123456789klmnop"),
        ],
    )
    def test_scrubs_token_shapes_from_free_text(self, scheme, body):
        token = fake_token(scheme, body)
        data = {"error": f"GET sys/mounts failed with status 403: denied for {token}"}
        result = _redact(data)
        assert token not in result["error"]
        assert "[REDACTED]" in result["error"]

    def test_preserves_surrounding_diagnostic_text(self):
        token = fake_token("hvs", "CAESIJnotarealvalue123")
        data = {"error": f"GET sys/mounts failed with status 403: denied for {token}"}
        result = _redact(data)
        assert "GET sys/mounts failed with status 403" in result["error"]

    def test_scrubs_tokens_nested_in_lists_and_dicts(self):
        token = fake_token("hvs", "CAESIJnotarealvalue123")
        data = {"metadata": {"messages": ["ok", f"leaked {token} here"]}}
        result = _redact(data)
        assert token not in json.dumps(result)

    def test_truncates_oversized_free_text(self):
        data = {"error": "x" * 5000}
        result = _redact(data)
        assert len(result["error"]) < 5000
        assert result["error"].endswith("...[truncated]")

    def test_leaves_ordinary_strings_alone(self):
        data = {"namespace": "team-a/", "command": "namespace-audit --workers 4"}
        result = _redact(data)
        assert result["namespace"] == "team-a/"
        assert result["command"] == "namespace-audit --workers 4"


class TestAuditLoggerLifecycle:
    """All instances share the process-wide 'vault_tools.audit' logger."""

    def test_second_instance_does_not_mute_the_first(self, tmp_path):
        """Regression test for silent audit-record loss.

        __init__ used to call handlers.clear() without stopping the previous
        instance's listener, so the singleton kept a QueueHandler that was no
        longer attached and every later record was dropped without error.
        """
        first = get_audit_logger(log_dir=str(tmp_path))
        second = AuditLogger(log_dir=str(tmp_path))

        first.log_tool_execution("tool", "cmd", {}, result="from-first")
        second.log_tool_execution("tool", "cmd", {}, result="from-second")

        time.sleep(0.05)
        reset_audit_logger()
        second.close()

        results = [json.loads(ln)["result"] for ln in (tmp_path / "audit.log").read_text().strip().splitlines()]
        assert "from-first" in results, "records from the first instance were silently dropped"
        assert "from-second" in results

    def test_close_is_idempotent(self, tmp_path):
        """close() runs from both explicit shutdown and the atexit hook."""
        logger = AuditLogger(log_dir=str(tmp_path))
        logger.close()
        logger.close()  # must not raise

    def test_close_detaches_own_handler(self, tmp_path):
        logger = AuditLogger(log_dir=str(tmp_path))
        assert logger._handler in logger.logger.handlers
        logger.close()
        assert logger._handler not in logger.logger.handlers


class TestAuditLoggerTimestamp:
    def test_timestamp_is_utc_aware_with_z_suffix(self, tmp_path):
        """datetime.utcnow() was deprecated and naive despite the 'Z' suffix."""
        from datetime import datetime

        logger = AuditLogger(log_dir=str(tmp_path))
        logger.log_tool_execution("tool", "cmd", {})
        time.sleep(0.05)
        logger.close()

        entry = json.loads((tmp_path / "audit.log").read_text().strip().splitlines()[0])
        assert entry["timestamp"].endswith("Z")
        parsed = datetime.fromisoformat(entry["timestamp"].replace("Z", "+00:00"))
        assert parsed.tzinfo is not None


class TestAuditLoggerRedaction:
    """Tests that sensitive values never reach the log file."""

    def test_log_tool_execution_redacts_token_in_parameters(self, tmp_path):
        logger = AuditLogger(log_dir=str(tmp_path))
        logger.log_tool_execution(
            tool_name="namespace-audit",
            command="namespace-audit",
            parameters={"vault_token": "s.supersecret", "namespace": "root"},
        )
        # Give the async queue handler time to flush
        time.sleep(0.05)
        logger.close()

        log_content = (tmp_path / "audit.log").read_text()
        assert "s.supersecret" not in log_content
        assert "[REDACTED]" in log_content

    def test_log_tool_execution_preserves_non_sensitive_fields(self, tmp_path):
        logger = AuditLogger(log_dir=str(tmp_path))
        logger.log_tool_execution(
            tool_name="namespace-audit",
            command="namespace-audit",
            parameters={"namespace": "team-a/", "workers": 4},
        )
        time.sleep(0.05)
        logger.close()

        log_content = (tmp_path / "audit.log").read_text()
        assert "team-a/" in log_content
        assert "namespace-audit" in log_content


class TestAuditLoggerThreadSafety:
    """Tests that concurrent log writes are safe."""

    def test_concurrent_writes_produce_valid_json_lines(self, tmp_path):
        logger = AuditLogger(log_dir=str(tmp_path))
        errors = []

        def write_entries(n: int):
            for i in range(n):
                try:
                    logger.log_tool_execution(
                        tool_name=f"tool-{i}",
                        command=f"cmd-{i}",
                        parameters={"index": i},
                    )
                except Exception as e:
                    errors.append(e)

        threads = [threading.Thread(target=write_entries, args=(20,)) for _ in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        time.sleep(0.1)
        logger.close()

        assert not errors, f"Exceptions during concurrent writes: {errors}"

        log_content = (tmp_path / "audit.log").read_text().strip()
        lines = [ln for ln in log_content.splitlines() if ln.strip()]
        assert len(lines) == 100, f"Expected 100 log lines, got {len(lines)}"

        for line in lines:
            json.loads(line)  # raises if any line is malformed
