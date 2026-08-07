"""Tests for AuditLogger — thread safety and sensitive field redaction."""

import json
import threading
import time

from src.common.audit_logger import AuditLogger, _redact


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
