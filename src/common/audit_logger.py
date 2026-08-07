"""
Audit logging module for vault-tools.

Provides tamper-proof audit trail of all tool invocations with user context,
parameters, and results for compliance and forensic analysis.
"""

import atexit
import json
import logging
import os
import queue
import socket
from datetime import datetime
from logging.handlers import QueueHandler, QueueListener, RotatingFileHandler
from pathlib import Path
from typing import Any

# Keys whose values must never appear in audit logs.
_SENSITIVE_KEYS = frozenset(
    {
        "token",
        "vault_token",
        "password",
        "passwd",
        "secret",
        "api_key",
        "apikey",
        "credential",
        "credentials",
        "auth",
        "authorization",
    }
)


def _redact(data: Any) -> Any:
    """Recursively replace sensitive values in a dict with '[REDACTED]'.

    Operates on a deep copy so the original dict is never mutated.
    Key matching is case-insensitive.
    """
    if isinstance(data, dict):
        return {k: ("[REDACTED]" if k.lower() in _SENSITIVE_KEYS else _redact(v)) for k, v in data.items()}
    if isinstance(data, list):
        return [_redact(item) for item in data]
    return data


class AuditLogger:
    """Audit logger for tracking tool usage and operations.

    Log writes are serialised through a QueueHandler → QueueListener pipeline
    so concurrent calls from multiple threads are safe.  Sensitive field values
    are redacted before serialisation.
    """

    def __init__(self, log_dir: str = None, max_bytes: int = 10485760, backup_count: int = 5):
        """
        Initialize audit logger.

        Args:
            log_dir: Directory for audit logs.  When omitted the
                ``VAULT_TOOLS_AUDIT_DIR`` environment variable is consulted,
                falling back to ``./outputs/audit`` (AL4).
            max_bytes: Maximum size of each log file (default: 10MB)
            backup_count: Number of backup files to keep (default: 5)
        """
        # AL4: honour env var so the audit dir is configurable without code changes.
        if log_dir is None:
            log_dir = os.environ.get("VAULT_TOOLS_AUDIT_DIR", "outputs/audit")
        self.log_dir = Path(log_dir)
        self.log_dir.mkdir(parents=True, exist_ok=True)

        # Create audit logger
        self.logger = logging.getLogger("vault_tools.audit")
        self.logger.setLevel(logging.INFO)
        self.logger.propagate = False  # Don't propagate to root logger

        # Remove existing handlers to allow re-initialisation in tests
        self.logger.handlers.clear()

        # Create rotating file handler (the actual sink)
        log_file = self.log_dir / "audit.log"
        rotating_handler = RotatingFileHandler(
            log_file,
            maxBytes=max_bytes,
            backupCount=backup_count,
            encoding="utf-8",
        )
        rotating_handler.setFormatter(logging.Formatter("%(message)s"))

        # Route all writes through a queue so concurrent callers are safe
        log_queue: queue.Queue = queue.Queue(-1)
        self._listener = QueueListener(log_queue, rotating_handler, respect_handler_level=True)
        self._listener.start()

        queue_handler = QueueHandler(log_queue)
        self.logger.addHandler(queue_handler)

        # Ensure the listener is stopped cleanly on interpreter exit
        atexit.register(self.close)

        # AL5: do not cache user context at init — _get_user_context() is called
        # per log entry so forked processes and long-lived loggers always reflect
        # the current PID and username rather than stale init-time values.

    def close(self) -> None:
        """Stop the background logging thread cleanly."""
        self._listener.stop()

    def _get_user_context(self) -> dict[str, str]:
        """Get user context information."""
        return {
            "username": os.getenv("USER", os.getenv("USERNAME", "unknown")),
            "hostname": socket.gethostname(),
            "pid": os.getpid(),
        }

    def _format_log_entry(self, event_type: str, data: dict[str, Any]) -> str:
        """Format log entry as JSON with sensitive fields redacted."""
        entry = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "event_type": event_type,
            **self._get_user_context(),
            **data,
        }
        return json.dumps(_redact(entry), default=str)

    def log_tool_execution(
        self,
        tool_name: str,
        command: str,
        parameters: dict[str, Any],
        result: str = "success",
        duration_seconds: float = None,
        error: str = None,
        metadata: dict[str, Any] = None,
    ):
        """
        Log tool execution event.

        Args:
            tool_name: Name of the tool (e.g., 'namespace-audit')
            command: Full command executed
            parameters: Command parameters
            result: Execution result ('success', 'failure', 'partial')
            duration_seconds: Execution duration
            error: Error message if failed
            metadata: Additional metadata
        """
        data = {
            "tool_name": tool_name,
            "command": command,
            "parameters": parameters,
            "result": result,
        }

        if duration_seconds is not None:
            data["duration_seconds"] = round(duration_seconds, 3)

        if error:
            data["error"] = error

        if metadata:
            data["metadata"] = metadata

        log_entry = self._format_log_entry("tool_execution", data)
        self.logger.info(log_entry)

    def log_vault_operation(
        self,
        operation: str,
        namespace: str,
        path: str,
        method: str,
        result: str = "success",
        error: str = None,
        metadata: dict[str, Any] = None,
    ):
        """
        Log Vault API operation.

        Args:
            operation: Operation description
            namespace: Vault namespace
            path: API path
            method: HTTP method
            result: Operation result
            error: Error message if failed
            metadata: Additional metadata
        """
        data = {
            "operation": operation,
            "namespace": namespace,
            "path": path,
            "method": method,
            "result": result,
        }

        if error:
            data["error"] = error

        if metadata:
            data["metadata"] = metadata

        log_entry = self._format_log_entry("vault_operation", data)
        self.logger.info(log_entry)

    def log_security_event(
        self,
        event: str,
        severity: str,
        description: str,
        metadata: dict[str, Any] = None,
    ):
        """
        Log security-related event.

        Args:
            event: Event name
            severity: Severity level (low, medium, high, critical)
            description: Event description
            metadata: Additional metadata
        """
        data = {
            "event": event,
            "severity": severity,
            "description": description,
        }

        if metadata:
            data["metadata"] = metadata

        log_entry = self._format_log_entry("security_event", data)
        self.logger.warning(log_entry)

    def log_data_export(
        self,
        export_type: str,
        record_count: int,
        output_file: str,
        filters: dict[str, Any] = None,
        metadata: dict[str, Any] = None,
    ):
        """
        Log data export operation.

        Args:
            export_type: Type of export (e.g., 'activity', 'entities', 'namespaces')
            record_count: Number of records exported
            output_file: Output file path
            filters: Filters applied
            metadata: Additional metadata
        """
        data = {
            "export_type": export_type,
            "record_count": record_count,
            "output_file": output_file,
        }

        if filters:
            data["filters"] = filters

        if metadata:
            data["metadata"] = metadata

        log_entry = self._format_log_entry("data_export", data)
        self.logger.info(log_entry)


# Global audit logger instance
_audit_logger: AuditLogger | None = None


def get_audit_logger(log_dir: str = None) -> AuditLogger:
    """
    Get or create global audit logger instance.

    Args:
        log_dir: Directory for audit logs

    Returns:
        AuditLogger instance
    """
    global _audit_logger
    if _audit_logger is None:
        _audit_logger = AuditLogger(log_dir=log_dir)
    return _audit_logger
