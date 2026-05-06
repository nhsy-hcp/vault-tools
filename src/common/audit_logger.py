"""
Audit logging module for vault-tools.

Provides tamper-proof audit trail of all tool invocations with user context,
parameters, and results for compliance and forensic analysis.
"""

import json
import logging
import os
import socket
from datetime import datetime
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Any


class AuditLogger:
    """Audit logger for tracking tool usage and operations."""

    def __init__(self, log_dir: str = None, max_bytes: int = 10485760, backup_count: int = 5):
        """
        Initialize audit logger.

        Args:
            log_dir: Directory for audit logs (default: ./outputs/audit)
            max_bytes: Maximum size of each log file (default: 10MB)
            backup_count: Number of backup files to keep (default: 5)
        """
        self.log_dir = Path(log_dir) if log_dir else Path("outputs/audit")
        self.log_dir.mkdir(parents=True, exist_ok=True)

        # Create audit logger
        self.logger = logging.getLogger("vault_tools.audit")
        self.logger.setLevel(logging.INFO)
        self.logger.propagate = False  # Don't propagate to root logger

        # Remove existing handlers
        self.logger.handlers.clear()

        # Create rotating file handler
        log_file = self.log_dir / "audit.log"
        handler = RotatingFileHandler(log_file, maxBytes=max_bytes, backupCount=backup_count, encoding="utf-8")

        # JSON formatter for structured logging
        formatter = logging.Formatter(
            "%(message)s"  # We'll format as JSON in the log methods
        )
        handler.setFormatter(formatter)
        self.logger.addHandler(handler)

        # Get user context once
        self.user_context = self._get_user_context()

    def _get_user_context(self) -> dict[str, str]:
        """Get user context information."""
        return {
            "username": os.getenv("USER", os.getenv("USERNAME", "unknown")),
            "hostname": socket.gethostname(),
            "pid": os.getpid(),
        }

    def _format_log_entry(self, event_type: str, data: dict[str, Any]) -> str:
        """Format log entry as JSON."""
        entry = {"timestamp": datetime.utcnow().isoformat() + "Z", "event_type": event_type, **self.user_context, **data}
        return json.dumps(entry, default=str)

    def log_tool_execution(self, tool_name: str, command: str, parameters: dict[str, Any], result: str = "success", duration_seconds: float = None, error: str = None, metadata: dict[str, Any] = None):
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

    def log_vault_operation(self, operation: str, namespace: str, path: str, method: str, result: str = "success", error: str = None, metadata: dict[str, Any] = None):
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

    def log_security_event(self, event: str, severity: str, description: str, metadata: dict[str, Any] = None):
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

    def log_data_export(self, export_type: str, record_count: int, output_file: str, filters: dict[str, Any] = None, metadata: dict[str, Any] = None):
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
