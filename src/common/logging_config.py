"""Structured logging configuration for Vault Tools.

This module provides centralized logging configuration with:
- JSON structured logging for production
- Human-readable console logging for development
- Correlation IDs for request tracking
- Context-aware logging
"""

import logging
import sys
import uuid
from contextvars import ContextVar
from typing import Any

import structlog

# Context variable for correlation ID (thread-safe)
correlation_id_var: ContextVar[str | None] = ContextVar("correlation_id", default=None)


def get_correlation_id() -> str:
    """Get or create correlation ID for current context."""
    correlation_id = correlation_id_var.get()
    if correlation_id is None:
        correlation_id = str(uuid.uuid4())
        correlation_id_var.set(correlation_id)
    return correlation_id


def set_correlation_id(correlation_id: str) -> None:
    """Set correlation ID for current context."""
    correlation_id_var.set(correlation_id)


def add_correlation_id(logger: Any, method_name: str, event_dict: dict[str, Any]) -> dict[str, Any]:
    """Add correlation ID to log event."""
    event_dict["correlation_id"] = get_correlation_id()
    return event_dict


def add_app_context(logger: Any, method_name: str, event_dict: dict[str, Any]) -> dict[str, Any]:
    """Add application context to log event."""
    event_dict["app"] = "vault-tools"
    event_dict["version"] = "1.0.0"
    return event_dict


def setup_logging(debug: bool = False, json_logs: bool = False) -> None:
    """Configure structured logging for the application.

    Args:
        debug: If True, enable DEBUG level logging. Otherwise use INFO.
        json_logs: If True, output JSON formatted logs. Otherwise use console format.
    """
    log_level = logging.DEBUG if debug else logging.INFO

    # Configure standard library logging
    logging.basicConfig(
        format="%(message)s",
        stream=sys.stdout,
        level=log_level,
    )

    # Configure structlog processors
    shared_processors = [
        structlog.contextvars.merge_contextvars,
        add_correlation_id,
        add_app_context,
        structlog.stdlib.add_logger_name,
        structlog.stdlib.add_log_level,
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.StackInfoRenderer(),
    ]

    if json_logs:
        # JSON output for production/log aggregation
        processors = shared_processors + [structlog.processors.format_exc_info, structlog.processors.JSONRenderer()]
    else:
        # Human-readable console output for development
        processors = shared_processors + [structlog.processors.format_exc_info, structlog.dev.ConsoleRenderer(colors=True)]

    structlog.configure(
        processors=processors,
        wrapper_class=structlog.stdlib.BoundLogger,
        context_class=dict,
        logger_factory=structlog.stdlib.LoggerFactory(),
        cache_logger_on_first_use=True,
    )

    # Reduce noise from third-party libraries
    if not debug:
        logging.getLogger("hvac").setLevel(logging.WARNING)
        logging.getLogger("requests").setLevel(logging.WARNING)
        logging.getLogger("urllib3").setLevel(logging.WARNING)


def get_logger(name: str) -> structlog.stdlib.BoundLogger:
    """Get a structured logger instance.

    Args:
        name: Logger name (typically __name__)

    Returns:
        Configured structured logger
    """
    return structlog.get_logger(name)


class StructuredLoggerAdapter:
    """Adapter to provide structured logging interface to existing code.

    This allows gradual migration from standard logging to structured logging.
    """

    def __init__(self, logger: structlog.stdlib.BoundLogger):
        self.logger = logger

    def debug(self, msg: str, **kwargs) -> None:
        """Log debug message with optional context."""
        self.logger.debug(msg, **kwargs)

    def info(self, msg: str, **kwargs) -> None:
        """Log info message with optional context."""
        self.logger.info(msg, **kwargs)

    def warning(self, msg: str, **kwargs) -> None:
        """Log warning message with optional context."""
        self.logger.warning(msg, **kwargs)

    def error(self, msg: str, **kwargs) -> None:
        """Log error message with optional context."""
        self.logger.error(msg, **kwargs)

    def exception(self, msg: str, **kwargs) -> None:
        """Log exception with traceback."""
        self.logger.exception(msg, **kwargs)

    def bind(self, **kwargs) -> "StructuredLoggerAdapter":
        """Bind context to logger."""
        return StructuredLoggerAdapter(self.logger.bind(**kwargs))


def get_structured_logger(name: str) -> StructuredLoggerAdapter:
    """Get a structured logger adapter.

    Args:
        name: Logger name (typically __name__)

    Returns:
        Structured logger adapter
    """
    return StructuredLoggerAdapter(get_logger(name))
