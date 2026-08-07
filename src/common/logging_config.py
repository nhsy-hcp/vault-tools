"""Structured logging configuration for Vault Tools.

This module provides centralized logging configuration with:
- JSON structured logging for production
- Human-readable console logging for development
- Correlation IDs for request tracking
- Context-aware logging
"""

import functools
import logging
import os
import sys
import tomllib
import uuid
from contextvars import ContextVar
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path
from typing import Any

import structlog


@functools.lru_cache(maxsize=1)
def get_version() -> str:
    """Get application version from package metadata or pyproject.toml.

    Result is cached for the lifetime of the process (LC1) so pyproject.toml
    is read at most once even when this is called on every log event.
    """
    try:
        return version("vault-tools")
    except PackageNotFoundError:
        # Fallback: read from pyproject.toml for development/uninstalled package
        try:
            pyproject_path = Path(__file__).parent.parent.parent / "pyproject.toml"
            if pyproject_path.exists():
                with open(pyproject_path, "rb") as f:
                    pyproject_data = tomllib.load(f)
                    return pyproject_data.get("project", {}).get("version", "dev")
        except Exception:
            pass
        return "dev"


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
    event_dict["version"] = get_version()
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
        # Human-readable console output for development.
        # LC3: disable ANSI colours when stdout is not a TTY (e.g. CI) or when
        # the NO_COLOR env var is set (https://no-color.org/).
        use_colors = sys.stdout.isatty() and not os.environ.get("NO_COLOR")
        processors = shared_processors + [structlog.processors.format_exc_info, structlog.dev.ConsoleRenderer(colors=use_colors)]

    structlog.configure(
        processors=processors,
        wrapper_class=structlog.stdlib.BoundLogger,
        context_class=dict,
        logger_factory=structlog.stdlib.LoggerFactory(),
        cache_logger_on_first_use=True,
    )

    # LC4: suppress verbose output from third-party libraries in non-debug mode.
    # These libraries produce INFO/DEBUG chatter that obscures vault-tools output.
    # In debug mode all levels are intentionally left unrestricted for diagnosis.
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

    def critical(self, msg: str, **kwargs) -> None:
        """Log critical message with optional context."""
        self.logger.critical(msg, **kwargs)

    def log(self, level: int, msg: str, **kwargs) -> None:
        """Log message at the given numeric level."""
        # structlog uses named levels; map via stdlib
        import logging as _logging

        method = {
            _logging.DEBUG: self.debug,
            _logging.INFO: self.info,
            _logging.WARNING: self.warning,
            _logging.ERROR: self.error,
            _logging.CRITICAL: self.critical,
        }.get(level, self.info)
        method(msg, **kwargs)

    def isEnabledFor(self, level: int) -> bool:  # noqa: N802
        """Return True if the underlying logger would emit at this level."""
        try:
            return self.logger.isEnabledFor(level)
        except AttributeError:
            return True

    def setLevel(self, level) -> None:  # noqa: N802
        """No-op: level control is not meaningful on a structlog bound logger."""
        self.logger.debug("setLevel called on StructuredLoggerAdapter (no-op)", level=level)

    def addHandler(self, handler) -> None:  # noqa: N802
        """No-op: handler management is not meaningful on a structlog bound logger."""
        self.logger.debug("addHandler called on StructuredLoggerAdapter (no-op)")

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
