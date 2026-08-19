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
        debug: If True, enable DEBUG level logging.
        json_logs: If True, output JSON formatted logs. Otherwise use console format.
    """
    # Module loggers are diagnostics, not UI. rich owns the human console -- the
    # panel, progress bar, tables and check marks -- and an INFO line printed
    # alongside a live progress bar corrupts it, which is what a default level of
    # INFO used to do 134 times in a single namespace audit.
    #
    # So: anything a user must see on a default run belongs in a console.print,
    # not a logger.info. Warnings and errors still reach the console, and both
    # escape hatches below restore the detail.
    if debug:
        log_level = logging.DEBUG
    elif json_logs:
        # A machine-readable stream is not being read live by a human, so there
        # is no progress bar to protect and the lifecycle events are the point.
        log_level = logging.INFO
    else:
        log_level = logging.WARNING

    # Configure standard library logging
    logging.basicConfig(
        format="%(message)s",
        stream=sys.stdout,
        level=log_level,
    )
    # basicConfig silently does nothing once the root logger has a handler, so
    # its level= is honoured only on the very first call in a process. Set the
    # level directly as well: whether the threshold actually applies is the
    # whole point of this function, and it must not depend on being first.
    logging.getLogger().setLevel(log_level)

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
        method = {
            logging.DEBUG: self.debug,
            logging.INFO: self.info,
            logging.WARNING: self.warning,
            logging.ERROR: self.error,
            logging.CRITICAL: self.critical,
        }.get(level, self.info)
        method(msg, **kwargs)

    def isEnabledFor(self, level: int) -> bool:  # noqa: N802
        """Return True if the underlying logger would emit at this level."""
        try:
            return self.logger.isEnabledFor(level)
        except AttributeError:
            return True

    def _stdlib_logger(self) -> logging.Logger | None:
        """Return the stdlib logger backing this adapter, if reachable."""
        underlying = getattr(self.logger, "_logger", None)
        if isinstance(underlying, logging.Logger):
            return underlying
        name = getattr(self.logger, "name", None)
        return logging.getLogger(name) if name else None

    def setLevel(self, level) -> None:  # noqa: N802
        """Set the level on the underlying stdlib logger.

        Delegates rather than silently accepting the call. A no-op here is worse
        than the AttributeError it replaced: a caller raising verbosity would
        get silence with no indication the request was discarded.
        """
        logger = self._stdlib_logger()
        if logger is None:
            raise NotImplementedError("This logger has no stdlib logger to configure; set levels via setup_logging(debug=...) instead.")
        logger.setLevel(level)

    def addHandler(self, handler) -> None:  # noqa: N802
        """Attach a handler to the underlying stdlib logger."""
        logger = self._stdlib_logger()
        if logger is None:
            raise NotImplementedError("This logger has no stdlib logger to attach handlers to; configure handlers via setup_logging() instead.")
        logger.addHandler(handler)

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
