"""Shared exception classes for Vault Tools.

All custom exceptions used across the codebase are defined here so that
modules can import from a single, predictable location rather than from
whichever implementation module happened to define them first.
"""


class VaultToolsError(Exception):
    """Base class for every expected operational failure in this tool.

    These represent conditions the user can act on — a revoked token, a sealed
    cluster, a denied path, an unwritable output directory — rather than defects.
    The CLI catches this base class and reports the message without a traceback;
    anything not derived from it is treated as a bug and keeps its stack trace.
    """

    pass


class VaultAPIError(VaultToolsError):
    """Custom exception for Vault API errors."""

    pass


class VaultConnectionError(VaultToolsError):
    """Custom exception for Vault connection issues."""

    pass


class VaultDataError(VaultToolsError):
    """Custom exception for malformed Vault API responses."""

    pass


class VaultPermissionError(VaultToolsError):
    """Custom exception for Vault authorization issues."""

    pass


class ConfigurationError(VaultToolsError):
    """Custom exception for configuration-related errors."""

    pass


class FileProcessingError(VaultToolsError):
    """Custom exception for file processing errors."""

    pass
