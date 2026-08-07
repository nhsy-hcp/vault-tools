"""Shared exception classes for Vault Tools.

All custom exceptions used across the codebase are defined here so that
modules can import from a single, predictable location rather than from
whichever implementation module happened to define them first.
"""


class VaultAPIError(Exception):
    """Custom exception for Vault API errors."""

    pass


class VaultConnectionError(Exception):
    """Custom exception for Vault connection issues."""

    pass


class VaultDataError(Exception):
    """Custom exception for malformed Vault API responses."""

    pass


class VaultPermissionError(Exception):
    """Custom exception for Vault authorization issues."""

    pass


class ConfigurationError(Exception):
    """Custom exception for configuration-related errors."""

    pass


class FileProcessingError(Exception):
    """Custom exception for file processing errors."""

    pass
