"""Centralized configuration management for Vault Tools."""

import os
from dataclasses import dataclass

from .exceptions import ConfigurationError

# Note (CF3): all boolean env-var parsing in this module intentionally uses the
# pattern `.lower() == "true"` — this is consistent across every boolean flag
# and is the correct approach; there is no inconsistency to fix.


@dataclass
class GlobalConfig:
    """Global configuration settings."""

    output_dir: str = "outputs"
    debug: bool = False

    def __post_init__(self):
        """Validate and prepare configuration after initialization."""
        # Ensure output_dir exists and is writable (CF4).
        try:
            os.makedirs(self.output_dir, exist_ok=True)
        except OSError as e:
            raise ConfigurationError(f"Cannot create output directory '{self.output_dir}': {e}") from e
        if not os.access(self.output_dir, os.W_OK):
            raise ConfigurationError(f"Output directory '{self.output_dir}' is not writable. Set VAULT_TOOLS_OUTPUT_DIR to a writable path.")

    @classmethod
    def from_environment(cls, output_dir: str | None = None) -> "GlobalConfig":
        """Create configuration from environment variables.

        Args:
            output_dir: Overrides ``VAULT_TOOLS_OUTPUT_DIR`` when set (the CLI
                ``--output-dir`` flag). Passed through the constructor so
                ``__post_init__`` validates the directory that will actually be
                written to. Assigning to ``output_dir`` after construction
                bypasses that check and defers the failure to report-write time.
        """
        return cls(
            output_dir=output_dir if output_dir is not None else os.environ.get("VAULT_TOOLS_OUTPUT_DIR", "outputs"),
            debug=os.environ.get("VAULT_TOOLS_DEBUG", "false").lower() == "true",
        )
