"""Centralized configuration management for Vault Tools."""

import os
from dataclasses import dataclass

from .exceptions import ConfigurationError
from .utils import normalise_namespace_path

# Note (CF3): all boolean env-var parsing in this module intentionally uses the
# pattern `.lower() == "true"` — this is consistent across every boolean flag
# and is the correct approach; there is no inconsistency to fix.


@dataclass
class VaultConfig:
    """Base Vault configuration."""

    vault_addr: str
    vault_token: str
    vault_skip_verify: bool = False

    def __post_init__(self):
        """Validate configuration after initialization."""
        if not self.vault_addr:
            raise ConfigurationError("VAULT_ADDR is required. Set it to your Vault server URL (e.g., https://vault.example.com)")
        if not self.vault_token:
            raise ConfigurationError("VAULT_TOKEN is required. Set it to a valid Vault authentication token")


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
            raise ConfigurationError(f"Output directory '{self.output_dir}' is not writable. " "Set VAULT_TOOLS_OUTPUT_DIR to a writable path.")

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


@dataclass
class NamespaceAuditConfig(VaultConfig):
    """Configuration for namespace audit operations."""

    namespace_path: str = ""
    worker_threads: int = 4
    rate_limit_disable: bool = False
    rate_limit_batch_size: int = 100
    rate_limit_sleep_seconds: int = 3
    hvac_timeout: int = 30

    def __post_init__(self):
        """Validate configuration after initialization."""
        super().__post_init__()

        if self.worker_threads <= 0:
            raise ConfigurationError(f"Worker threads must be positive (got {self.worker_threads}). Set VAULT_TOOLS_WORKERS to a positive integer.")
        if self.rate_limit_batch_size <= 0:
            raise ConfigurationError(f"Rate limit batch size must be positive (got {self.rate_limit_batch_size}). Set VAULT_TOOLS_RATE_LIMIT_BATCH to a positive integer.")
        if self.hvac_timeout <= 0:
            raise ConfigurationError(f"HVAC timeout must be positive (got {self.hvac_timeout}). Set VAULT_TOOLS_TIMEOUT to a positive integer.")

        # Canonical form (trailing slash on non-root) via the shared helper —
        # see normalise_namespace_path for the convention (C1).
        self.namespace_path = normalise_namespace_path(self.namespace_path)

    @classmethod
    def from_environment(cls, **overrides) -> "NamespaceAuditConfig":
        """Create configuration from environment variables with optional overrides."""
        vault_addr = os.environ.get("VAULT_ADDR")
        vault_token = os.environ.get("VAULT_TOKEN")
        vault_skip_verify = os.environ.get("VAULT_SKIP_VERIFY", "false").lower() == "true"

        # Validate integer environment variables early
        try:
            worker_threads = int(os.environ.get("VAULT_TOOLS_WORKERS", "4"))
        except ValueError as e:
            raise ConfigurationError(f"VAULT_TOOLS_WORKERS must be an integer (got '{os.environ.get('VAULT_TOOLS_WORKERS')}')") from e

        try:
            rate_limit_batch_size = int(os.environ.get("VAULT_TOOLS_RATE_LIMIT_BATCH", "100"))
        except ValueError as e:
            raise ConfigurationError(f"VAULT_TOOLS_RATE_LIMIT_BATCH must be an integer (got '{os.environ.get('VAULT_TOOLS_RATE_LIMIT_BATCH')}')") from e

        try:
            rate_limit_sleep_seconds = int(os.environ.get("VAULT_TOOLS_RATE_LIMIT_SLEEP", "3"))
        except ValueError as e:
            raise ConfigurationError(f"VAULT_TOOLS_RATE_LIMIT_SLEEP must be an integer (got '{os.environ.get('VAULT_TOOLS_RATE_LIMIT_SLEEP')}')") from e

        try:
            hvac_timeout = int(os.environ.get("VAULT_TOOLS_TIMEOUT", "30"))
        except ValueError as e:
            raise ConfigurationError(f"VAULT_TOOLS_TIMEOUT must be an integer (got '{os.environ.get('VAULT_TOOLS_TIMEOUT')}')") from e

        # Normalise namespace path from env before passing to config so
        # __post_init__ receives an already-canonical value (CF2).
        raw_namespace = normalise_namespace_path(os.environ.get("VAULT_TOOLS_NAMESPACE", ""))

        config = cls(
            vault_addr=vault_addr,
            vault_token=vault_token,
            vault_skip_verify=vault_skip_verify,
            namespace_path=raw_namespace,
            worker_threads=worker_threads,
            rate_limit_disable=os.environ.get("VAULT_TOOLS_NO_RATE_LIMIT", "false").lower() == "true",
            rate_limit_batch_size=rate_limit_batch_size,
            rate_limit_sleep_seconds=rate_limit_sleep_seconds,
            hvac_timeout=hvac_timeout,
        )

        # Apply any overrides
        for key, value in overrides.items():
            if hasattr(config, key):
                setattr(config, key, value)

        return config


@dataclass
class ActivityExportConfig(VaultConfig):
    """Configuration for activity export operations."""

    start_date: str = ""
    end_date: str = ""
    cluster_name: str = ""

    def __post_init__(self):
        """Validate configuration after initialization."""
        super().__post_init__()

        if not self.start_date:
            raise ConfigurationError("Start date is required")
        if not self.end_date:
            raise ConfigurationError("End date is required")
        if not self.cluster_name:
            raise ConfigurationError("Cluster name is required")

    @classmethod
    def from_environment(cls, **overrides) -> "ActivityExportConfig":
        """Create configuration from environment variables with optional overrides."""
        vault_addr = os.environ.get("VAULT_ADDR")
        vault_token = os.environ.get("VAULT_TOKEN")
        vault_skip_verify = os.environ.get("VAULT_SKIP_VERIFY", "false").lower() == "true"

        config = cls(
            vault_addr=vault_addr,
            vault_token=vault_token,
            vault_skip_verify=vault_skip_verify,
            start_date=os.environ.get("VAULT_TOOLS_START_DATE", ""),
            end_date=os.environ.get("VAULT_TOOLS_END_DATE", ""),
            cluster_name=os.environ.get("VAULT_TOOLS_CLUSTER_NAME", ""),
        )

        # Apply any overrides
        for key, value in overrides.items():
            if hasattr(config, key):
                setattr(config, key, value)

        return config


@dataclass
class EntityExportConfig(ActivityExportConfig):
    """Configuration for entity export operations (inherits from activity export)."""

    pass
