"""Centralized configuration management for Vault Tools."""

import os
from dataclasses import dataclass
from typing import Optional

from .vault_client import ConfigurationError


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
    
    @classmethod
    def from_environment(cls) -> 'GlobalConfig':
        """Create configuration from environment variables."""
        return cls(
            output_dir=os.environ.get('VAULT_TOOLS_OUTPUT_DIR', 'outputs'),
            debug=os.environ.get('VAULT_TOOLS_DEBUG', 'false').lower() == 'true'
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
            
        # Ensure namespace path ends with / if not empty
        if self.namespace_path and not self.namespace_path.endswith("/"):
            self.namespace_path += "/"
    
    @classmethod
    def from_environment(cls, **overrides) -> 'NamespaceAuditConfig':
        """Create configuration from environment variables with optional overrides."""
        vault_addr = os.environ.get('VAULT_ADDR')
        vault_token = os.environ.get('VAULT_TOKEN')
        vault_skip_verify = os.environ.get('VAULT_SKIP_VERIFY', 'false').lower() == 'true'
        
        # Validate integer environment variables early
        try:
            worker_threads = int(os.environ.get('VAULT_TOOLS_WORKERS', '4'))
        except ValueError as e:
            raise ConfigurationError(f"VAULT_TOOLS_WORKERS must be an integer (got '{os.environ.get('VAULT_TOOLS_WORKERS')}')") from e
            
        try:
            rate_limit_batch_size = int(os.environ.get('VAULT_TOOLS_RATE_LIMIT_BATCH', '100'))
        except ValueError as e:
            raise ConfigurationError(f"VAULT_TOOLS_RATE_LIMIT_BATCH must be an integer (got '{os.environ.get('VAULT_TOOLS_RATE_LIMIT_BATCH')}')") from e
            
        try:
            rate_limit_sleep_seconds = int(os.environ.get('VAULT_TOOLS_RATE_LIMIT_SLEEP', '3'))
        except ValueError as e:
            raise ConfigurationError(f"VAULT_TOOLS_RATE_LIMIT_SLEEP must be an integer (got '{os.environ.get('VAULT_TOOLS_RATE_LIMIT_SLEEP')}')") from e
            
        try:
            hvac_timeout = int(os.environ.get('VAULT_TOOLS_TIMEOUT', '30'))
        except ValueError as e:
            raise ConfigurationError(f"VAULT_TOOLS_TIMEOUT must be an integer (got '{os.environ.get('VAULT_TOOLS_TIMEOUT')}')") from e
        
        config = cls(
            vault_addr=vault_addr,
            vault_token=vault_token,
            vault_skip_verify=vault_skip_verify,
            namespace_path=os.environ.get('VAULT_TOOLS_NAMESPACE', ''),
            worker_threads=worker_threads,
            rate_limit_disable=os.environ.get('VAULT_TOOLS_NO_RATE_LIMIT', 'false').lower() == 'true',
            rate_limit_batch_size=rate_limit_batch_size,
            rate_limit_sleep_seconds=rate_limit_sleep_seconds,
            hvac_timeout=hvac_timeout
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
    def from_environment(cls, **overrides) -> 'ActivityExportConfig':
        """Create configuration from environment variables with optional overrides."""
        vault_addr = os.environ.get('VAULT_ADDR')
        vault_token = os.environ.get('VAULT_TOKEN')
        vault_skip_verify = os.environ.get('VAULT_SKIP_VERIFY', 'false').lower() == 'true'
        
        config = cls(
            vault_addr=vault_addr,
            vault_token=vault_token,
            vault_skip_verify=vault_skip_verify,
            start_date=os.environ.get('VAULT_TOOLS_START_DATE', ''),
            end_date=os.environ.get('VAULT_TOOLS_END_DATE', ''),
            cluster_name=os.environ.get('VAULT_TOOLS_CLUSTER_NAME', '')
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