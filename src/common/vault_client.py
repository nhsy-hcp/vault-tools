import json
import logging
import os
from contextlib import contextmanager

import hvac
import requests
import urllib3
from cachetools import TTLCache
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry


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


class VaultClient:
    def __init__(
        self,
        vault_addr: str = None,
        vault_token: str = None,
        vault_skip_verify: bool = False,
        hvac_timeout: int = 30,
        pool_connections: int = 10,
        pool_maxsize: int = 20,
        cache_ttl: int = 300,
        cache_maxsize: int = 1000,
    ):
        self.vault_addr = vault_addr or os.environ.get("VAULT_ADDR")
        self.vault_token = vault_token or os.environ.get("VAULT_TOKEN")
        self.vault_skip_verify = vault_skip_verify
        self.hvac_timeout = hvac_timeout
        self.logger = logging.getLogger(__name__)

        if not self.vault_addr or not self.vault_token:
            raise ValueError("VAULT_ADDR and VAULT_TOKEN must be provided or set as environment variables.")

        if self.vault_skip_verify:
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

        # Initialize connection pooling session
        self.session = requests.Session()
        retry_strategy = Retry(
            total=3,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["HEAD", "GET", "OPTIONS", "POST"],
        )
        adapter = HTTPAdapter(
            pool_connections=pool_connections,
            pool_maxsize=pool_maxsize,
            max_retries=retry_strategy,
        )
        self.session.mount("https://", adapter)
        self.session.mount("http://", adapter)

        # Initialize response cache
        self.cache = TTLCache(maxsize=cache_maxsize, ttl=cache_ttl)
        self.cache_hits = 0
        self.cache_misses = 0

        self.logger.info(f"VaultClient initialized with connection pool (connections={pool_connections}, maxsize={pool_maxsize})")

    def _cache_key(self, path: str, namespace: str = "", params: dict = None) -> str:
        """Generate cache key for a request.

        Includes a short token prefix so responses cached under one token are
        never returned to a caller presenting a different token.  The full token
        is never stored; only the first 8 characters are used as a fingerprint.
        """
        token_prefix = self.vault_token[:8] if self.vault_token else ""
        params_str = json.dumps(params, sort_keys=True) if params else ""
        return f"{token_prefix}:{namespace}:{path}:{params_str}"

    def _is_cacheable(self, path: str) -> bool:
        """Determine if a path should be cached (read-only endpoints)."""
        cacheable_paths = [
            "sys/health",
            "sys/auth",
            "sys/mounts",
            "sys/policy",
            "sys/policies",
            "identity/entity",
            "identity/group",
        ]
        return any(path.startswith(cp) for cp in cacheable_paths)

    def get_cache_stats(self) -> dict:
        """Return cache statistics."""
        total_requests = self.cache_hits + self.cache_misses
        hit_rate = (self.cache_hits / total_requests * 100) if total_requests > 0 else 0
        return {
            "hits": self.cache_hits,
            "misses": self.cache_misses,
            "total": total_requests,
            "hit_rate": f"{hit_rate:.2f}%",
            "cache_size": len(self.cache),
            "cache_maxsize": self.cache.maxsize,
        }

    @contextmanager
    def get_client(self, namespace_path: str = ""):
        """Context manager for creating Vault clients with connection pooling."""
        client = hvac.Client(
            url=self.vault_addr,
            token=self.vault_token,
            namespace=namespace_path,
            verify=not self.vault_skip_verify,
            timeout=self.hvac_timeout,
            session=self.session,  # Use pooled session
        )
        yield client

    def validate_connection(self) -> str:
        """Validate Vault connection and return cluster name."""
        try:
            with self.get_client() as client:
                health_status = client.sys.read_health_status(
                    method="GET",
                    sealed_code=200,
                    performance_standby_code=200,
                    uninit_code=200,
                )

                if not isinstance(health_status, dict):
                    raise VaultConnectionError(f"Invalid health status response: {health_status}")

                if client.sys.is_sealed():
                    raise VaultConnectionError("Vault cluster is sealed. Please unseal the cluster using 'vault operator unseal' " "or ensure auto-unseal is properly configured.")

                if not client.is_authenticated():
                    raise VaultConnectionError("Vault client is not authenticated. Please check your VAULT_TOKEN environment variable " "and ensure the token has not expired or been revoked.")

                if not client.sys.is_initialized():
                    raise VaultConnectionError("Vault cluster is not initialized. Please initialize the cluster using 'vault operator init'.")

                cluster_name = health_status.get("cluster_name", "unknown")
                self.logger.info(f"Connected to Vault cluster: {cluster_name}")
                return cluster_name

        except hvac.exceptions.VaultError as e:
            error_msg = f"Vault API error: {e}. Please check your VAULT_ADDR ({self.vault_addr}) and network connectivity."
            raise VaultConnectionError(error_msg) from e
        except Exception as e:
            error_msg = f"Connection error: {e}. Please verify VAULT_ADDR ({self.vault_addr}) is correct and accessible."
            raise VaultConnectionError(error_msg) from e

    def get(self, path: str, params: dict = None, namespace: str = "") -> dict:
        """Make GET request to Vault API with caching support."""
        # Check cache for cacheable endpoints
        cache_key = self._cache_key(path, namespace, params)
        if self._is_cacheable(path) and cache_key in self.cache:
            self.cache_hits += 1
            self.logger.debug(f"Cache hit for {path} (namespace: {namespace})")
            return self.cache[cache_key]

        self.cache_misses += 1

        try:
            with self.get_client(namespace) as client:
                # Remove leading slash and v1 prefix if present
                clean_path = path.lstrip("/").replace("v1/", "")

                response = client.adapter.request("GET", f"v1/{clean_path}", params=params) if params else client.adapter.request("GET", f"v1/{clean_path}")

                # If hvac already parsed the response into a dict, return it directly
                if isinstance(response, dict):
                    result = response
                elif not isinstance(response, requests.Response):
                    raise VaultDataError(f"Expected requests.Response object or dict, but got {type(response)} for GET {path}. Raw response: {response}")
                elif response.status_code != 200:
                    raise VaultAPIError(f"GET {path} failed with status {response.status_code}: {response.text}")
                else:
                    try:
                        # Attempt to parse as a single JSON object first
                        result = response.json()
                    except json.JSONDecodeError as e:
                        # If it fails with 'Extra data', assume it's NDJSON and parse line by line
                        if "Extra data" in str(e):
                            self.logger.debug("JSONDecodeError: Extra data. Attempting NDJSON parsing.")
                            result = [json.loads(line) for line in response.text.strip().split("\n") if line]
                        else:
                            # Re-raise other JSONDecodeErrors
                            raise VaultDataError(f"Failed to parse JSON from {path}: {e}") from e

                # Cache the result if cacheable
                if self._is_cacheable(path):
                    self.cache[cache_key] = result
                    self.logger.debug(f"Cached response for {path} (namespace: {namespace})")

                return result

        except hvac.exceptions.Forbidden as e:
            raise VaultPermissionError(f"Access denied to {path}. Check token permissions for this path.") from e
        except hvac.exceptions.InvalidPath as e:
            raise VaultAPIError(f"Invalid path {path}: {e}. Verify the path exists and is accessible.") from e
        except hvac.exceptions.VaultError as e:
            raise VaultAPIError(f"Vault API error on GET {path}: {e}") from e
        except requests.exceptions.ConnectionError as e:
            raise VaultConnectionError(f"Connection failed for GET {path}. Check network connectivity and Vault address.") from e
        except requests.exceptions.Timeout as e:
            raise VaultConnectionError(f"Request timeout for GET {path}. Consider increasing timeout or check Vault responsiveness.") from e
        except Exception as e:
            raise VaultAPIError(f"Unexpected error on GET {path}: {e}") from e

    def post(self, path: str, data: dict = None, namespace: str = "") -> dict:
        """Make POST request to Vault API."""
        try:
            with self.get_client(namespace) as client:
                # Remove leading slash and v1 prefix if present
                clean_path = path.lstrip("/").replace("v1/", "")

                response = client.adapter.request("POST", f"{client.url}/v1/{clean_path}", json=data)

                if response.status_code not in [200, 204]:
                    raise VaultAPIError(f"POST {path} failed with status {response.status_code}: {response.text}")

                if response.content:
                    try:
                        return response.json()
                    except json.JSONDecodeError as e:
                        raise VaultDataError(f"Failed to parse JSON response from POST {path}: {e}") from e
                else:
                    return {}

        except hvac.exceptions.Forbidden as e:
            raise VaultPermissionError(f"Access denied to {path}. Check token permissions for this path.") from e
        except hvac.exceptions.InvalidPath as e:
            raise VaultAPIError(f"Invalid path {path}: {e}. Verify the path exists and is accessible.") from e
        except hvac.exceptions.VaultError as e:
            raise VaultAPIError(f"Vault API error on POST {path}: {e}") from e
        except requests.exceptions.ConnectionError as e:
            raise VaultConnectionError(f"Connection failed for POST {path}. Check network connectivity and Vault address.") from e
        except requests.exceptions.Timeout as e:
            raise VaultConnectionError(f"Request timeout for POST {path}. Consider increasing timeout or check Vault responsiveness.") from e
        except Exception as e:
            raise VaultAPIError(f"Unexpected error on POST {path}: {e}") from e
