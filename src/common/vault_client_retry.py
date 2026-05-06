"""Enhanced VaultClient with retry logic and circuit breaker pattern.

This module extends the base VaultClient with:
- Automatic retry with exponential backoff for transient failures
- Circuit breaker pattern to fail fast when endpoints are consistently failing
- Detailed logging of retry attempts
"""

import json
import logging
import os
from contextlib import contextmanager

import hvac
import requests
import urllib3
from tenacity import after_log, before_sleep_log, retry, retry_if_exception_type, stop_after_attempt, wait_exponential

# Import base exceptions
from .vault_client import VaultAPIError, VaultConnectionError, VaultDataError, VaultPermissionError


class CircuitBreakerOpenError(Exception):
    """Exception raised when circuit breaker is open."""

    pass


class CircuitBreaker:
    """Simple circuit breaker implementation.

    Tracks failures and opens circuit after threshold is reached.
    Circuit automatically closes after recovery timeout.
    """

    def __init__(self, failure_threshold: int = 5, recovery_timeout: int = 60):
        """Initialize circuit breaker.

        Args:
            failure_threshold: Number of failures before opening circuit
            recovery_timeout: Seconds to wait before attempting recovery
        """
        self.failure_threshold = failure_threshold
        self.recovery_timeout = recovery_timeout
        self.failure_count = 0
        self.last_failure_time: float | None = None
        self.state = "closed"  # closed, open, half-open
        self.logger = logging.getLogger(__name__)

    def call(self, func, *args, **kwargs):
        """Execute function with circuit breaker protection."""
        import time

        # Check if circuit should transition from open to half-open
        if self.state == "open":
            if self.last_failure_time and (time.time() - self.last_failure_time) > self.recovery_timeout:
                self.logger.info("circuit_breaker_half_open", recovery_timeout=self.recovery_timeout)
                self.state = "half-open"
            else:
                raise CircuitBreakerOpenError(f"Circuit breaker is open. Last failure: {self.failure_count} failures. " f"Will retry after {self.recovery_timeout}s recovery timeout.")

        try:
            result = func(*args, **kwargs)
            # Success - reset failure count
            if self.state == "half-open":
                self.logger.info("circuit_breaker_closed", message="Circuit breaker recovered")
                self.state = "closed"
            self.failure_count = 0
            return result

        except Exception as e:
            import time

            self.failure_count += 1
            self.last_failure_time = time.time()

            if self.failure_count >= self.failure_threshold:
                self.state = "open"
                self.logger.error("circuit_breaker_opened", failure_count=self.failure_count, threshold=self.failure_threshold, error=str(e))
            raise


class VaultClientWithRetry:
    """VaultClient with automatic retry and circuit breaker capabilities."""

    def __init__(self, vault_addr: str = None, vault_token: str = None, vault_skip_verify: bool = False, hvac_timeout: int = 30, max_retry_attempts: int = 3, enable_circuit_breaker: bool = True):
        """Initialize VaultClient with retry capabilities.

        Args:
            vault_addr: Vault server address
            vault_token: Vault authentication token
            vault_skip_verify: Skip TLS verification
            hvac_timeout: Request timeout in seconds
            max_retry_attempts: Maximum number of retry attempts
            enable_circuit_breaker: Enable circuit breaker pattern
        """
        self.vault_addr = vault_addr or os.environ.get("VAULT_ADDR")
        self.vault_token = vault_token or os.environ.get("VAULT_TOKEN")
        self.vault_skip_verify = vault_skip_verify
        self.hvac_timeout = hvac_timeout
        self.max_retry_attempts = max_retry_attempts
        self.logger = logging.getLogger(__name__)

        if not self.vault_addr or not self.vault_token:
            raise ValueError("VAULT_ADDR and VAULT_TOKEN must be provided or set as environment variables.")

        if self.vault_skip_verify:
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

        # Initialize circuit breakers for different endpoint types
        self.circuit_breakers: dict[str, CircuitBreaker] = {}
        self.enable_circuit_breaker = enable_circuit_breaker

    def _get_circuit_breaker(self, endpoint: str) -> CircuitBreaker | None:
        """Get or create circuit breaker for endpoint."""
        if not self.enable_circuit_breaker:
            return None

        # Group endpoints by prefix for circuit breaker
        prefix = endpoint.split("/")[0] if "/" in endpoint else endpoint

        if prefix not in self.circuit_breakers:
            self.circuit_breakers[prefix] = CircuitBreaker(failure_threshold=5, recovery_timeout=60)

        return self.circuit_breakers[prefix]

    @contextmanager
    def get_client(self, namespace_path: str = ""):
        """Context manager for creating Vault clients."""
        client = hvac.Client(url=self.vault_addr, token=self.vault_token, namespace=namespace_path, verify=not self.vault_skip_verify, timeout=self.hvac_timeout)
        yield client

    def validate_connection(self) -> str:
        """Validate Vault connection and return cluster name.

        This method does not use retry logic as it's typically called once at startup.
        """
        try:
            with self.get_client() as client:
                health_status = client.sys.read_health_status(method="GET", sealed_code=200, performance_standby_code=200, uninit_code=200)

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

    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=2, max=10),
        retry=retry_if_exception_type((VaultConnectionError, requests.exceptions.ConnectionError, requests.exceptions.Timeout)),
        before_sleep=before_sleep_log(logging.getLogger(__name__), logging.WARNING),
        after=after_log(logging.getLogger(__name__), logging.DEBUG),
    )
    def _get_with_retry(self, path: str, params: dict = None, namespace: str = "") -> dict:
        """Internal GET method with retry logic."""
        circuit_breaker = self._get_circuit_breaker(path)

        def _do_get():
            with self.get_client(namespace) as client:
                clean_path = path.lstrip("/").replace("v1/", "")

                response = client.adapter.request("GET", f"v1/{clean_path}", params=params) if params else client.adapter.request("GET", f"v1/{clean_path}")

                if isinstance(response, dict):
                    return response

                if not isinstance(response, requests.Response):
                    raise VaultDataError(f"Expected requests.Response object or dict, but got {type(response)} for GET {path}")

                if response.status_code != 200:
                    raise VaultAPIError(f"GET {path} failed with status {response.status_code}: {response.text}")

                try:
                    return response.json()
                except json.JSONDecodeError as e:
                    if "Extra data" in str(e):
                        self.logger.debug("JSONDecodeError: Extra data. Attempting NDJSON parsing.")
                        return [json.loads(line) for line in response.text.strip().split("\n") if line]
                    else:
                        raise VaultDataError(f"Failed to parse JSON from {path}: {e}") from e

        if circuit_breaker:
            return circuit_breaker.call(_do_get)
        else:
            return _do_get()

    def get(self, path: str, params: dict = None, namespace: str = "") -> dict:
        """Make GET request to Vault API with automatic retry.

        Args:
            path: API endpoint path
            params: Optional query parameters
            namespace: Optional namespace path

        Returns:
            Response data as dictionary

        Raises:
            VaultAPIError: For API errors
            VaultConnectionError: For connection issues
            VaultPermissionError: For authorization issues
            VaultDataError: For malformed responses
        CircuitBreakerOpenError: When circuit breaker is open
        """
        try:
            return self._get_with_retry(path, params, namespace)
        except hvac.exceptions.Forbidden as e:
            raise VaultPermissionError(f"Access denied to {path}. Check token permissions for this path.") from e
        except hvac.exceptions.InvalidPath as e:
            raise VaultAPIError(f"Invalid path {path}: {e}. Verify the path exists and is accessible.") from e
        except hvac.exceptions.VaultError as e:
            raise VaultAPIError(f"Vault API error on GET {path}: {e}") from e

    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=2, max=10),
        retry=retry_if_exception_type((VaultConnectionError, requests.exceptions.ConnectionError, requests.exceptions.Timeout)),
        before_sleep=before_sleep_log(logging.getLogger(__name__), logging.WARNING),
        after=after_log(logging.getLogger(__name__), logging.DEBUG),
    )
    def _post_with_retry(self, path: str, data: dict = None, namespace: str = "") -> dict:
        """Internal POST method with retry logic."""
        circuit_breaker = self._get_circuit_breaker(path)

        def _do_post():
            with self.get_client(namespace) as client:
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

        if circuit_breaker:
            return circuit_breaker.call(_do_post)
        else:
            return _do_post()

    def post(self, path: str, data: dict = None, namespace: str = "") -> dict:
        """Make POST request to Vault API with automatic retry.

        Args:
            path: API endpoint path
            data: Optional request body data
            namespace: Optional namespace path

        Returns:
            Response data as dictionary

        Raises:
            VaultAPIError: For API errors
            VaultConnectionError: For connection issues
            VaultPermissionError: For authorization issues
            VaultDataError: For malformed responses
            CircuitBreakerOpen: When circuit breaker is open
        """
        try:
            return self._post_with_retry(path, data, namespace)
        except hvac.exceptions.Forbidden as e:
            raise VaultPermissionError(f"Access denied to {path}. Check token permissions for this path.") from e
        except hvac.exceptions.InvalidPath as e:
            raise VaultAPIError(f"Invalid path {path}: {e}. Verify the path exists and is accessible.") from e
        except hvac.exceptions.VaultError as e:
            raise VaultAPIError(f"Vault API error on POST {path}: {e}") from e
