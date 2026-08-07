"""Enhanced VaultClient with retry logic and circuit breaker pattern.

This module extends the base VaultClient with:
- Automatic retry with exponential backoff for transient failures
- Circuit breaker pattern to fail fast when endpoints are consistently failing
- Detailed logging of retry attempts
"""

import logging
import os
import threading

import requests
from tenacity import after_log, before_sleep_log, retry, retry_if_exception_type, stop_after_attempt, wait_exponential

# Import base client and exceptions
from .vault_client import VaultClient, VaultConnectionError


class CircuitBreakerOpenError(Exception):
    """Exception raised when circuit breaker is open."""

    pass


class CircuitBreaker:
    """Simple circuit breaker implementation.

    Tracks failures and opens circuit after threshold is reached.
    Circuit automatically closes after recovery timeout.

    All state transitions are guarded by a threading.Lock so instances are
    safe to call from multiple threads concurrently.
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
        self._lock = threading.Lock()
        self.logger = logging.getLogger(__name__)

    def call(self, func, *args, **kwargs):
        """Execute function with circuit breaker protection."""
        import time

        with self._lock:
            # Check if circuit should transition from open to half-open
            if self.state == "open":
                if self.last_failure_time and (time.time() - self.last_failure_time) > self.recovery_timeout:
                    self.logger.info("circuit_breaker_half_open recovery_timeout=%s", self.recovery_timeout)
                    self.state = "half-open"
                else:
                    raise CircuitBreakerOpenError(f"Circuit breaker is open. Last failure: {self.failure_count} failures. " f"Will retry after {self.recovery_timeout}s recovery timeout.")

        try:
            result = func(*args, **kwargs)
            # Success — reset failure count
            with self._lock:
                if self.state == "half-open":
                    self.logger.info("circuit_breaker_closed: Circuit breaker recovered")
                    self.state = "closed"
                self.failure_count = 0
            return result

        except Exception as e:
            with self._lock:
                self.failure_count += 1
                self.last_failure_time = time.time()
                if self.failure_count >= self.failure_threshold:
                    self.state = "open"
                    self.logger.error(
                        "circuit_breaker_opened failure_count=%s threshold=%s error=%s",
                        self.failure_count,
                        self.failure_threshold,
                        str(e),
                    )
            raise


class VaultClientWithRetry(VaultClient):
    """VaultClient with automatic retry and circuit breaker capabilities.

    Inherits all connection pooling, caching, and base request logic from
    VaultClient and adds tenacity-based retry and per-endpoint circuit breakers
    on top of the get() and post() methods.
    """

    def __init__(
        self,
        vault_addr: str = None,
        vault_token: str = None,
        vault_skip_verify: bool = False,
        hvac_timeout: int = 30,
        max_retry_attempts: int = 3,
        enable_circuit_breaker: bool = True,
        circuit_breaker_failure_threshold: int = 5,
        circuit_breaker_recovery_timeout: int = None,
        **kwargs,
    ):
        """Initialize VaultClientWithRetry.

        Args:
            vault_addr: Vault server address
            vault_token: Vault authentication token
            vault_skip_verify: Skip TLS verification
            hvac_timeout: Request timeout in seconds
            max_retry_attempts: Maximum number of retry attempts
            enable_circuit_breaker: Enable circuit breaker pattern
            circuit_breaker_failure_threshold: Failures before opening a circuit breaker
            circuit_breaker_recovery_timeout: Seconds before a breaker attempts recovery.
                Defaults to the VAULT_TOOLS_CB_RECOVERY_TIMEOUT env var, or 60 seconds.
            **kwargs: Additional keyword arguments forwarded to VaultClient
        """
        super().__init__(
            vault_addr=vault_addr,
            vault_token=vault_token,
            vault_skip_verify=vault_skip_verify,
            hvac_timeout=hvac_timeout,
            **kwargs,
        )
        self.max_retry_attempts = max_retry_attempts
        self.enable_circuit_breaker = enable_circuit_breaker
        self.circuit_breaker_failure_threshold = circuit_breaker_failure_threshold
        # Allow env-var override so recovery timeout is configurable without code changes.
        if circuit_breaker_recovery_timeout is None:
            circuit_breaker_recovery_timeout = int(os.environ.get("VAULT_TOOLS_CB_RECOVERY_TIMEOUT", "60"))
        self.circuit_breaker_recovery_timeout = circuit_breaker_recovery_timeout
        self.circuit_breakers: dict[str, CircuitBreaker] = {}

    def _get_circuit_breaker(self, endpoint: str) -> CircuitBreaker | None:
        """Get or create circuit breaker for endpoint.

        Endpoints are grouped by their first two path segments so that, for
        example, ``identity/entity`` and ``identity/group`` each get their own
        independent breaker rather than sharing one for all of ``identity/*``.
        This is finer-grained than grouping by the first segment alone, which
        was the original finding (R4) — the two-segment strategy is already the
        correct fix and is preserved here.
        """
        if not self.enable_circuit_breaker:
            return None

        # Two-segment prefix gives per-operation isolation within a service.
        parts = endpoint.split("/")
        prefix = "/".join(parts[:2]) if len(parts) >= 2 else parts[0]

        if prefix not in self.circuit_breakers:
            self.circuit_breakers[prefix] = CircuitBreaker(
                failure_threshold=self.circuit_breaker_failure_threshold,
                recovery_timeout=self.circuit_breaker_recovery_timeout,
            )

        return self.circuit_breakers[prefix]

    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=2, max=10),
        retry=retry_if_exception_type((VaultConnectionError, requests.exceptions.ConnectionError, requests.exceptions.Timeout)),
        before_sleep=before_sleep_log(logging.getLogger(__name__), logging.WARNING),
        after=after_log(logging.getLogger(__name__), logging.DEBUG),
    )
    def get(self, path: str, params: dict = None, namespace: str = "") -> dict:
        """Make GET request to Vault API with automatic retry and circuit breaker.

        Args:
            path: API endpoint path
            params: Optional query parameters
            namespace: Optional namespace path

        Returns:
            Response data as dictionary

        Raises:
            VaultAPIError: For API errors
            VaultConnectionError: For connection issues (triggers retry)
            VaultPermissionError: For authorization issues
            VaultDataError: For malformed responses
            CircuitBreakerOpenError: When circuit breaker is open
        """
        circuit_breaker = self._get_circuit_breaker(path)
        if circuit_breaker:
            return circuit_breaker.call(super().get, path, params, namespace)
        return super().get(path, params, namespace)

    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=2, max=10),
        retry=retry_if_exception_type((VaultConnectionError, requests.exceptions.ConnectionError, requests.exceptions.Timeout)),
        before_sleep=before_sleep_log(logging.getLogger(__name__), logging.WARNING),
        after=after_log(logging.getLogger(__name__), logging.DEBUG),
    )
    def post(self, path: str, data: dict = None, namespace: str = "") -> dict:
        """Make POST request to Vault API with automatic retry and circuit breaker.

        Args:
            path: API endpoint path
            data: Optional request body data
            namespace: Optional namespace path

        Returns:
            Response data as dictionary

        Raises:
            VaultAPIError: For API errors
            VaultConnectionError: For connection issues (triggers retry)
            VaultPermissionError: For authorization issues
            VaultDataError: For malformed responses
            CircuitBreakerOpenError: When circuit breaker is open
        """
        circuit_breaker = self._get_circuit_breaker(path)
        if circuit_breaker:
            return circuit_breaker.call(super().post, path, data, namespace)
        return super().post(path, data, namespace)

    def validate_connection(self) -> str:
        """Validate Vault connection with circuit breaker protection.

        Wraps the base validate_connection() call through the circuit breaker
        for the ``sys/health`` endpoint so connectivity checks are subject to
        the same fail-fast semantics as regular API calls.

        Returns:
            Cluster name string from the Vault health endpoint.
        """
        circuit_breaker = self._get_circuit_breaker("sys/health")
        if circuit_breaker:
            return circuit_breaker.call(super().validate_connection)
        return super().validate_connection()
