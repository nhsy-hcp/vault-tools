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
from tenacity import Retrying, after_log, before_sleep_log, retry_if_exception_type, stop_after_attempt, wait_exponential

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
                    raise CircuitBreakerOpenError(f"Circuit breaker is open. Last failure: {self.failure_count} failures. Will retry after {self.recovery_timeout}s recovery timeout.")

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
        if max_retry_attempts < 1:
            raise ValueError(f"max_retry_attempts must be at least 1 (got {max_retry_attempts})")
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
        This replaced the original first-segment-only grouping, which was too
        coarse (finding R4).
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

    def _build_retryer(self) -> Retrying:
        """Build a retry controller for a single request.

        Constructed per call rather than shared: tenacity's Retrying keeps
        mutable per-run statistics on the instance, and namespace_audit drives
        this client from several worker threads at once.

        reraise=True is essential. Without it tenacity wraps the final failure in
        tenacity.RetryError, which is not what any caller catches — the friendly
        "connection failed" branch in NamespaceAuditor.audit_cluster looks for
        VaultConnectionError and would be bypassed entirely.
        """
        module_logger = logging.getLogger(__name__)
        return Retrying(
            stop=stop_after_attempt(self.max_retry_attempts),
            wait=wait_exponential(multiplier=1, min=2, max=10),
            retry=retry_if_exception_type((VaultConnectionError, requests.exceptions.ConnectionError, requests.exceptions.Timeout)),
            before_sleep=before_sleep_log(module_logger, logging.WARNING),
            after=after_log(module_logger, logging.DEBUG),
            reraise=True,
        )

    def get(self, path: str, params: dict = None, namespace: str = "", timeout: int | None = None) -> dict:
        """Make GET request to Vault API with automatic retry and circuit breaker.

        Retries up to ``max_retry_attempts`` times on connection-level failures,
        then re-raises the original exception.

        Args:
            path: API endpoint path
            params: Optional query parameters
            namespace: Optional namespace path
            timeout: Optional per-request timeout override in seconds

        Returns:
            Response data as dictionary

        Raises:
            VaultAPIError: For API errors
            VaultConnectionError: For connection issues, after retries are exhausted
            VaultPermissionError: For authorization issues
            VaultDataError: For malformed responses
            CircuitBreakerOpenError: When circuit breaker is open
        """
        return self._build_retryer()(self._get_once, path, params, namespace, timeout)

    def _get_once(self, path: str, params: dict, namespace: str, timeout: int | None) -> dict:
        """Single GET attempt, routed through the endpoint's circuit breaker."""
        circuit_breaker = self._get_circuit_breaker(path)
        if circuit_breaker:
            return circuit_breaker.call(super().get, path, params, namespace, timeout)
        return super().get(path, params, namespace, timeout)

    def post(self, path: str, data: dict = None, namespace: str = "", timeout: int | None = None) -> dict:
        """Make POST request to Vault API with automatic retry and circuit breaker.

        Retries up to ``max_retry_attempts`` times on connection-level failures,
        then re-raises the original exception.

        Args:
            path: API endpoint path
            data: Optional request body data
            namespace: Optional namespace path
            timeout: Optional per-request timeout override in seconds

        Returns:
            Response data as dictionary

        Raises:
            VaultAPIError: For API errors
            VaultConnectionError: For connection issues, after retries are exhausted
            VaultPermissionError: For authorization issues
            VaultDataError: For malformed responses
            CircuitBreakerOpenError: When circuit breaker is open
        """
        return self._build_retryer()(self._post_once, path, data, namespace, timeout)

    def _post_once(self, path: str, data: dict, namespace: str, timeout: int | None) -> dict:
        """Single POST attempt, routed through the endpoint's circuit breaker."""
        circuit_breaker = self._get_circuit_breaker(path)
        if circuit_breaker:
            return circuit_breaker.call(super().post, path, data, namespace, timeout)
        return super().post(path, data, namespace, timeout)

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
