import hashlib
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

# Re-export all exceptions from the shared module so existing callers that do
#   from src.common.vault_client import VaultAPIError, ...
# continue to work without changes.
from .exceptions import (  # noqa: F401
    ConfigurationError,
    VaultAPIError,
    VaultConnectionError,
    VaultDataError,
    VaultPermissionError,
)

# Upper bound on how much of a Vault error body is carried in an exception
# message. Exception text reaches the audit log via `error=str(e)`, so the whole
# raw body must never be interpolated verbatim.
_MAX_ERROR_BODY_LENGTH = 500


def _summarise_error_body(response: requests.Response) -> str:
    """Render a Vault error response for an exception message, safely.

    Vault reports failures as ``{"errors": [...]}``. Those strings are the
    useful diagnostic, so they are kept (bounded in length). Anything that is
    not a recognisable Vault error document is described rather than quoted,
    because an arbitrary body may carry token material or wrapped secrets.
    """
    try:
        payload = response.json()
    except (ValueError, json.JSONDecodeError):
        return f"<non-JSON body, {len(response.content or b'')} bytes>"

    if isinstance(payload, dict) and "errors" in payload:
        errors = "; ".join(str(item) for item in payload["errors"]) or "<none>"
        if len(errors) > _MAX_ERROR_BODY_LENGTH:
            errors = errors[:_MAX_ERROR_BODY_LENGTH] + "...[truncated]"
        return errors

    return f"<unrecognised JSON body, {len(response.content or b'')} bytes>"


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
        # raise_on_status=False is what makes the status codes below surface
        # correctly (V2). With the default, an exhausted retry raises
        # urllib3's MaxRetryError — surfacing as requests.exceptions.RetryError,
        # which falls through to the generic "Unexpected error" handler and
        # loses the status code entirely. Returning the response instead lets
        # the explicit status_code checks in get()/post() build a precise
        # VaultAPIError naming the code and Vault's own error strings.
        retry_strategy = Retry(
            total=3,
            backoff_factor=1,
            status_forcelist=[408, 429, 500, 502, 503, 504],
            allowed_methods=["HEAD", "GET", "OPTIONS", "POST"],
            raise_on_status=False,
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

        The cache lives on the instance and each instance holds a single token
        for its lifetime, so the token component is defensive rather than the
        primary isolation mechanism: it keeps entries from colliding if a token
        is ever rotated in place on a live client.

        A SHA-256 digest is used rather than a raw prefix of the token. A short
        prefix is not a fingerprint — tokens sharing a scheme prefix ("hvs.",
        "hvb.") differ in only a few of the first 8 characters — and it also put
        real token material into a dictionary key.
        """
        token_fingerprint = hashlib.sha256(self.vault_token.encode()).hexdigest()[:16] if self.vault_token else ""
        params_str = json.dumps(params, sort_keys=True) if params else ""
        return f"{token_fingerprint}:{namespace}:{path}:{params_str}"

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
    def get_client(self, namespace_path: str = "", timeout: int | None = None):
        """Context manager for creating Vault clients with connection pooling.

        Args:
            namespace_path: Vault namespace for this client.
            timeout: Per-request timeout override in seconds. Falls back to the
                client-wide ``hvac_timeout`` when omitted, so a single heavy
                call (a large activity export, say) can be given more headroom
                without raising the timeout for every other request.
        """
        client = hvac.Client(
            url=self.vault_addr,
            token=self.vault_token,
            namespace=namespace_path,
            verify=not self.vault_skip_verify,
            timeout=self.hvac_timeout if timeout is None else timeout,
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
                    raise VaultConnectionError("Vault cluster is sealed. Please unseal the cluster using 'vault operator unseal' or ensure auto-unseal is properly configured.")

                if not client.is_authenticated():
                    raise VaultConnectionError("Vault client is not authenticated. Please check your VAULT_TOKEN environment variable and ensure the token has not expired or been revoked.")

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

    def get(self, path: str, params: dict = None, namespace: str = "", timeout: int | None = None) -> dict | list:
        """Make GET request to Vault API with caching support.

        Args:
            path: API endpoint path.
            params: Optional query parameters.
            namespace: Optional namespace path.
            timeout: Per-request timeout override in seconds; defaults to the
                client-wide ``hvac_timeout``.

        Returns:
            dict | list: The decoded response body — a dict for regular JSON
                endpoints, a list for NDJSON ones such as the activity export.
                A 204 No Content response yields an empty list.
        """
        # Check cache for cacheable endpoints
        cache_key = self._cache_key(path, namespace, params)
        if self._is_cacheable(path) and cache_key in self.cache:
            self.cache_hits += 1
            self.logger.debug(f"Cache hit for {path} (namespace: {namespace})")
            return self.cache[cache_key]

        self.cache_misses += 1

        try:
            with self.get_client(namespace, timeout=timeout) as client:
                # Remove leading slash and v1 prefix if present. removeprefix,
                # not replace: replace strips "v1/" from anywhere in the path,
                # mangling any mount or namespace that happens to contain it.
                clean_path = path.lstrip("/").removeprefix("v1/")

                response = client.adapter.request("GET", f"v1/{clean_path}", params=params) if params else client.adapter.request("GET", f"v1/{clean_path}")

                # If hvac already parsed the response into a dict, return it directly
                if isinstance(response, dict):
                    result = response
                elif not isinstance(response, requests.Response):
                    raise VaultDataError(f"Expected requests.Response object or dict, but got {type(response)} for GET {path}. Raw response: {response}")
                elif response.status_code == 204:
                    # 204 No Content is Vault's success response for a query that
                    # matched nothing — most visibly the activity/entity export
                    # endpoints over a window with no client records. Treating it
                    # as an error aborted whole runs on quiet periods, so return
                    # the empty result the caller would have got from a 200.
                    self.logger.debug(f"No content (204) for GET {path}; returning empty result")
                    result = []
                elif response.status_code != 200:
                    raise VaultAPIError(f"GET {path} failed with status {response.status_code}: {_summarise_error_body(response)}")
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
        except requests.exceptions.RetryError as e:
            # Adapter-level retries exhausted (V2). Classified as a connection
            # problem so callers' existing VaultConnectionError handling applies.
            raise VaultConnectionError(f"Retries exhausted for GET {path} after repeated retryable responses (see status_forcelist). Check Vault health and load.") from e
        except requests.exceptions.ConnectionError as e:
            raise VaultConnectionError(f"Connection failed for GET {path}. Check network connectivity and Vault address.") from e
        except requests.exceptions.Timeout as e:
            raise VaultConnectionError(f"Request timeout for GET {path}. Consider increasing timeout or check Vault responsiveness.") from e
        except Exception as e:
            raise VaultAPIError(f"Unexpected error on GET {path}: {e}") from e

    def post(self, path: str, data: dict = None, namespace: str = "", timeout: int | None = None) -> dict:
        """Make POST request to Vault API.

        Args:
            path: API endpoint path.
            data: Optional request body.
            namespace: Optional namespace path.
            timeout: Per-request timeout override in seconds; defaults to the
                client-wide ``hvac_timeout``.
        """
        try:
            with self.get_client(namespace, timeout=timeout) as client:
                # See the note in get(): removeprefix, not replace.
                clean_path = path.lstrip("/").removeprefix("v1/")

                response = client.adapter.request("POST", f"{client.url}/v1/{clean_path}", json=data)

                if response.status_code not in [200, 204]:
                    raise VaultAPIError(f"POST {path} failed with status {response.status_code}: {_summarise_error_body(response)}")

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
        except requests.exceptions.RetryError as e:
            # Adapter-level retries exhausted (V2). Classified as a connection
            # problem so callers' existing VaultConnectionError handling applies.
            raise VaultConnectionError(f"Retries exhausted for POST {path} after repeated retryable responses (see status_forcelist). Check Vault health and load.") from e
        except requests.exceptions.ConnectionError as e:
            raise VaultConnectionError(f"Connection failed for POST {path}. Check network connectivity and Vault address.") from e
        except requests.exceptions.Timeout as e:
            raise VaultConnectionError(f"Request timeout for POST {path}. Consider increasing timeout or check Vault responsiveness.") from e
        except Exception as e:
            raise VaultAPIError(f"Unexpected error on POST {path}: {e}") from e
