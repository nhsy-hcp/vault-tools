import json
import logging
import os
from contextlib import contextmanager
from typing import NamedTuple

import requests
import urllib3
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from . import vault_http

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
from .vault_http import HEALTH_PARAMS, NamespacedClient, _summarise_error_body


class ConnectionInfo(NamedTuple):
    cluster_name: str
    vault_version: str | None
    # None when sys/health omits the version, so the edition is unknown rather
    # than assumed to be Community.
    is_enterprise: bool | None
    cluster_id: str | None


class VaultClient:
    def __init__(
        self,
        vault_addr: str = None,
        vault_token: str = None,
        vault_skip_verify: bool = False,
        vault_cacert: str | None = None,
        request_timeout: int = 30,
        pool_connections: int = 10,
        pool_maxsize: int = 20,
    ):
        self.vault_addr = vault_addr or os.environ.get("VAULT_ADDR")
        self.vault_token = vault_token or os.environ.get("VAULT_TOKEN")
        self.vault_skip_verify = vault_skip_verify
        self.vault_cacert = vault_cacert or None
        # What requests' `verify` takes: False skips verification, a path
        # verifies against that CA bundle, True uses the system store. Skip wins
        # over a CA bundle, as it does in the vault CLI.
        self.verify: bool | str = False if vault_skip_verify else (self.vault_cacert or True)
        self.request_timeout = request_timeout
        self.logger = logging.getLogger(__name__)

        if not self.vault_addr or not self.vault_token:
            raise ValueError("VAULT_ADDR and VAULT_TOKEN must be provided or set as environment variables.")

        if self.vault_skip_verify:
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

        # Initialize connection pooling session
        self.session = requests.Session()
        # TLS verification lives on the session, which every request goes
        # through: NamespacedClient never passes its own `verify`.
        self.session.verify = self.verify
        # raise_on_status=False is what makes the status codes below surface
        # correctly (V2). With the default, an exhausted retry raises
        # urllib3's MaxRetryError — surfacing as requests.exceptions.RetryError,
        # which falls through to the generic "Unexpected error" handler and
        # loses the status code entirely. Returning the response instead lets
        # the explicit status_code checks in get() build a precise
        # VaultAPIError naming the code and Vault's own error strings.
        retry_strategy = Retry(
            total=3,
            backoff_factor=1,
            status_forcelist=[408, 429, 500, 502, 503, 504],
            allowed_methods=["HEAD", "GET", "OPTIONS"],
            raise_on_status=False,
        )
        adapter = HTTPAdapter(
            pool_connections=pool_connections,
            pool_maxsize=pool_maxsize,
            max_retries=retry_strategy,
        )
        self.session.mount("https://", adapter)
        self.session.mount("http://", adapter)

        self.logger.debug(f"VaultClient initialized with connection pool (connections={pool_connections}, maxsize={pool_maxsize})")

    @contextmanager
    def get_client(self, namespace_path: str = "", timeout: int | None = None):
        """Context manager for creating Vault clients with connection pooling.

        Args:
            namespace_path: Vault namespace for this client.
            timeout: Per-request timeout override in seconds. Falls back to the
                client-wide ``request_timeout`` when omitted, so a single heavy
                call (a large activity export, say) can be given more headroom
                without raising the timeout for every other request.
        """
        yield NamespacedClient(
            self.session,
            self.vault_addr,
            self.vault_token,
            namespace=namespace_path,
            timeout=self.request_timeout if timeout is None else timeout,
        )

    def validate_connection(self) -> ConnectionInfo:
        """Validate Vault connection and return connection information.

        One sys/health read (answering 200 for every node state) settles
        sealed and initialised; auth/token/lookup-self settles authentication,
        a 403 meaning the token is not valid.
        """
        try:
            with self.get_client() as client:
                health_status = client.read("sys/health", params=HEALTH_PARAMS)

                if not health_status:
                    raise VaultConnectionError(f"Invalid health status response: {health_status}")

                if health_status.get("sealed") is True:
                    raise VaultConnectionError("Vault cluster is sealed. Please unseal the cluster using 'vault operator unseal' or ensure auto-unseal is properly configured.")

                try:
                    client.read("auth/token/lookup-self")
                except vault_http.Forbidden:
                    raise VaultConnectionError("Vault client is not authenticated. Please check your VAULT_TOKEN environment variable and ensure the token has not expired or been revoked.") from None

                if health_status.get("initialized") is False:
                    raise VaultConnectionError("Vault cluster is not initialized. Please initialize the cluster using 'vault operator init'.")

                cluster_name = health_status.get("cluster_name", "unknown")
                vault_version = health_status.get("version")
                is_enterprise = "+ent" in vault_version if vault_version else None
                cluster_id = health_status.get("cluster_id")
                self.logger.info(f"Connected to Vault cluster: {cluster_name}")
                return ConnectionInfo(cluster_name, vault_version, is_enterprise, cluster_id)

        except VaultConnectionError:
            raise
        except vault_http.VaultError as e:
            error_msg = f"Vault API error: {e}. Please check your VAULT_ADDR ({self.vault_addr}) and network connectivity."
            raise VaultConnectionError(error_msg) from e
        except Exception as e:
            error_msg = f"Connection error: {e}. Please verify VAULT_ADDR ({self.vault_addr}) is correct and accessible."
            raise VaultConnectionError(error_msg) from e

    def get(self, path: str, params: dict = None, namespace: str = "", timeout: int | None = None) -> dict | list:
        """Make a GET request to the Vault API.

        Args:
            path: API endpoint path.
            params: Optional query parameters.
            namespace: Optional namespace path.
            timeout: Per-request timeout override in seconds; defaults to the
                client-wide ``request_timeout``.

        Returns:
            dict | list: The decoded response body — a dict for regular JSON
                endpoints, a list for NDJSON ones such as the activity export.
                A 204 No Content response yields an empty list.
        """
        try:
            with self.get_client(namespace, timeout=timeout) as client:
                # A leading slash and v1/ prefix are stripped by the client.
                response = client.request("GET", path, params=params)

                if response.status_code == 204:
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

                return result

        except vault_http.Forbidden as e:
            raise VaultPermissionError(f"Access denied to {path}. Check token permissions for this path.") from e
        except vault_http.InvalidPath as e:
            raise VaultAPIError(f"Invalid path {path}: {e}. Verify the path exists and is accessible.") from e
        except vault_http.VaultError as e:
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
