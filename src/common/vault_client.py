import json
import logging
import os
from contextlib import contextmanager
from typing import NamedTuple
from urllib.parse import urlsplit

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
from .utils import normalise_namespace_path
from .vault_http import HEALTH_PARAMS, NamespacedClient

# HCP Vault Dedicated endpoints (public and private) are served under this
# domain. Vault exposes no API signal for HCP, so the host is the only one: HCP
# behind custom DNS or a proxy reports as "enterprise". From the vault-ops skill.
HCP_HOST_SUFFIX = ".hashicorp.cloud"


def detect_platform(addr: str | None, version: str | None) -> str | None:
    """run.platform: "hcp", "enterprise", "community", or None when the version is unknown.

    The host decides first, because HCP Vault Dedicated also reports a +ent
    version. Only the HCP read profile in cluster health keys on it; rules and
    scoping never do.
    """
    try:
        host = (urlsplit(addr or "").hostname or "").lower()
    except ValueError:
        host = ""
    if host.endswith(HCP_HOST_SUFFIX):
        return "hcp"
    if not isinstance(version, str) or not version:
        return None
    return "enterprise" if "+ent" in version else "community"


class RunScope(NamedTuple):
    """Where the token lives and what it runs against, for findings.json's run block."""

    # "" = root; None = the token was not validated (DR secondary, sealed node).
    token_namespace: str | None = None
    platform: str | None = None


class ConnectionInfo(NamedTuple):
    cluster_name: str
    vault_version: str | None
    # None when sys/health omits the version, so the edition is unknown rather
    # than assumed to be Community.
    is_enterprise: bool | None
    cluster_id: str | None
    # Where the token lives, from lookup-self: "" for root, "admin/" for a token
    # created in a child namespace (the only kind HCP Vault Dedicated issues).
    token_namespace: str = ""
    platform: str | None = None


class VaultClient:
    # Class-level defaults as well as instance values, so Mock(spec=VaultClient)
    # in tests knows the attributes exist.
    namespace: str = ""
    token_namespace: str | None = None
    platform: str | None = None

    def __init__(
        self,
        vault_addr: str = None,
        vault_token: str = None,
        vault_skip_verify: bool = False,
        vault_cacert: str | None = None,
        request_timeout: int = 30,
        pool_connections: int = 10,
        pool_maxsize: int = 20,
        namespace: str | None = None,
    ):
        self.vault_addr = vault_addr or os.environ.get("VAULT_ADDR")
        # Where the run starts (VAULT_NAMESPACE or --namespace; "" = root). A token
        # created in a child namespace must start there or below.
        self.namespace = normalise_namespace_path(namespace)
        # Set by validate_connection(). None until then: a DR secondary or a sealed
        # node is never validated, so where the token lives is unknown there.
        self.token_namespace: str | None = None
        self.platform: str | None = None
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

    @property
    def scoped(self) -> bool:
        """The token lives in a child namespace: root-only cluster data is not this token's to read."""
        return bool(self.token_namespace)

    def run_scope(self) -> RunScope:
        return RunScope(self.token_namespace, self.platform)

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
        initialised, sealed and DR-secondary; auth/token/lookup-self settles
        authentication. A 400, 401 or 403 there means the token is not valid;
        any other failure is reported as such, not blamed on the address.
        """
        try:
            with self.get_client() as client:
                health_status = client.read("sys/health", params=HEALTH_PARAMS)

                if not health_status:
                    raise VaultConnectionError(f"Invalid health status response: {health_status}")

                # Initialised first: an uninitialised node also reports sealed,
                # and "unseal" is no use before "vault operator init".
                if health_status.get("initialized") is False:
                    raise VaultConnectionError("Vault cluster is not initialized. Please initialize the cluster using 'vault operator init'.")

                if health_status.get("sealed") is True:
                    raise VaultConnectionError("Vault cluster is sealed. Please unseal the cluster using 'vault operator unseal' or ensure auto-unseal is properly configured.")

                if health_status.get("replication_dr_mode") == "secondary":
                    raise VaultConnectionError("This node is a DR secondary, which answers only unauthenticated endpoints. Run cluster-audit against it, or point VAULT_ADDR at the primary.")

            # In the start namespace, so a token created in a child namespace
            # validates; a root-namespace token may look itself up from anywhere.
            with self.get_client(self.namespace) as ns_client:
                try:
                    lookup = ns_client.read("auth/token/lookup-self")
                except (vault_http.InvalidRequest, vault_http.Unauthorized, vault_http.Forbidden):
                    where = self.namespace.rstrip("/") or "/"
                    raise VaultConnectionError(
                        f"Vault client is not authenticated in namespace {where}. Check VAULT_TOKEN has not expired or been revoked. "
                        "A token created in a child namespace needs VAULT_NAMESPACE (or --namespace) set to that namespace or one below it "
                        "(e.g. VAULT_NAMESPACE=admin on HCP Vault Dedicated)."
                    ) from None
                except vault_http.VaultError as e:
                    raise VaultConnectionError(f"Could not verify the token: auth/token/lookup-self returned HTTP {e.status} ({e}).") from e

            data = lookup.get("data") if isinstance(lookup, dict) and isinstance(lookup.get("data"), dict) else {}
            namespace_path = data.get("namespace_path")
            self.token_namespace = normalise_namespace_path(namespace_path if isinstance(namespace_path, str) else "")
            cluster_name = health_status.get("cluster_name", "unknown")
            vault_version = health_status.get("version")
            is_enterprise = "+ent" in vault_version if vault_version else None
            cluster_id = health_status.get("cluster_id")
            self.platform = detect_platform(self.vault_addr, vault_version)
            self.logger.info(f"Connected to Vault cluster: {cluster_name}")
            return ConnectionInfo(cluster_name, vault_version, is_enterprise, cluster_id, self.token_namespace, self.platform)

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
        except requests.exceptions.ConnectionError as e:
            raise VaultConnectionError(f"Connection failed for GET {path}. Check network connectivity and Vault address.") from e
        except requests.exceptions.Timeout as e:
            raise VaultConnectionError(f"Request timeout for GET {path}. Consider increasing timeout or check Vault responsiveness.") from e
        except Exception as e:
            raise VaultAPIError(f"Unexpected error on GET {path}: {e}") from e
