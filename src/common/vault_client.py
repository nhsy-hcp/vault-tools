
import hvac
import os
import logging
import urllib3
import json
import requests
from contextlib import contextmanager

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
    def __init__(self, vault_addr: str = None, vault_token: str = None, vault_skip_verify: bool = False, hvac_timeout: int = 30):
        self.vault_addr = vault_addr or os.environ.get('VAULT_ADDR')
        self.vault_token = vault_token or os.environ.get('VAULT_TOKEN')
        self.vault_skip_verify = vault_skip_verify
        self.hvac_timeout = hvac_timeout
        self.logger = logging.getLogger(__name__)

        if not self.vault_addr or not self.vault_token:
            raise ValueError("VAULT_ADDR and VAULT_TOKEN must be provided or set as environment variables.")

        if self.vault_skip_verify:
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    @contextmanager
    def get_client(self, namespace_path: str = ""):
        """Context manager for creating Vault clients."""
        client = hvac.Client(
            url=self.vault_addr,
            token=self.vault_token,
            namespace=namespace_path,
            verify=not self.vault_skip_verify,
            timeout=self.hvac_timeout
        )
        yield client

    def validate_connection(self) -> str:
        """Validate Vault connection and return cluster name."""
        try:
            with self.get_client() as client:
                health_status = client.sys.read_health_status(
                    method='GET',
                    sealed_code=200,
                    performance_standby_code=200,
                    uninit_code=200
                )

                if not isinstance(health_status, dict):
                    raise VaultConnectionError(f"Invalid health status response: {health_status}")

                if client.sys.is_sealed():
                    raise VaultConnectionError(
                        "Vault cluster is sealed. Please unseal the cluster using 'vault operator unseal' "
                        "or ensure auto-unseal is properly configured."
                    )

                if not client.is_authenticated():
                    raise VaultConnectionError(
                        "Vault client is not authenticated. Please check your VAULT_TOKEN environment variable "
                        "and ensure the token has not expired or been revoked."
                    )

                if not client.sys.is_initialized():
                    raise VaultConnectionError(
                        "Vault cluster is not initialized. Please initialize the cluster using 'vault operator init'."
                    )

                cluster_name = health_status.get('cluster_name', 'unknown')
                self.logger.info(f"Connected to Vault cluster: {cluster_name}")
                return cluster_name

        except hvac.exceptions.VaultError as e:
            error_msg = f"Vault API error: {e}. Please check your VAULT_ADDR ({self.vault_addr}) and network connectivity."
            raise VaultConnectionError(error_msg) from e
        except Exception as e:
            error_msg = f"Connection error: {e}. Please verify VAULT_ADDR ({self.vault_addr}) is correct and accessible."
            raise VaultConnectionError(error_msg) from e

    def get(self, path: str, params: dict = None, namespace: str = "") -> dict:
        """Make GET request to Vault API."""
        try:
            with self.get_client(namespace) as client:
                # Remove leading slash and v1 prefix if present
                clean_path = path.lstrip('/').replace('v1/', '')
                
                if params:
                    response = client.adapter.request('GET', f'v1/{clean_path}', params=params)
                else:
                    response = client.adapter.request('GET', f'v1/{clean_path}')
                
                # If hvac already parsed the response into a dict, return it directly
                if isinstance(response, dict):
                    return response

                if not isinstance(response, requests.Response):
                    raise VaultDataError(f"Expected requests.Response object or dict, but got {type(response)} for GET {path}. Raw response: {response}")

                if response.status_code != 200:
                    raise VaultAPIError(f"GET {path} failed with status {response.status_code}: {response.text}")
                
                try:
                    # Attempt to parse as a single JSON object first
                    return response.json()
                except json.JSONDecodeError as e:
                    # If it fails with 'Extra data', assume it's NDJSON and parse line by line
                    if "Extra data" in str(e):
                        self.logger.debug("JSONDecodeError: Extra data. Attempting NDJSON parsing.")
                        return [json.loads(line) for line in response.text.strip().split('\n') if line]
                    else:
                        # Re-raise other JSONDecodeErrors
                        raise VaultDataError(f"Failed to parse JSON from {path}: {e}") from e
                
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
                clean_path = path.lstrip('/').replace('v1/', '')
                
                response = client.adapter.request('POST', f'{client.url}/v1/{clean_path}', json=data)
                
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
