"""A minimal, read-only HTTP client for the Vault API.

Replaces the parts of hvac the tool used: a namespace-bound client over the
pooled ``requests.Session`` and an exception per HTTP status. There are no
write methods, so the tool's read-only rule is structural: ``request`` issues
only GET (a LIST is a GET with ``?list=true``, which Vault authorises against
the ``list`` capability).

The exception names match hvac's so a caller written against
``hvac.exceptions.Forbidden`` reads the same against ``vault_http.Forbidden``.
"""

# N818 (Error suffix): the exception names deliberately match hvac's.
# ruff: noqa: N818

from __future__ import annotations

import json
from typing import Any

import requests

# Upper bound on how much of a Vault error body is carried in an exception
# message. Exception text reaches the audit log via `error=str(e)`, so the whole
# raw body must never be interpolated verbatim.
_MAX_ERROR_BODY_LENGTH = 500

# sys/health query that answers 200 with a body for every node state, so a
# sealed, standby or DR-secondary node still describes itself.
HEALTH_PARAMS = {
    "standbyok": "true",
    "perfstandbyok": "true",
    "sealedcode": "200",
    "uninitcode": "200",
    "drsecondarycode": "200",
    "performancestandbycode": "200",
    "standbycode": "200",
}

# The only methods request() accepts. Not configurable: adding one is a change
# to the tool's read-only guarantee.
_ALLOWED_METHODS = frozenset({"GET"})


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


def _error_strings(response: requests.Response) -> list[str]:
    try:
        payload = response.json()
    except (ValueError, json.JSONDecodeError):
        return []
    if isinstance(payload, dict) and isinstance(payload.get("errors"), list):
        return [str(item) for item in payload["errors"]]
    return []


class VaultError(Exception):
    """A non-2xx response from Vault.

    ``str(e)`` carries Vault's own ``errors`` text (bounded): the Sentinel
    "unsupported path" heuristic matches on it. ``response`` is kept so callers
    can read the status code without parsing the message.
    """

    def __init__(
        self,
        message: str = "",
        *,
        status: int | None = None,
        errors: list[str] | None = None,
        method: str | None = None,
        path: str | None = None,
        response: requests.Response | None = None,
    ):
        super().__init__(message)
        self.status = status
        self.errors = errors or []
        self.method = method
        self.path = path
        self.response = response

    def __str__(self) -> str:
        message = str(self.args[0]) if self.args else ""
        if self.method and self.path:
            return f"{message}, on {self.method} {self.path}"
        return message


class InvalidRequest(VaultError):
    """HTTP 400."""


class Unauthorized(VaultError):
    """HTTP 401."""


class Forbidden(VaultError):
    """HTTP 403."""


class InvalidPath(VaultError):
    """HTTP 404."""


class RateLimitExceeded(VaultError):
    """HTTP 429."""


class InternalServerError(VaultError):
    """HTTP 500."""


class VaultNotInitialized(VaultError):
    """HTTP 501."""


class BadGateway(VaultError):
    """HTTP 502."""


class VaultDown(VaultError):
    """HTTP 503."""


class UnexpectedError(VaultError):
    """Any other status of 400 or above."""


_STATUS_EXCEPTIONS: dict[int, type[VaultError]] = {
    400: InvalidRequest,
    401: Unauthorized,
    403: Forbidden,
    404: InvalidPath,
    429: RateLimitExceeded,
    500: InternalServerError,
    501: VaultNotInitialized,
    502: BadGateway,
    503: VaultDown,
}


def raise_for_vault_status(response: requests.Response, method: str = "GET", path: str | None = None) -> None:
    """Raise the VaultError subclass for a response of 400 or above; return otherwise."""
    status = response.status_code
    if status < 400:
        return
    cls = _STATUS_EXCEPTIONS.get(status, UnexpectedError)
    raise cls(
        _summarise_error_body(response),
        status=status,
        errors=_error_strings(response),
        method=method,
        path=path,
        response=response,
    )


def clean_path(path: str) -> str:
    """Strip a leading slash and ``v1/`` prefix, and collapse ``//`` as the vault CLI does.

    removeprefix, not replace: replace strips "v1/" from anywhere in the path,
    mangling any mount or namespace that happens to contain it.
    """
    path = path.lstrip("/").removeprefix("v1/")
    while "//" in path:
        path = path.replace("//", "/")
    return path


class NamespacedClient:
    """Read-only Vault client bound to one namespace, over a shared session.

    ``namespace`` is sent as ``X-Vault-Namespace`` only when non-empty; the root
    namespace sends no header. TLS verification is the session's ``verify``.
    """

    def __init__(
        self,
        session: requests.Session,
        addr: str,
        token: str | None,
        namespace: str = "",
        timeout: float | None = 30,
    ):
        self.session = session
        self.addr = addr.rstrip("/")
        self.token = token
        self.namespace = namespace or ""
        self.timeout = timeout

    def request(self, method: str, path: str, params: dict[str, Any] | None = None) -> requests.Response:
        """Send one request and raise the mapped VaultError on a status of 400 or above."""
        method = method.upper()
        if method not in _ALLOWED_METHODS:
            raise ValueError(f"{method} is not allowed: vault-tools issues read-only requests")
        path = clean_path(path)
        headers = {"X-Vault-Request": "true"}
        if self.token:
            headers["X-Vault-Token"] = self.token
        if self.namespace:
            headers["X-Vault-Namespace"] = self.namespace
        response = self.session.request(
            method=method,
            url=f"{self.addr}/v1/{path}",
            params=params,
            headers=headers,
            timeout=self.timeout,
        )
        raise_for_vault_status(response, method, path)
        return response

    def read(self, path: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        """GET a path and decode its JSON object; ``{}`` for 204 or an empty body."""
        response = self.request("GET", path, params=params)
        if response.status_code == 204 or not response.content:
            return {}
        payload = response.json()
        return payload if isinstance(payload, dict) else {}

    def list(self, path: str) -> dict[str, Any]:
        """LIST a path (GET with ``?list=true``); the response dict, keys under ``data.keys``."""
        return self.read(path, params={"list": "true"})
