"""A namespace-aware fake Vault: routes keyed by (namespace header, path)."""

from contextlib import contextmanager
from typing import Any
from unittest.mock import Mock

import hvac

from src.common.vault_client import ConnectionInfo


def entity(entity_id, name="user", aliases=None, policies=(), disabled=False, groups=(), metadata=None):
    # One alias named after the entity by default, so separate entities never
    # share an alias name (VT-ID-005) unless a test says so.
    aliases = ((f"login-{entity_id}", "userpass/", "userpass"),) if aliases is None else aliases
    return {
        "id": entity_id,
        "name": name,
        "disabled": disabled,
        "policies": list(policies),
        "group_ids": list(groups),
        "metadata": metadata or {},
        "aliases": [{"name": n, "mount_path": p, "mount_type": t, "metadata": {}} for n, p, t in aliases],
    }


def fake_identity_client(tree: dict[str, list[str]], entities: dict[str, list[dict]], extra: dict[tuple[str, str], Any] | None = None) -> Mock:
    """``tree`` maps a namespace header ("" or "a/") to child names; ``entities`` maps it to entity bodies."""
    routes: dict[tuple[str, str], Any] = dict(extra or {})
    for ns, items in entities.items():
        if items:
            routes.setdefault((ns, "identity/entity/id"), {"data": {"keys": [e["id"] for e in items], "key_info": {e["id"]: {"name": e["name"], "aliases": e["aliases"]} for e in items}}})
        for e in items:
            routes.setdefault((ns, f"identity/entity/id/{e['id']}"), {"data": e})
    calls: list[tuple[str, str]] = []

    @contextmanager
    def get_client(namespace_path="", **_kwargs):
        client = Mock()

        def get(url, params=None):
            path = url.removeprefix("/v1/")
            calls.append((namespace_path, path))
            value = routes.get((namespace_path, path))
            if value is None:
                raise hvac.exceptions.InvalidPath()
            if isinstance(value, BaseException):
                raise value
            return value

        client.adapter.get.side_effect = get
        children = tree.get(namespace_path)
        if isinstance(children, BaseException):
            client.sys.list_namespaces.side_effect = children
        elif children:
            client.sys.list_namespaces.return_value = {"data": {"key_info": {f"{c}/": {} for c in children}}}
        else:
            client.sys.list_namespaces.side_effect = hvac.exceptions.InvalidPath()
        yield client

    vault = Mock()
    vault.vault_addr = "https://vault.example.com:8200"
    vault.get_client.side_effect = get_client
    vault.validate_connection.return_value = ConnectionInfo("idc", "1.20.1+ent", True, "id")
    vault.calls = calls
    return vault
