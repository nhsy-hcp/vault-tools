"""Identity entity collection for `identity-audit`, ported from the vault-ops skill.

Entities are read per namespace with their aliases, policies and group counts.
Names, metadata and alias names can hold emails, usernames and AppRole
role_ids, so they are collected but only written out under ``--list``; every
other output carries counts and entity IDs.

Never raises: denials and errors are recorded per namespace on
``IdentityCoverage`` and the walk continues.
"""

from __future__ import annotations

import logging
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import Any

import hvac
import requests

from src.cluster_audit.collector import RawReader, sanitise_error
from src.common.vault_client import VaultClient

logger = logging.getLogger(__name__)


@dataclass
class IdentityCoverage:
    """``denied`` holds (namespace, scope) and ``errors`` (namespace, message), as AuditStats does."""

    denied: list[tuple[str, str]] = field(default_factory=list)
    errors: list[tuple[str, str]] = field(default_factory=list)
    namespaces_processed: int = 0

    @property
    def complete(self) -> bool:
        return not self.denied and not self.errors


@dataclass
class Entity:
    id: str
    name: str
    namespace: str
    # None when the entity body could not be read (the listing still named it).
    disabled: bool | None
    policies: list[str]
    group_count: int | None
    aliases: list[dict[str, Any]]  # {name, mount_path, mount_type, metadata}
    metadata: dict[str, Any] = field(default_factory=dict)
    last_update_time: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """The per-entity row. Written only with --list: it carries names and metadata."""
        return {
            "id": self.id,
            "name": self.name,
            "disabled": self.disabled,
            "metadata": dict(sorted(self.metadata.items())),
            "alias_count": len(self.aliases),
            "aliases": self.aliases,
            "policies": self.policies,
            "group_count": self.group_count,
            "last_update_time": self.last_update_time,
        }


def _api_namespace(stored: str) -> str:
    """Stored keys have no trailing slash ("" is root); the namespace header wants one."""
    return f"{stored}/" if stored else ""


def discover_namespaces(vault_client: VaultClient, workers: int = 4, coverage: IdentityCoverage | None = None) -> list[str]:
    """The namespace tree from root, using only LIST sys/namespaces.

    Used when identity-audit runs on its own; full-audit passes the list the
    namespace walk already found instead. Deliberately not the walk itself:
    that one also collects mounts, policies and Sentinel, and drives a
    progress bar and rate limiting this needs none of.
    """
    coverage = coverage if coverage is not None else IdentityCoverage()

    def children(ns: str) -> list[str]:
        try:
            with vault_client.get_client(_api_namespace(ns)) as client:
                keys = (client.sys.list_namespaces().get("data") or {}).get("key_info") or {}
        except hvac.exceptions.InvalidPath:
            return []
        except hvac.exceptions.Forbidden:
            coverage.denied.append((ns, "child namespaces (subtree not audited)"))
            return []
        except Exception as e:
            coverage.errors.append((ns, sanitise_error(e)))
            return []
        return [f"{ns}/{name.strip('/')}" if ns else name.strip("/") for name in keys]

    found, level = [""], [""]
    while level:
        with ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
            level = sorted(c for result in pool.map(children, level) for c in result if c not in found)
        found.extend(level)
    return found


def _alias_rows(aliases: list[dict[str, Any]] | None) -> list[dict[str, Any]]:
    rows = (
        {
            "name": a.get("name"),
            "mount_path": a.get("mount_path") or None,
            "mount_type": a.get("mount_type") or None,
            "metadata": dict(sorted((a.get("metadata") or {}).items())),
        }
        for a in aliases or []
    )
    return sorted(rows, key=lambda r: (r["mount_path"] or "", r["name"] or ""))


def collect_entities(
    vault_client: VaultClient,
    namespaces: list[str],
    workers: int = 4,
    coverage: IdentityCoverage | None = None,
) -> tuple[dict[str, list[Entity]], IdentityCoverage]:
    """Entities per namespace (stored keys, "" for root), with aliases and metadata."""
    coverage = coverage if coverage is not None else IdentityCoverage()

    def one_namespace(ns: str) -> tuple[str, list[Entity]]:
        try:
            with vault_client.get_client(_api_namespace(ns)) as client:
                reader = RawReader(client)
                try:
                    listing = reader.get("identity/entity/id", params={"list": "true"})
                except hvac.exceptions.InvalidPath:
                    return ns, []  # no entities: Vault 404s an empty LIST
                except hvac.exceptions.Forbidden:
                    coverage.denied.append((ns, "identity entities"))
                    return ns, []
                key_info = (listing.get("data") or {}).get("key_info") or {}
                entities, denied, error = [], False, None
                for entity_id in sorted(key_info):
                    info = key_info[entity_id] or {}
                    try:
                        body: dict[str, Any] | None = reader.data(f"identity/entity/id/{entity_id}")
                    except hvac.exceptions.InvalidPath:
                        # Deleted between the LIST and the read: it no longer
                        # exists, so it is neither counted nor a gap.
                        continue
                    except hvac.exceptions.Forbidden:
                        # The listing still names it, so the entity is counted;
                        # one access-gap row per namespace, not one per entity.
                        body, denied = None, True
                    except (hvac.exceptions.VaultError, requests.exceptions.RequestException) as e:
                        # A 5xx or timeout is not a token problem: report it as
                        # an error, once per namespace, so nobody widens a policy.
                        body = None
                        error = error or f"identity entity details: {sanitise_error(e)}"
                    source = body or info
                    entities.append(
                        Entity(
                            id=entity_id,
                            name=source.get("name") or info.get("name") or entity_id,
                            namespace=ns,
                            disabled=bool(body.get("disabled")) if body is not None else None,
                            policies=sorted(body.get("policies") or []) if body is not None else [],
                            group_count=len(body.get("group_ids") or []) if body is not None else None,
                            aliases=_alias_rows(source.get("aliases")),
                            metadata=dict(body.get("metadata") or {}) if body is not None else {},
                            last_update_time=body.get("last_update_time") if body is not None else None,
                        )
                    )
                if denied:
                    coverage.denied.append((ns, "identity entity details"))
                if error:
                    coverage.errors.append((ns, error))
                return ns, entities
        except Exception as e:
            coverage.errors.append((ns, sanitise_error(e)))
            return ns, []

    with ThreadPoolExecutor(max_workers=max(1, workers)) as pool:
        results = dict(pool.map(one_namespace, namespaces))
    coverage.namespaces_processed = len(namespaces)
    return results, coverage


def read_activity(vault_client: VaultClient, path: str, coverage: IdentityCoverage) -> dict[str, Any] | None:
    """Activity-log read at root. {} when nothing is recorded; None when denied or failed."""
    try:
        with vault_client.get_client() as client:
            return RawReader(client).data(path)
    except hvac.exceptions.Forbidden:
        coverage.denied.append(("", path))
    except hvac.exceptions.InvalidPath:
        return {}
    except Exception as e:
        coverage.errors.append(("", sanitise_error(e)))
    return None


def _client_count(block: dict[str, Any] | None, key: str = "clients") -> int:
    return int((block or {}).get(key) or 0)


def active_entity_clients(activity: dict[str, Any] | None, current: dict[str, Any] | None = None) -> dict[str, int] | None:
    """Active entity clients per namespace: the higher of the billing period and the current month.

    None when no activity is recorded at all (log disabled, or a new cluster),
    so VT-ID-004 is never judged against an empty log.
    """
    if activity is None or (not _client_count(activity.get("total")) and not _client_count(current)):
        return None
    active: dict[str, int] = {}
    for rows in (activity.get("by_namespace") or [], (current or {}).get("by_namespace") or []):
        for row in rows:
            ns = (row.get("namespace_path") or "").strip().strip("/")
            active[ns] = max(active.get(ns, 0), _client_count(row.get("counts"), "entity_clients"))
    return active
