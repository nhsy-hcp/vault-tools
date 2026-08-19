"""Fixtures for the markdown report tests.

The mount objects here mirror the shape Vault actually returns (verified against
the real output files in outputs/) rather than the minimal {"type": ...} stubs
used elsewhere, because the report reads config, deprecation_status and local.
"""

import pytest

from src.namespace_audit.main import AuditData, AuditStats


def mount(mount_type, **overrides):
    """Build a realistic mount object, overridable per test."""
    data = {
        "accessor": f"auth_{mount_type}_00000000",
        "config": {
            "default_lease_ttl": 0,
            "force_no_cache": False,
            "max_lease_ttl": 0,
            "token_type": "default-service",
        },
        "deprecation_status": "supported",
        "description": "",
        "external_entropy_access": False,
        "local": False,
        "options": None,
        "plugin_version": "",
        "running_plugin_version": "v1.0.0+builtin.vault",
        "seal_wrap": False,
        "type": mount_type,
        "uuid": "00000000-0000-0000-0000-000000000000",
    }
    config_overrides = overrides.pop("config", {})
    data.update(overrides)
    data["config"] = {**data["config"], **config_overrides}
    return data


@pytest.fixture
def clean_data():
    """A cluster with nothing worth flagging: root plus one populated child."""
    data = AuditData()
    data.namespaces = {"team-a": {"id": "abc12", "path": "team-a/", "custom_metadata": {"owner": "platform"}}}
    data.auth_methods = {
        "": {"token/": mount("token"), "oidc/": mount("oidc")},
        "team-a": {"token/": mount("token"), "approle/": mount("approle")},
    }
    data.secret_engines = {
        "": {"cubbyhole/": mount("cubbyhole"), "identity/": mount("identity"), "kv/": mount("kv")},
        "team-a": {"ns_cubbyhole/": mount("ns_cubbyhole"), "pki/": mount("pki")},
    }
    return data


@pytest.fixture
def flagged_data():
    """A cluster triggering one of every finding type."""
    data = AuditData()
    data.namespaces = {
        "team-a": {"id": "abc12", "path": "team-a/", "custom_metadata": {}},
        "team-a/sub": {"id": "def34", "path": "sub/", "custom_metadata": {}},
        "empty": {"id": "ghi56", "path": "empty/", "custom_metadata": {}},
    }
    data.auth_methods = {
        "": {
            "token/": mount("token"),
            "legacy/": mount("aws", deprecation_status="pending-removal"),
            "public/": mount("oidc", config={"listing_visibility": "unauth"}),
        },
        # token-only: triggers the "no external auth" finding
        "team-a": {"token/": mount("token")},
        "team-a/sub": {"token/": mount("token"), "userpass/": mount("userpass")},
        "empty": {"token/": mount("token")},
    }
    data.secret_engines = {
        "": {"kv/": mount("kv", config={"max_lease_ttl": 90 * 24 * 3600})},
        "team-a": {"transit/": mount("transit", local=True)},
        "team-a/sub": {"kv/": mount("kv")},
        # built-ins only: triggers the "empty namespace" finding
        "empty": {"cubbyhole/": mount("cubbyhole"), "identity/": mount("identity")},
    }
    return data


def sentinel_policy(name, **overrides):
    """Build a Sentinel policy the shape Vault returns from a read.

    Defaults to the innocuous case — hard-mandatory with a real rule body — so a
    test only has to state the one attribute it is exercising.
    """
    data = {
        "name": name,
        "enforcement_level": "hard-mandatory",
        "policy": 'import "time"\n\nmain = rule { time.now.unix > 0 }\n',
    }
    data.update(overrides)
    return data


@pytest.fixture
def sentinel_data():
    """A cluster with one Sentinel policy per finding branch.

    Deliberately separate from clean_data/flagged_data: those two carry
    finding-count assertions that would silently absorb a regression here.
    """
    data = AuditData()
    data.namespaces = {"team-a": {"id": "abc12", "path": "team-a/", "custom_metadata": {}}}
    data.auth_methods = {
        "": {"token/": mount("token"), "oidc/": mount("oidc")},
        "team-a": {"token/": mount("token"), "approle/": mount("approle")},
    }
    data.secret_engines = {
        "": {"kv/": mount("kv")},
        "team-a": {"pki/": mount("pki")},
    }
    data.egp_policies = {
        # The control: hard-mandatory, real body, narrow path — no finding.
        "": {"require-cidr": sentinel_policy("require-cidr", paths=["auth/approle/login"])},
        "team-a": {
            "audit-only": sentinel_policy("audit-only", enforcement_level="advisory", paths=["secret/data/*"]),
            "catch-all": sentinel_policy("catch-all", paths=["*"]),
            "placeholder": sentinel_policy("placeholder", policy="# TODO: write this properly\nmain = rule { true }\n", paths=["sys/mounts"]),
        },
    }
    data.rgp_policies = {
        "team-a": {"overridable": sentinel_policy("overridable", enforcement_level="soft-mandatory")},
    }
    return data


@pytest.fixture
def finished_stats():
    """Stats from a completed, fully successful run."""
    stats = AuditStats()
    stats.start()
    stats.processed_count = 2
    stats.discovered_count = 2
    stats.finish()
    return stats


@pytest.fixture
def denied_stats():
    """Stats from a run that hit both a denial and an error."""
    stats = AuditStats()
    stats.start()
    stats.processed_count = 3
    stats.increment_forbidden("restricted/", "child namespaces (subtree not audited)")
    stats.increment_errors("broken/", "connection reset")
    stats.finish()
    return stats
