"""Mount, lease and Sentinel rules ported from the vault-ops skill.

VT-MOUNT-004/005/006, VT-LEASE-001 and VT-SNT-005/006/007. Each rule has a case
that fires, its nearest case that must not, and the default state, which must
never fire — that is the noise these checks are tuned against.
"""

from src.namespace_audit.main import AuditData
from src.namespace_audit.report import (
    DEFAULT_LEASE_TTL_WARNING_SECONDS,
    MOUNT_SPRAWL_THRESHOLD,
    collect_findings,
    render_findings,
)
from tests.namespace_audit.report_fixtures import mount, sentinel_policy

HOUR = 3600


def _data(auth=None, secrets=None, egp=None, rgp=None):
    data = AuditData()
    data.auth_methods = auth if auth is not None else {"": {"token/": mount("token"), "oidc/": mount("oidc")}}
    data.secret_engines = secrets if secrets is not None else {"": {"pki/": mount("pki")}}
    data.egp_policies = egp or {}
    data.rgp_policies = rgp or {}
    return data


def _rules(data, rule_id, **kwargs):
    return [f for f in collect_findings(data, **kwargs) if f.rule_id == rule_id]


class TestMountDefaultLeaseTtl:
    def test_fires_above_threshold(self):
        data = _data(secrets={"": {"db/": mount("database", config={"default_lease_ttl": 2000 * HOUR})}})
        [f] = _rules(data, "VT-MOUNT-004")
        assert f.mount == "db/"
        assert f.evidence["default_lease_ttl_seconds"] == 2000 * HOUR
        assert "2000h" in f.detail

    def test_threshold_itself_does_not_fire(self):
        data = _data(secrets={"": {"db/": mount("database", config={"default_lease_ttl": DEFAULT_LEASE_TTL_WARNING_SECONDS})}})
        assert not _rules(data, "VT-MOUNT-004")

    def test_inherited_zero_never_fires(self):
        assert not _rules(_data(), "VT-MOUNT-004")

    def test_applies_to_auth_mounts_too(self):
        data = _data(auth={"": {"token/": mount("token"), "approle/": mount("approle", config={"default_lease_ttl": 1000 * HOUR})}})
        [f] = _rules(data, "VT-MOUNT-004")
        assert f.object_kind == "auth_mount"


class TestMountSprawl:
    def _many(self, mount_type, count):
        return {f"{mount_type}-{i}/": mount(mount_type) for i in range(count)}

    def test_fires_above_threshold_once_per_namespace_and_kind(self):
        secrets = {"team/": {**self._many("pki", MOUNT_SPRAWL_THRESHOLD + 1), **self._many("transit", MOUNT_SPRAWL_THRESHOLD + 5)}}
        [f] = _rules(_data(secrets=secrets), "VT-MOUNT-005")
        assert f.namespace == "team/"
        assert f.object_kind == "secrets_mount"
        assert f.evidence["mounts_by_type"] == {"pki": MOUNT_SPRAWL_THRESHOLD + 1, "transit": MOUNT_SPRAWL_THRESHOLD + 5}
        assert f.mount == "—"

    def test_threshold_itself_does_not_fire(self):
        assert not _rules(_data(secrets={"": self._many("pki", MOUNT_SPRAWL_THRESHOLD)}), "VT-MOUNT-005")

    def test_builtin_mounts_are_not_counted(self):
        secrets = {"": {f"cubbyhole-{i}/": mount("cubbyhole") for i in range(MOUNT_SPRAWL_THRESHOLD + 5)}}
        assert not _rules(_data(secrets=secrets), "VT-MOUNT-005")


class TestKvVersion1:
    def test_kv_without_version_option_is_v1(self):
        data = _data(secrets={"": {"old/": mount("kv", options=None)}})
        [f] = _rules(data, "VT-MOUNT-006")
        assert f.mount == "old/"

    def test_explicit_version_1_and_generic_fire(self):
        data = _data(secrets={"": {"a/": mount("kv", options={"version": "1"}), "b/": mount("generic", options=None)}})
        assert sorted(f.mount for f in _rules(data, "VT-MOUNT-006")) == ["a/", "b/"]

    def test_kv_v2_does_not_fire(self):
        assert not _rules(_data(secrets={"": {"kv/": mount("kv", options={"version": "2"})}}), "VT-MOUNT-006")


class TestClusterDefaultLeaseTtl:
    def test_fires_above_threshold(self):
        [f] = _rules(_data(), "VT-LEASE-001", system_default_lease_ttl=1000 * HOUR)
        assert f.object_kind == "cluster"
        assert f.evidence["default_lease_ttl_seconds"] == 1000 * HOUR

    def test_unknown_or_default_does_not_fire(self):
        for value in (None, 0, DEFAULT_LEASE_TTL_WARNING_SECONDS):
            assert not _rules(_data(), "VT-LEASE-001", system_default_lease_ttl=value)


class TestSentinelDrift:
    def test_same_name_with_different_bodies_is_one_finding(self):
        egp = {
            "a": {"deny-x": sentinel_policy("deny-x", paths=["x"])},
            "b": {"deny-x": sentinel_policy("deny-x", paths=["x"])},
            "c": {"deny-x": sentinel_policy("deny-x", paths=["x"], policy='main = rule { request.path is "x" }\n')},
        }
        [f] = _rules(_data(egp=egp), "VT-SNT-005")
        assert (f.namespace, f.mount, f.object_kind) == ("", "deny-x", "egp_policy")
        assert f.evidence["variants"] == 2
        assert f.evidence["outliers"] == 1
        assert f.evidence["examples"] == ["c/"]

    def test_identical_copies_do_not_fire(self):
        egp = {ns: {"deny-x": sentinel_policy("deny-x", paths=["x"])} for ns in ("a", "b", "c")}
        assert not _rules(_data(egp=egp), "VT-SNT-005")

    def test_unreadable_bodies_are_not_counted_as_different(self):
        egp = {
            "a": {"deny-x": sentinel_policy("deny-x", paths=["x"])},
            "b": {"deny-x": {"name": "deny-x", "read_error": "permission denied"}},
        }
        assert not _rules(_data(egp=egp), "VT-SNT-005")

    def test_egp_and_rgp_with_the_same_name_are_not_compared(self):
        egp = {"a": {"p": sentinel_policy("p", paths=["x"])}}
        rgp = {"b": {"p": sentinel_policy("p", policy="main = rule { false }\n")}}
        assert not _rules(_data(egp=egp, rgp=rgp), "VT-SNT-005")


class TestSentinelAlwaysFalse:
    def test_hard_mandatory_false_fires_with_paths(self):
        egp = {"a": {"lockout": sentinel_policy("lockout", paths=["*"], policy='# deny all\nimport "time"\nmain = rule { false }\n')}}
        [f] = _rules(_data(egp=egp), "VT-SNT-006")
        assert f.severity == "Medium"
        assert f.evidence["paths"] == ["*"]
        assert "`*`" in f.detail

    def test_bare_false_main_fires_for_rgp(self):
        rgp = {"a": {"lockout": sentinel_policy("lockout", policy="main = false\n")}}
        [f] = _rules(_data(rgp=rgp), "VT-SNT-006")
        assert "paths" not in f.evidence

    def test_overridable_levels_do_not_fire(self):
        rgp = {"a": {"s": sentinel_policy("s", enforcement_level="soft-mandatory", policy="main = rule { false }\n")}}
        assert not _rules(_data(rgp=rgp), "VT-SNT-006")

    def test_real_rule_does_not_fire(self):
        rgp = {"a": {"r": sentinel_policy("r")}}
        assert not _rules(_data(rgp=rgp), "VT-SNT-006")


class TestSentinelHttpImport:
    def test_http_import_fires(self):
        rgp = {"a": {"ext": sentinel_policy("ext", policy='import "http"\nimport "strings"\nmain = rule { true }\n')}}
        [f] = _rules(_data(rgp=rgp), "VT-SNT-007")
        assert f.evidence["imports"] == ["http", "strings"]

    def test_other_imports_do_not_fire(self):
        rgp = {"a": {"t": sentinel_policy("t")}}
        assert not _rules(_data(rgp=rgp), "VT-SNT-007")


def test_rendered_report_carries_the_new_rule_ids():
    data = _data(secrets={"": {"old/": mount("kv", options=None)}})
    assert "| VT-MOUNT-006 |" in render_findings(collect_findings(data))
