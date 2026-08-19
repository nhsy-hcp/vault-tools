"""Tests for namespace traversal functionality."""

import queue

import hvac

from tests.namespace_audit.fixtures import as_context_manager, make_hvac_client


def attach(auditor, hvac_client):
    """Point the auditor's get_client at this mock and hand the mock back."""
    auditor.vault_client.get_client.return_value = as_context_manager(hvac_client)
    return hvac_client


class TestNamespaceDataFetching:
    """Test fetching data from individual namespaces."""

    def test_fetch_namespace_data_success(self, auditor):
        """Test successful namespace data fetch from non-root namespace."""
        attach(
            auditor,
            make_hvac_client(
                list_auth_methods={"data": {"userpass/": {"type": "userpass"}}},
                list_mounted_secrets_engines={"data": {"secret/": {"type": "kv"}}},
                list_namespaces={"data": {"key_info": {"team-a/": {"id": "123"}}}},
            ),
        )

        path_queue = queue.Queue()
        auditor._traverse_namespace("test/", path_queue)

        # Verify auth methods and secret engines are stored
        assert "test" in auditor.data.auth_methods
        assert "test" in auditor.data.secret_engines
        # Children of a non-root namespace are discovered and queued with their
        # path resolved against the parent
        assert "test/team-a" in auditor.data.namespaces
        assert path_queue.get() == "test/team-a/"

    def test_fetch_namespace_data_invalid_path(self, auditor):
        """Test namespace data fetch with invalid path."""
        client = attach(auditor, make_hvac_client())
        client.sys.list_namespaces.side_effect = hvac.exceptions.InvalidPath()

        path_queue = queue.Queue()
        auditor._traverse_namespace("test/", path_queue)

        assert "test" in auditor.data.auth_methods
        assert "test" in auditor.data.secret_engines
        assert path_queue.empty()  # Should be empty since no child namespaces were found

    def test_fetch_namespace_data_forbidden(self, auditor):
        """Test namespace data fetch with forbidden access."""
        client = attach(auditor, make_hvac_client())
        client.sys.list_auth_methods.side_effect = hvac.exceptions.Forbidden()

        path_queue = queue.Queue()
        auditor._traverse_namespace("test/", path_queue)

        assert "test/" not in auditor.data.auth_methods
        assert "test/" not in auditor.data.secret_engines
        # Forbidden access is tracked in forbidden_count, not error_count (N5 fix).
        assert auditor.stats.error_count == 0
        assert auditor.stats.forbidden_count == 1

    def test_traverse_namespace_error_handling(self, auditor):
        """Test error handling during namespace traversal."""
        client = attach(auditor, make_hvac_client())
        client.sys.list_auth_methods.side_effect = Exception("Unexpected error")

        path_queue = queue.Queue()
        auditor._traverse_namespace("test/", path_queue)

        # Should increment error count for unexpected errors
        assert auditor.stats.error_count == 1
        assert "test/" not in auditor.data.auth_methods


class TestNamespacePathProcessing:
    """Test namespace path processing and child discovery."""

    def test_root_namespace_processing(self, auditor):
        """Test processing the root namespace."""
        attach(
            auditor,
            make_hvac_client(
                list_auth_methods={"data": {"token/": {"type": "token"}}},
                list_mounted_secrets_engines={"data": {"sys/": {"type": "system"}}},
                list_namespaces={"data": {"key_info": {"prod/": {"id": "456"}}}},
            ),
        )

        path_queue = queue.Queue()
        # Root namespace is represented as empty string ""
        auditor._traverse_namespace("", path_queue)

        assert "" in auditor.data.auth_methods
        assert "" in auditor.data.secret_engines
        # Child namespace 'prod/' is stored without trailing slash as 'prod'
        assert "prod" in auditor.data.namespaces
        # Verify child was added to queue for processing
        assert not path_queue.empty()
        assert path_queue.get() == "prod/"

    def test_nested_namespace_processing(self, auditor):
        """Test that deeply nested namespaces still discover their own children."""
        attach(
            auditor,
            make_hvac_client(
                list_auth_methods={"data": {"ldap/": {"type": "ldap"}}},
                list_mounted_secrets_engines={"data": {"database/": {"type": "database"}}},
                list_namespaces={"data": {"key_info": {"dev/": {"id": "789"}}}},
            ),
        )

        path_queue = queue.Queue()
        auditor._traverse_namespace("prod/team-a/", path_queue)

        # Verify auth methods and secret engines are stored
        assert "prod/team-a" in auditor.data.auth_methods
        assert "prod/team-a" in auditor.data.secret_engines
        # Discovery continues below the second level
        assert "prod/team-a/dev" in auditor.data.namespaces
        assert path_queue.get() == "prod/team-a/dev/"

    def test_already_visited_child_is_not_requeued(self, auditor):
        """A namespace reported twice is only enqueued once."""
        attach(auditor, make_hvac_client(list_namespaces={"data": {"key_info": {"dev/": {"id": "789"}}}}))

        path_queue = queue.Queue()
        auditor._traverse_namespace("prod/", path_queue)
        discovered_after_first = auditor.stats.discovered_count

        # Same parent walked again: the child is already known, so nothing new
        # is queued and the progress denominator does not grow.
        auditor._traverse_namespace("prod/", path_queue)

        assert path_queue.get() == "prod/dev/"
        assert path_queue.empty()
        assert auditor.stats.discovered_count == discovered_after_first

    def test_empty_namespace_processing(self, auditor):
        """Test processing namespace with no auth methods or secret engines."""
        client = attach(auditor, make_hvac_client())
        client.sys.list_namespaces.side_effect = hvac.exceptions.InvalidPath()

        path_queue = queue.Queue()
        auditor._traverse_namespace("empty/", path_queue)

        assert "empty" in auditor.data.auth_methods
        assert "empty" in auditor.data.secret_engines
        assert auditor.data.auth_methods["empty"] == {}
        assert auditor.data.secret_engines["empty"] == {}


class TestAclPolicyCollection:
    """Names only, with Vault's own everywhere-policies filtered out."""

    def test_names_are_stored_sorted(self, auditor):
        attach(auditor, make_hvac_client(list_acl_policies={"data": {"keys": ["kv-writer", "admin", "auditor"]}}))

        auditor._traverse_namespace("team-a/", queue.Queue())

        assert auditor.data.acl_policies["team-a"] == ["admin", "auditor", "kv-writer"]

    def test_builtin_policies_are_excluded(self, auditor):
        attach(auditor, make_hvac_client(list_acl_policies={"data": {"keys": ["default", "root", "default-ceiling", "admin"]}}))

        auditor._traverse_namespace("team-a/", queue.Queue())

        assert auditor.data.acl_policies["team-a"] == ["admin"]

    def test_exclusion_is_exact_not_a_prefix(self, auditor):
        """`default-ceiling` is excluded, but a user policy that merely starts
        with `default` is real configuration and must survive."""
        keys = ["default", "default-admin", "default-ceiling", "default-ceiling-override", "rooted"]
        attach(auditor, make_hvac_client(list_acl_policies={"data": {"keys": keys}}))

        auditor._traverse_namespace("team-a/", queue.Queue())

        assert auditor.data.acl_policies["team-a"] == ["default-admin", "default-ceiling-override", "rooted"]

    def test_namespace_with_only_builtins_still_gets_a_key(self, auditor):
        """Twelve namespaces on the reference cluster are in this state. An
        absent key would read as 'not audited' rather than 'nothing defined'."""
        attach(auditor, make_hvac_client(list_acl_policies={"data": {"keys": ["default", "default-ceiling"]}}))

        auditor._traverse_namespace("team-a/", queue.Queue())

        assert auditor.data.acl_policies["team-a"] == []

    def test_forbidden_is_recorded_as_an_access_gap(self, auditor):
        client = attach(auditor, make_hvac_client())
        client.sys.list_acl_policies.side_effect = hvac.exceptions.Forbidden()

        auditor._traverse_namespace("team-a/", queue.Queue())

        assert ("team-a/", "ACL policies") in auditor.stats.forbidden_namespaces
        assert auditor.stats.error_count == 0
        # The rest of the namespace was still collected.
        assert "team-a" in auditor.data.auth_methods

    def test_invalid_path_yields_an_empty_list(self, auditor):
        client = attach(auditor, make_hvac_client())
        client.sys.list_acl_policies.side_effect = hvac.exceptions.InvalidPath()

        auditor._traverse_namespace("team-a/", queue.Queue())

        assert auditor.data.acl_policies["team-a"] == []
        assert auditor.stats.error_count == 0

    def test_unexpected_error_is_counted_not_swallowed(self, auditor):
        client = attach(auditor, make_hvac_client())
        client.sys.list_acl_policies.side_effect = RuntimeError("boom")

        auditor._traverse_namespace("team-a/", queue.Queue())

        assert auditor.stats.error_count == 1
        assert auditor.data.acl_policies["team-a"] == []


class TestSentinelPolicyCollection:
    """EGP/RGP collection, and the Enterprise-vs-Community degradation."""

    def _with_policies(self, auditor):
        client = attach(
            auditor,
            make_hvac_client(
                list_egp_policies={"data": {"keys": ["deny-root"]}},
                list_rgp_policies={"data": {"keys": ["require-mfa"]}},
                read_egp_policy={"data": {"name": "deny-root", "enforcement_level": "advisory", "paths": ["*"], "policy": "main = rule { true }"}},
                read_rgp_policy={"data": {"name": "require-mfa", "enforcement_level": "hard-mandatory", "policy": "main = rule { true }"}},
            ),
        )
        return client

    def test_policies_are_stored_per_namespace(self, auditor):
        self._with_policies(auditor)

        auditor._traverse_namespace("team-a/", queue.Queue())

        assert auditor.data.egp_policies["team-a"]["deny-root"]["enforcement_level"] == "advisory"
        assert auditor.data.rgp_policies["team-a"]["require-mfa"]["enforcement_level"] == "hard-mandatory"
        assert auditor.sentinel_supported is True

    def test_unsupported_path_marks_the_cluster_and_is_not_an_error(self, auditor):
        """Community and unlicensed Enterprise 404 with 'unsupported path'."""
        client = attach(auditor, make_hvac_client())
        client.sys.list_egp_policies.side_effect = hvac.exceptions.InvalidPath("1 error occurred:\n\t* unsupported path\n\n")

        auditor._traverse_namespace("team-a/", queue.Queue())

        assert auditor.sentinel_supported is False
        assert auditor.stats.error_count == 0
        assert auditor.stats.forbidden_count == 0
        assert auditor.data.egp_policies == {}

    def test_unsupported_cluster_is_probed_only_once(self, auditor):
        """The short-circuit caps a Community run at two extra API calls."""
        client = attach(auditor, make_hvac_client())
        client.sys.list_egp_policies.side_effect = hvac.exceptions.InvalidPath("unsupported path")

        auditor._traverse_namespace("a/", queue.Queue())
        auditor._traverse_namespace("b/", queue.Queue())
        auditor._traverse_namespace("c/", queue.Queue())

        assert client.sys.list_egp_policies.call_count == 1
        assert client.sys.list_rgp_policies.call_count == 0

    def test_plain_invalid_path_means_no_policies_not_no_sentinel(self, auditor):
        """Vault 404s an empty LIST too — that must not disable collection."""
        client = attach(auditor, make_hvac_client())
        client.sys.list_egp_policies.side_effect = hvac.exceptions.InvalidPath()

        auditor._traverse_namespace("team-a/", queue.Queue())

        assert auditor.sentinel_supported is True
        assert auditor.data.egp_policies == {}
        assert auditor.stats.error_count == 0

    def test_forbidden_list_is_recorded_as_an_access_gap(self, auditor):
        client = attach(auditor, make_hvac_client())
        client.sys.list_egp_policies.side_effect = hvac.exceptions.Forbidden()

        auditor._traverse_namespace("team-a/", queue.Queue())

        assert ("team-a/", "sentinel EGP policies") in auditor.stats.forbidden_namespaces
        assert auditor.stats.error_count == 0
        # The rest of the namespace was still collected.
        assert "team-a" in auditor.data.auth_methods

    def test_unreadable_policy_keeps_the_name_and_records_one_gap(self, auditor):
        """40 denied reads in a namespace must not become 40 access-gap rows."""
        client = attach(auditor, make_hvac_client(list_egp_policies={"data": {"keys": ["a", "b", "c"]}}))
        client.sys.read_egp_policy.side_effect = hvac.exceptions.Forbidden()

        auditor._traverse_namespace("team-a/", queue.Queue())

        assert set(auditor.data.egp_policies["team-a"]) == {"a", "b", "c"}
        assert "read_error" in auditor.data.egp_policies["team-a"]["a"]
        gaps = [g for g in auditor.stats.forbidden_namespaces if "policy bodies" in g[1]]
        assert len(gaps) == 1

    def test_collection_can_be_disabled(self, auditor):
        auditor.collect_sentinel = False
        client = self._with_policies(auditor)

        auditor._traverse_namespace("team-a/", queue.Queue())

        assert client.sys.list_egp_policies.call_count == 0
        assert auditor.data.egp_policies == {}
        assert auditor.sentinel_supported is None

    def test_namespaces_without_policies_get_no_entry(self, auditor):
        """An empty dict per namespace would put a blank row in every table."""
        attach(auditor, make_hvac_client())

        auditor._traverse_namespace("team-a/", queue.Queue())

        assert "team-a" not in auditor.data.egp_policies
        assert "team-a" not in auditor.data.rgp_policies
