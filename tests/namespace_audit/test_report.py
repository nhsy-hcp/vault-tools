"""Tests for the namespace audit markdown report."""

from src.namespace_audit.main import AuditData, AuditStats
from src.namespace_audit.report import (
    LONG_MAX_LEASE_TTL_SECONDS,
    _is_trivial_policy,
    build_markdown_report,
    build_namespace_tree,
    collect_findings,
    display_namespace,
    format_ttl,
    md_escape,
    md_table,
    render_access_gaps,
    render_enforcement_distribution,
    render_findings,
    render_namespace_inventory,
    render_namespace_tree,
    render_sentinel_policies,
    render_type_distribution,
    render_type_matrix,
)

# Only the plain helper is imported here. The clean_data/flagged_data/
# finished_stats/denied_stats fixtures are registered in conftest.py — importing
# them into this module too would shadow the fixture in every test signature
# that requests one (ruff F811).
from .report_fixtures import mount, sentinel_policy


class TestMarkdownPrimitives:
    """md_table is hand-rolled, so its escaping rules need pinning."""

    def test_escapes_pipes(self):
        assert md_escape("a|b") == "a\\|b"

    def test_flattens_newlines(self):
        assert md_escape("line1\nline2") == "line1 line2"
        assert md_escape("line1\r\nline2") == "line1 line2"

    def test_none_becomes_empty(self):
        assert md_escape(None) == ""

    def test_table_renders_header_separator_and_body(self):
        result = md_table(["A", "B"], [[1, 2], [3, 4]])
        lines = result.split("\n")
        assert lines[0] == "| A | B |"
        assert lines[1] == "| --- | --- |"
        assert lines[2] == "| 1 | 2 |"
        assert lines[3] == "| 3 | 4 |"

    def test_table_with_no_rows_is_a_placeholder_not_a_bare_header(self):
        assert md_table(["A", "B"], []) == "_No entries._"

    def test_table_escapes_cell_content(self):
        assert "a\\|b" in md_table(["A"], [["a|b"]])


class TestDisplayNamespace:
    def test_root_renders_as_slash(self):
        assert display_namespace("") == "/"

    def test_child_gains_trailing_slash(self):
        assert display_namespace("team-a") == "team-a/"

    def test_trailing_slash_is_not_doubled(self):
        assert display_namespace("team-a/") == "team-a/"


class TestNamespaceTree:
    def test_nests_children_under_parents(self, flagged_data):
        tree = build_namespace_tree(flagged_data)

        assert tree["__roots__"] == [""]
        assert set(tree[""]) == {"empty", "team-a"}
        assert tree["team-a"] == ["team-a/sub"]

    def test_root_only_cluster_still_renders_root(self):
        """The root is absent from data.namespaces, so it must come from the
        auth_methods keys — otherwise a dev-server audit renders an empty tree."""
        data = AuditData()
        data.auth_methods = {"": {"token/": {"type": "token"}}}
        data.secret_engines = {"": {"kv/": {"type": "kv"}}}

        rendered = render_namespace_tree(data)

        assert "`/`" in rendered
        assert "1 auth, 1 engines" in rendered

    def test_orphaned_node_is_kept_as_a_root(self):
        """An audit started partway down the tree has no recorded parent."""
        data = AuditData()
        data.auth_methods = {"a/b": {}, "a/b/c": {}}

        tree = build_namespace_tree(data)

        assert tree["__roots__"] == ["a/b"]
        assert tree["a/b"] == ["a/b/c"]

    def test_empty_data_does_not_crash(self):
        assert render_namespace_tree(AuditData()) == "_No namespaces recorded._"

    def test_tree_is_truncated_past_the_cap(self):
        data = AuditData()
        data.auth_methods = {f"ns{i:03d}": {} for i in range(50)}

        rendered = render_namespace_tree(data, max_nodes=10)

        assert "truncated at 10 of 50 namespaces" in rendered
        assert rendered.count("- `ns") == 10

    def test_indentation_reflects_depth(self, flagged_data):
        rendered = render_namespace_tree(flagged_data)

        assert "- `/`" in rendered
        assert "  - `team-a/`" in rendered
        assert "    - `team-a/sub/`" in rendered


class TestNamespaceInventory:
    def test_lists_id_depth_and_counts(self, clean_data):
        rendered = render_namespace_inventory(clean_data)

        assert "| team-a/ | abc12 | 1 | 2 | 2 | owner=platform |" in rendered

    def test_root_has_no_id_and_zero_depth(self, clean_data):
        rendered = render_namespace_inventory(clean_data)

        assert "| / | — | 0 | 2 | 3 | — |" in rendered

    def test_truncates_past_the_cap(self):
        data = AuditData()
        data.auth_methods = {f"ns{i:03d}": {} for i in range(50)}

        rendered = render_namespace_inventory(data, max_rows=10)

        assert "Showing 10 of 50 namespaces" in rendered


class TestTypeDistribution:
    def test_counts_mounts_and_namespaces_per_type(self, clean_data):
        rendered = render_type_distribution(clean_data.auth_methods, "Auth method type")

        # token appears in both namespaces, oidc and approle in one each
        assert "| token | 2 | 2 |" in rendered
        assert "| approle | 1 | 1 |" in rendered

    def test_sorted_by_count_descending(self, clean_data):
        rendered = render_type_distribution(clean_data.auth_methods, "Auth method type")
        body = [line for line in rendered.split("\n") if line.startswith("| ") and "---" not in line][1:]

        assert body[0].startswith("| token |")

    def test_matrix_renders_per_namespace_counts(self, clean_data):
        rendered = render_type_matrix(clean_data.auth_methods, "Auth methods")

        assert "| Namespace | token | approle | oidc |" in rendered

    def test_matrix_defers_to_csv_when_too_wide(self):
        data = AuditData()
        collection = {f"ns{i}": {"token/": {"type": "token"}} for i in range(30)}
        data.auth_methods = collection

        rendered = render_type_matrix(collection, "Auth methods", max_namespaces=25)

        assert "too many to tabulate here" in rendered
        assert "auth methods summary CSV" in rendered

    def test_empty_collection(self):
        assert render_type_matrix({}, "Auth methods") == "_No entries._"


class TestFindings:
    def test_clean_cluster_produces_no_findings(self, clean_data):
        assert collect_findings(clean_data) == []

    def test_clean_cluster_renders_reassuring_text(self, clean_data):
        assert "No observations" in render_findings(collect_findings(clean_data))

    def _details(self, data):
        return [f.detail for f in collect_findings(data)]

    def test_flags_deprecated_plugin(self, flagged_data):
        matches = [f for f in collect_findings(flagged_data) if "pending-removal" in f.detail]

        assert len(matches) == 1
        assert matches[0].severity == "Medium"
        assert matches[0].mount == "legacy/"

    def test_flags_unauth_listing_visibility(self, flagged_data):
        matches = [f for f in collect_findings(flagged_data) if "listing_visibility" in f.detail]

        assert len(matches) == 1
        assert matches[0].mount == "public/"
        assert matches[0].severity == "Low"

    def test_flags_long_max_lease_ttl(self, flagged_data):
        matches = [f for f in collect_findings(flagged_data) if "max_lease_ttl" in f.detail]

        assert len(matches) == 1
        assert matches[0].mount == "kv/"

    def test_zero_max_lease_ttl_is_not_flagged(self, clean_data):
        """0 means 'inherit the system default', not 'unlimited'. On a real
        cluster ~99.7% of mounts sit at 0, so flagging them buries everything."""
        assert not [f for f in collect_findings(clean_data) if "max_lease_ttl" in f.detail]

    def test_ttl_exactly_at_threshold_is_not_flagged(self):
        data = AuditData()
        data.auth_methods = {"": {"token/": mount("token")}}
        data.secret_engines = {"": {"kv/": mount("kv", config={"max_lease_ttl": LONG_MAX_LEASE_TTL_SECONDS})}}

        assert not [f for f in collect_findings(data) if "max_lease_ttl" in f.detail]


class TestSystemLeaseTtlBaseline:
    """The lease check calibrates against the cluster's own ceiling when known."""

    def _data(self, max_lease_ttl):
        data = AuditData()
        data.auth_methods = {"": {"token/": mount("token"), "oidc/": mount("oidc")}}
        data.secret_engines = {"": {"kv/": mount("kv"), "pki/": mount("pki", config={"max_lease_ttl": max_lease_ttl})}}
        return data

    def test_override_of_a_tuned_down_cluster_max_is_flagged(self):
        """2160h passes the stock 768h threshold untouched, but is 90x a 24h
        cluster max — the case the fixed threshold silently missed."""
        data = self._data(90 * 24 * 3600)  # 2160h

        matches = [f for f in collect_findings(data, system_max_lease_ttl=24 * 3600) if "max_lease_ttl" in f.detail]

        assert len(matches) == 1
        assert "overrides the cluster system max of 24h" in matches[0].detail
        assert "90x higher" in matches[0].detail

    def test_mount_at_the_system_max_is_not_flagged(self):
        data = self._data(24 * 3600)

        assert not [f for f in collect_findings(data, system_max_lease_ttl=24 * 3600) if "max_lease_ttl" in f.detail]

    def test_falls_back_to_the_fixed_threshold_when_unknown(self):
        data = self._data(90 * 24 * 3600)

        matches = [f for f in collect_findings(data, system_max_lease_ttl=None) if "max_lease_ttl" in f.detail]

        assert len(matches) == 1
        assert "review threshold" in matches[0].detail
        assert "could not be read" in matches[0].detail

    def test_fixed_threshold_misses_what_the_system_max_catches(self):
        """Pins the reason this option was chosen: a 100h lease is unremarkable
        against 768h but is 4x a 24h cluster ceiling."""
        data = self._data(100 * 3600)

        assert not collect_findings(data, system_max_lease_ttl=None)
        assert [f for f in collect_findings(data, system_max_lease_ttl=24 * 3600) if "max_lease_ttl" in f.detail]

    def test_zero_system_max_is_treated_as_unknown(self):
        """A 0 from the API means 'unset'; it must not become the baseline, or
        every mount on the cluster would be an override."""
        data = self._data(3600)

        assert not [f for f in collect_findings(data, system_max_lease_ttl=0) if "max_lease_ttl" in f.detail]


class TestFormatTtl:
    def test_whole_hours(self):
        assert format_ttl(86400) == "24h"
        assert format_ttl(3600) == "1h"

    def test_minutes_when_not_whole_hours(self):
        assert format_ttl(90 * 60) == "90m"

    def test_seconds_when_not_whole_minutes(self):
        assert format_ttl(45) == "45s"

    def test_flags_local_mount(self, flagged_data):
        matches = [f for f in collect_findings(flagged_data) if "not replicated" in f.detail]

        assert len(matches) == 1
        assert matches[0].mount == "transit/"

    def test_local_builtin_mounts_are_not_flagged(self):
        """cubbyhole is always local — flagging it is one noise row per namespace."""
        data = AuditData()
        data.auth_methods = {"": {"token/": mount("token"), "oidc/": mount("oidc")}}
        data.secret_engines = {
            "": {
                "cubbyhole/": mount("cubbyhole", local=True),
                "ns_cubbyhole/": mount("ns_cubbyhole", local=True),
                "kv/": mount("kv"),
            }
        }

        assert not [f for f in collect_findings(data) if "not replicated" in f.detail]

    def test_flags_namespace_with_only_token_auth(self, flagged_data):
        matches = [f for f in collect_findings(flagged_data) if "beyond the built-in token backend" in f.detail]

        assert {f.namespace for f in matches} == {"team-a", "empty"}

    def test_ns_token_counts_as_the_builtin_token_backend(self):
        """Child namespaces mount 'ns_token', not 'token' — both are built-in."""
        data = AuditData()
        data.auth_methods = {"child": {"token/": mount("ns_token")}}

        matches = [f for f in collect_findings(data) if "beyond the built-in token backend" in f.detail]

        assert [f.namespace for f in matches] == ["child"]

    def test_flags_leaf_namespace_with_only_builtin_engines(self, flagged_data):
        matches = [f for f in collect_findings(flagged_data) if "appears unused" in f.detail]

        assert [f.namespace for f in matches] == ["empty"]

    def test_parent_namespace_with_no_engines_is_not_flagged_as_unused(self):
        """A namespace holding only child namespaces is ordinary organisation."""
        data = AuditData()
        data.auth_methods = {"parent": {}, "parent/child": {}}
        data.secret_engines = {
            "parent": {"ns_cubbyhole/": mount("ns_cubbyhole")},
            "parent/child": {"kv/": mount("kv")},
        }

        assert not [f for f in collect_findings(data) if "appears unused" in f.detail]

    def test_findings_sorted_most_severe_first(self, flagged_data):
        severities = [f.severity for f in collect_findings(flagged_data)]

        assert severities[0] == "Medium"
        assert severities == sorted(severities, key=["Medium", "Low", "Info"].index)

    def test_rendered_findings_are_grouped_by_severity(self, flagged_data):
        rendered = render_findings(collect_findings(flagged_data))

        assert "#### Medium (1)" in rendered
        assert "#### Low (2)" in rendered
        assert rendered.index("#### Medium") < rendered.index("#### Low")

    def test_malformed_mount_data_is_skipped(self):
        """A non-dict mount value must not crash the whole report."""
        data = AuditData()
        data.auth_methods = {"": {"broken/": "not-a-dict", "token/": mount("token")}}

        assert collect_findings(data)  # the token-only finding still fires


class TestTrivialPolicyDetection:
    """What a do-nothing Sentinel policy actually looks like on a real cluster.

    Not an empty body: Vault refuses those at write time with "every policy must
    have a main rule". The reachable case is a main rule of literal `true`.
    """

    def test_always_true_rule_is_trivial(self):
        assert _is_trivial_policy("main = rule { true }")

    def test_comments_do_not_hide_the_rule(self):
        assert _is_trivial_policy("# placeholder\n// for now\nmain = rule { true }\n")

    def test_wrapped_rule_is_still_recognised(self):
        assert _is_trivial_policy("main = rule {\n    true\n}\n")

    def test_empty_body_is_trivial(self):
        """Unreachable through Vault's own endpoint, but cheap to catch."""
        assert _is_trivial_policy("")

    def test_comments_only_body_is_trivial(self):
        assert _is_trivial_policy("# nothing yet\n\n// still nothing\n")

    def test_real_condition_is_not_trivial(self):
        assert not _is_trivial_policy('import "time"\n\nmain = rule { time.now.unix > 0 }\n')

    def test_rule_returning_a_named_value_is_not_trivial(self):
        """Only the literal `true` counts — `truthy` must not match."""
        assert not _is_trivial_policy("main = rule { truthy }")

    def test_extra_rules_alongside_the_true_main_are_not_trivial(self):
        assert not _is_trivial_policy('allowed = rule { request.operation is "read" }\nmain = rule { true }')

    def test_unreadable_body_is_not_trivial(self):
        """A denied read leaves no body at all — absence is not emptiness."""
        assert not _is_trivial_policy(None)


class TestSentinelRendering:
    def test_egp_table_lists_paths_and_line_count(self, sentinel_data):
        rendered = render_sentinel_policies(sentinel_data.egp_policies, "egp")

        assert "| Namespace | Policy | Enforcement | Paths | Lines |" in rendered
        assert "| team-a/ | audit-only | advisory | secret/data/* | 3 |" in rendered

    def test_rgp_table_omits_the_paths_column(self, sentinel_data):
        """RGP policies bind to roles, not endpoints — there is no paths field."""
        rendered = render_sentinel_policies(sentinel_data.rgp_policies, "rgp")

        assert "| Namespace | Policy | Enforcement | Lines |" in rendered
        assert "Paths" not in rendered

    def test_empty_collection_renders_a_placeholder(self):
        assert render_sentinel_policies({}, "egp") == "_No entries._"

    def test_truncates_past_the_cap(self):
        collection = {"": {f"p{i:03d}": sentinel_policy(f"p{i:03d}") for i in range(50)}}

        rendered = render_sentinel_policies(collection, "rgp", max_rows=10)

        assert "Showing 10 of 50 policies" in rendered

    def test_enforcement_distribution_counts_both_kinds(self, sentinel_data):
        rendered = render_enforcement_distribution(sentinel_data.egp_policies, sentinel_data.rgp_policies)

        assert "| hard-mandatory | 3 | 0 |" in rendered
        assert "| soft-mandatory | 0 | 1 |" in rendered
        assert "| advisory | 1 | 0 |" in rendered

    def test_unreadable_policies_are_counted_as_unknown(self):
        """A denied read still means a policy exists; the totals must reconcile."""
        collection = {"": {"denied": {"name": "denied", "read_error": "permission denied"}}}

        rendered = render_enforcement_distribution(collection, {})

        assert "| unknown | 1 | 0 |" in rendered

    def test_distribution_is_empty_when_there_are_no_policies(self):
        assert render_enforcement_distribution({}, {}) == "_No entries._"


class TestSentinelFindings:
    def test_flags_advisory_enforcement(self, sentinel_data):
        matches = [f for f in collect_findings(sentinel_data) if "`advisory`" in f.detail]

        assert len(matches) == 1
        assert matches[0].severity == "Low"
        assert matches[0].mount == "audit-only"
        assert matches[0].mount_type == "egp"

    def test_flags_soft_mandatory_as_informational(self, sentinel_data):
        matches = [f for f in collect_findings(sentinel_data) if "`soft-mandatory`" in f.detail]

        assert len(matches) == 1
        assert matches[0].severity == "Info"
        assert matches[0].mount_type == "rgp"

    def test_flags_wildcard_egp_paths(self, sentinel_data):
        matches = [f for f in collect_findings(sentinel_data) if "every request" in f.detail]

        assert [f.mount for f in matches] == ["catch-all"]

    def test_flags_comments_only_body(self, sentinel_data):
        matches = [f for f in collect_findings(sentinel_data) if "enforces nothing" in f.detail]

        assert [f.mount for f in matches] == ["placeholder"]

    def test_hard_mandatory_policy_with_a_real_body_is_not_flagged(self, sentinel_data):
        """The control case: if this ever fires, a check has grown too broad."""
        assert not [f for f in collect_findings(sentinel_data) if f.mount == "require-cidr"]

    def test_cluster_without_sentinel_produces_no_sentinel_findings(self, clean_data):
        assert collect_findings(clean_data) == []

    def test_findings_column_is_headed_object_not_mount(self, sentinel_data):
        """Policy names share the column with mount paths."""
        rendered = render_findings(collect_findings(sentinel_data))

        assert "| Namespace | Object | Type | Observation |" in rendered


class TestAccessGaps:
    def test_reports_none_when_nothing_was_denied(self, finished_stats):
        rendered = render_access_gaps(finished_stats, "")

        assert "None — the audit covered the full tree reachable from `/`" in rendered

    def test_none_message_names_the_starting_namespace(self, finished_stats):
        assert "`team-a/`" in render_access_gaps(finished_stats, "team-a/")

    def test_lists_denied_namespaces_by_name(self, denied_stats):
        rendered = render_access_gaps(denied_stats, "")

        assert "restricted/" in rendered
        assert "child namespaces (subtree not audited)" in rendered
        assert "report is incomplete below these paths" in rendered

    def test_lists_errors_with_their_namespace(self, denied_stats):
        rendered = render_access_gaps(denied_stats, "")

        assert "broken/" in rendered
        assert "connection reset" in rendered

    def test_a_cluster_wide_denial_collapses_to_one_row(self):
        """A missing policy rule denies every namespace; 134 rows would bury the
        specific gaps this section exists to surface."""
        stats = AuditStats()
        for i in range(40):
            stats.increment_forbidden(f"ns{i:03d}/", "sentinel EGP policies")
        stats.increment_forbidden("restricted/", "whole namespace (no data collected)")

        rendered = render_access_gaps(stats, "")

        assert "| 40 namespaces (ns000/, ns001/, ns002/, …) | sentinel EGP policies |" in rendered
        # The one-off denial is still named individually.
        assert "| restricted/ | whole namespace (no data collected) |" in rendered

    def test_a_handful_of_denials_are_still_listed_by_name(self):
        """Below the cap nothing is collapsed — naming them is the whole point."""
        stats = AuditStats()
        for name in ("alpha/", "beta/", "gamma/"):
            stats.increment_forbidden(name, "sentinel RGP policies")

        rendered = render_access_gaps(stats, "")

        for name in ("alpha/", "beta/", "gamma/"):
            assert f"| {name} | sentinel RGP policies |" in rendered
        assert "namespaces (" not in rendered

    def test_unattributed_denials_are_still_reported(self):
        """Bare increment_forbidden() calls record a count but no path."""
        stats = AuditStats()
        stats.increment_forbidden()

        rendered = render_access_gaps(stats, "")

        assert "1 permission denial(s) were recorded without an attributed namespace" in rendered


class TestAuditStatsRecording:
    """The lists behind the access-gaps section."""

    def test_forbidden_records_path_and_scope(self):
        stats = AuditStats()
        stats.increment_forbidden("team-a/", "whole namespace (no data collected)")

        assert stats.forbidden_count == 1
        assert stats.forbidden_namespaces == [("team-a/", "whole namespace (no data collected)")]

    def test_errors_record_path_and_message(self):
        stats = AuditStats()
        stats.increment_errors("team-a/", "boom")

        assert stats.error_count == 1
        assert stats.errors == [("team-a/", "boom")]

    def test_bare_calls_still_count_without_recording(self):
        """Backwards compatibility with the existing call sites and tests."""
        stats = AuditStats()
        stats.increment_forbidden()
        stats.increment_errors()

        assert stats.forbidden_count == 1
        assert stats.error_count == 1
        assert stats.forbidden_namespaces == []
        assert stats.errors == []


class TestFullReport:
    def test_contains_every_section(self, flagged_data, denied_stats):
        report = build_markdown_report("test-cluster", flagged_data, denied_stats)

        for heading in (
            "# Vault Namespace Audit — test-cluster",
            "## Summary",
            "## Access gaps",
            "## Namespace inventory",
            "## Type distribution",
            "## Security observations",
            "## Output files",
        ):
            assert heading in report

    def test_summary_reports_depth_and_type_counts(self, flagged_data, finished_stats):
        report = build_markdown_report("test-cluster", flagged_data, finished_stats)

        assert "| Maximum nesting depth | 2 |" in report
        assert "| Total auth methods | 7 |" in report

    def test_namespace_count_is_cumulative_over_the_whole_tree(self, flagged_data):
        """Root + every descendant, counted from the inventory — not the
        progress-bar denominator, which seeds at 1 for the root."""
        stats = AuditStats()
        stats.processed_count = 4  # root, team-a, team-a/sub, empty
        report = build_markdown_report("test-cluster", flagged_data, stats)

        assert "| Namespaces | 4 |" in report

    def test_namespace_count_collapses_to_one_row_when_fully_processed(self, clean_data):
        stats = AuditStats()
        stats.processed_count = 2
        report = build_markdown_report("test-cluster", clean_data, stats)

        assert "| Namespaces | 2 |" in report
        # The old two-row form must be gone entirely.
        assert "Namespaces processed" not in report
        assert "Namespaces discovered" not in report
        assert "Total namespaces" not in report

    def test_namespace_count_shows_the_shortfall_when_the_walk_did_not_finish(self, flagged_data):
        """A discovered namespace that was never traversed is worth surfacing."""
        stats = AuditStats()
        stats.processed_count = 2  # but four namespaces are known
        report = build_markdown_report("test-cluster", flagged_data, stats)

        assert "| Namespaces | 4 (2 processed) |" in report

    def test_root_only_cluster_counts_one_namespace(self):
        data = AuditData()
        data.auth_methods = {"": {"token/": {"type": "token"}}}
        stats = AuditStats()
        stats.processed_count = 1

        assert "| Namespaces | 1 |" in build_markdown_report("dev", data, stats)

    def test_header_records_cluster_and_start_namespace(self, clean_data, finished_stats):
        report = build_markdown_report("prod", clean_data, finished_stats, start_namespace="team-a/")

        assert "| Cluster | prod |" in report
        assert "| Starting namespace | team-a/ |" in report

    def test_includes_cache_stats_when_supplied(self, clean_data, finished_stats):
        report = build_markdown_report("prod", clean_data, finished_stats, cache_stats={"hit_rate": "42.00%"})

        assert "| Cache hit rate | 42.00% |" in report

    def test_omits_cache_row_when_not_supplied(self, clean_data, finished_stats):
        assert "Cache hit rate" not in build_markdown_report("prod", clean_data, finished_stats)

    def test_summary_reports_the_system_lease_ttls(self, clean_data, finished_stats):
        report = build_markdown_report("prod", clean_data, finished_stats, system_lease_ttls=(3600, 86400))

        assert "| System lease TTL | 1h default / 24h max |" in report

    def test_omits_the_lease_row_when_unavailable(self, clean_data, finished_stats):
        assert "System lease TTL" not in build_markdown_report("prod", clean_data, finished_stats)

    def test_system_max_reaches_the_finding_checks(self, finished_stats):
        """The tuple's max element must be threaded through to collect_findings."""
        data = AuditData()
        data.auth_methods = {"": {"token/": mount("token")}}
        data.secret_engines = {"": {"pki/": mount("pki", config={"max_lease_ttl": 100 * 3600})}}

        report = build_markdown_report("prod", data, finished_stats, system_lease_ttls=(3600, 86400))

        assert "overrides the cluster system max of 24h" in report

    def test_lists_sibling_output_files(self, clean_data, finished_stats):
        report = build_markdown_report("prod", clean_data, finished_stats, output_files=["prod-namespaces-20260817.json"])

        assert "prod-namespaces-20260817.json" in report

    def test_empty_audit_renders_without_crashing(self):
        report = build_markdown_report("prod", AuditData(), AuditStats())

        assert "# Vault Namespace Audit — prod" in report
        assert "_No namespaces recorded._" in report


class TestSentinelSection:
    """The tri-state: answered, absent from the cluster, or never asked."""

    def test_supported_cluster_renders_the_tables(self, sentinel_data, finished_stats):
        report = build_markdown_report("prod", sentinel_data, finished_stats, sentinel_supported=True)

        assert "## Sentinel policies" in report
        assert "### Enforcement levels" in report
        assert "### Endpoint governing policies (EGP)" in report
        assert "### Role governing policies (RGP)" in report
        assert "4 endpoint governing policies and 1 role governing policy" in report

    def test_supported_cluster_gets_summary_totals(self, sentinel_data, finished_stats):
        report = build_markdown_report("prod", sentinel_data, finished_stats, sentinel_supported=True)

        assert "| Sentinel EGP policies | 4 |" in report
        assert "| Sentinel RGP policies | 1 |" in report

    def test_unsupported_cluster_says_so_and_renders_no_tables(self, clean_data, finished_stats):
        """Community must not read as 'Sentinel checked, zero policies found'."""
        report = build_markdown_report("prod", clean_data, finished_stats, sentinel_supported=False)

        assert "## Sentinel policies" in report
        assert "endpoints are unavailable on this cluster" in report
        assert "### Enforcement levels" not in report
        # And no zero-valued summary rows implying a check that did not happen.
        assert "Sentinel EGP policies" not in report

    def test_skipped_collection_is_distinct_from_unavailable(self, clean_data, finished_stats):
        report = build_markdown_report("prod", clean_data, finished_stats, sentinel_supported=None)

        assert "Sentinel collection was skipped" in report
        assert "### Enforcement levels" not in report

    def test_denied_everywhere_does_not_read_as_skipped(self, clean_data):
        """Otherwise the reader hunts for a --no-sentinel they never passed."""
        stats = AuditStats()
        stats.increment_forbidden("team-a/", "sentinel EGP policies")

        report = build_markdown_report("prod", clean_data, stats, sentinel_supported=None)

        assert "denied access to the Sentinel policy endpoints" in report
        assert "Sentinel collection was skipped" not in report

    def test_section_sits_between_type_distribution_and_observations(self, sentinel_data, finished_stats):
        report = build_markdown_report("prod", sentinel_data, finished_stats, sentinel_supported=True)

        assert report.index("## Type distribution") < report.index("## Sentinel policies") < report.index("## Security observations")
