"""Client usage anti-patterns (VT-CLI-001..005) and how activity-export reports them."""

import json
from datetime import UTC, datetime
from pathlib import Path
from unittest.mock import Mock, patch

import hvac
import jsonschema
import pytest

from src.activity_export.findings import (
    CLIENT_CHURN_WARNING,
    CLIENT_GROWTH_MIN_CLIENTS,
    CLIENT_RULE_MIN_CLIENTS,
    parse_activity_config,
    usage_findings,
)
from src.activity_export.main import _covers_current_month, assess_activity
from src.common.exceptions import VaultAPIError, VaultPermissionError

SCHEMA = json.loads((Path(__file__).parents[2] / "schemas" / "findings.schema.json").read_text())


def _ids(findings):
    return sorted(f.rule_id for f in findings)


def _ns(path, clients, non_entity=0):
    return {"namespace_path": path, "counts": {"clients": clients, "entity_clients": clients - non_entity, "non_entity_clients": non_entity}}


def _activity(rows, months=None):
    return {"total": {"clients": sum(r["counts"]["clients"] for r in rows)}, "by_namespace": rows, "months": months or []}


class TestConfig:
    @pytest.mark.parametrize("enabled,recording", [("enable", True), ("default-enabled", True), ("disable", False), ("default-disabled", False), ("weird", None)])
    def test_recording_flag(self, enabled, recording):
        assert parse_activity_config({"enabled": enabled})["recording"] is recording

    def test_unreadable_is_none(self):
        assert parse_activity_config(None) is None

    def test_log_off_is_reported(self):
        [f] = usage_findings({}, None, False, parse_activity_config({"enabled": "default-disabled"}))
        assert f.rule_id == "VT-CLI-005" and f.evidence == {"enabled": "default-disabled"}


class TestTokenOnly:
    def test_fires_above_half(self):
        [f] = usage_findings(_activity([_ns("team-a/", CLIENT_RULE_MIN_CLIENTS, CLIENT_RULE_MIN_CLIENTS // 2 + 1)]))
        assert (f.rule_id, f.namespace, f.evidence["source"]) == ("VT-CLI-001", "team-a", "billing_period")

    def test_small_namespace_is_not_judged(self):
        assert usage_findings(_activity([_ns("team-a/", CLIENT_RULE_MIN_CLIENTS - 1, CLIENT_RULE_MIN_CLIENTS - 1)])) == []

    def test_falls_back_to_the_current_month(self):
        current = {"clients": 60, "by_namespace": [_ns("a/", 60, 60)]}
        [f] = usage_findings({"total": {"clients": 0}}, current)
        assert f.evidence["source"] == "current_month"


class TestRootConcentration:
    def test_enterprise_only(self):
        activity = _activity([_ns("", 90), _ns("a/", 10)])
        assert _ids(usage_findings(activity, enterprise=True)) == ["VT-CLI-004"]
        assert usage_findings(activity, enterprise=False) == []
        assert usage_findings(activity, enterprise=None) == []


class TestGrowth:
    def _months(self, *counts):
        return [{"timestamp": f"2026-0{i + 1}-01T00:00:00Z", "counts": {"clients": c}} for i, c in enumerate(counts)]

    def test_sharp_growth(self):
        [f] = usage_findings(_activity([], self._months(100, 100, 100, 300)))
        assert f.rule_id == "VT-CLI-002" and f.evidence["baseline_clients"] == 100

    def test_steady_and_small_do_not_fire(self):
        assert usage_findings(_activity([], self._months(100, 100, 120))) == []
        assert usage_findings(_activity([], self._months(10, 10, CLIENT_GROWTH_MIN_CLIENTS - 1))) == []

    def test_current_month_extends_the_series(self):
        current = {"clients": 400, "months": [{"timestamp": "2026-05-01T00:00:00Z"}]}
        assert _ids(usage_findings(_activity([], self._months(100, 100, 100)), current)) == ["VT-CLI-002"]


class TestChurn:
    def _months(self, before, total, new):
        mount = lambda c: {"namespace_path": "", "mounts": [{"mount_path": "auth/jwt/", "mount_type": "jwt", "counts": {"clients": c}}]}  # noqa: E731
        return [
            {"timestamp": "2026-01-01T00:00:00Z", "counts": {"clients": before}, "namespaces": [mount(before)]},
            {"timestamp": "2026-02-01T00:00:00Z", "counts": {"clients": total}, "namespaces": [mount(total)], "new_clients": {"namespaces": [mount(new)]}},
        ]

    def test_per_run_identities(self):
        [f] = usage_findings(_activity([], self._months(90, 100, int(100 * CLIENT_CHURN_WARNING))))
        assert (f.rule_id, f.object_kind, f.mount, f.mount_type) == ("VT-CLI-003", "auth_mount", "jwt/", "jwt")

    def test_stable_identities_do_not_fire(self):
        assert usage_findings(_activity([], self._months(90, 100, 10))) == []

    def test_new_mount_is_not_judged(self):
        assert usage_findings(_activity([], self._months(0, 100, 100))) == []


class TestAssess:
    NOW = datetime(2026, 10, 8, tzinfo=UTC)

    def _client(self, responses):
        client = Mock()
        client.vault_addr = "https://vault.example.com:8200"

        def get(path, **_kwargs):
            value = responses.get(path)
            if isinstance(value, BaseException):
                raise value
            return value if value is not None else {}

        client.get.side_effect = get
        return client

    def _assess(self, client, end_date="2026-10-31"):
        with patch("src.activity_export.main.write_json") as wj, patch("src.activity_export.main.write_csv") as wc, patch("src.activity_export.main.write_markdown") as wm:
            document = assess_activity(client, _activity([_ns("a/", 60, 60)]), "c", "2026-01-01", end_date, "out", True, self.NOW)
        return document, wj, wc, wm.call_args.args[1]

    def test_document_validates_and_files_are_written(self):
        client = self._client({"sys/internal/counters/config": {"data": {"enabled": "enable"}}, "sys/internal/counters/activity/monthly": {"data": {"clients": 3}}})
        document, wj, wc, markdown = self._assess(client)
        jsonschema.validate(document, SCHEMA)
        assert document["summary"]["by_rule"] == {"VT-CLI-001": 1}
        assert wj.call_args.args[0].endswith(".json") and "-activity-findings-" in wj.call_args.args[0]
        assert wc.called
        assert "Clients this month (in progress) | 3" in markdown

    def test_denied_config_is_a_gap(self):
        client = self._client({"sys/internal/counters/config": VaultPermissionError("no")})
        document, *_ = self._assess(client)
        assert document["coverage"]["denied"] == [{"namespace": "/", "scope": "sys/internal/counters/config"}]

    def test_missing_monthly_endpoint_is_not_an_error(self):
        error = VaultAPIError("Invalid path")
        error.__cause__ = hvac.exceptions.InvalidPath()
        client = self._client({"sys/internal/counters/activity/monthly": error})
        document, *_ = self._assess(client)
        assert document["coverage"]["complete"] is True

    def test_past_window_does_not_read_the_month_in_progress(self):
        client = self._client({})
        self._assess(client, end_date="2026-08-31")
        assert all(c.args[0] != "sys/internal/counters/activity/monthly" for c in client.get.call_args_list)

    def test_log_off_is_called_out_in_the_report(self):
        client = self._client({"sys/internal/counters/config": {"data": {"enabled": "default-disabled"}}})
        document, _, _, markdown = self._assess(client)
        assert "VT-CLI-005" in document["summary"]["by_rule"]
        assert "nothing is recorded" in markdown

    def test_no_findings_means_no_csv(self):
        client = self._client({"sys/internal/counters/config": {"data": {"enabled": "enable"}}})
        with patch("src.activity_export.main.write_json"), patch("src.activity_export.main.write_csv") as wc, patch("src.activity_export.main.write_markdown"):
            assess_activity(client, _activity([_ns("a/", 5)]), "c", "2026-01-01", "2026-08-31", "out", False, self.NOW)
        wc.assert_not_called()


def test_current_month_window():
    now = datetime(2026, 10, 8, tzinfo=UTC)
    assert _covers_current_month("2026-10-01", now) and _covers_current_month("2026-12-31", now)
    assert not _covers_current_month("2026-09-30", now)


def test_current_month_read_elsewhere_is_reused():
    """full-audit hands identity-audit's activity/monthly read on instead of repeating it."""
    client = Mock()
    client.vault_addr = "addr"
    client.get.return_value = {"data": {"enabled": "enable"}}
    with patch("src.activity_export.main.write_json"), patch("src.activity_export.main.write_csv"), patch("src.activity_export.main.write_markdown") as wm:
        assess_activity(client, _activity([]), "c", "2026-01-01", "2026-12-31", "out", True, datetime(2026, 10, 8, tzinfo=UTC), current_month={"clients": 9})
    assert [c.args[0] for c in client.get.call_args_list] == ["sys/internal/counters/config"]
    assert "Clients this month (in progress) | 9" in wm.call_args.args[1]
