"""The two exporters must derive the same window from the same -s/-e.

activity-export previously ended its window at ``T00:00:00Z`` on the end date —
midnight at the *start* of it — while entity-export used ``T23:59:59Z``, so a
shared ``all -s A -e B`` asked the two endpoints for different ranges.

Verified against a live cluster: Vault normalises the *activity* endpoint's
window to month boundaries, which masked the discrepancy there. It does not do
so for the entity export endpoint, and the normalisation is server behaviour
rather than a documented contract — so these tests pin what the tool asks for,
which is the part under our control.
"""

from unittest.mock import Mock

import pytest

from src.activity_export.main import get_activity_data
from src.entity_export.main import get_entity_export_data


def _captured_params(fetch, start_date, end_date):
    """Run a fetch function against a stub client and return the query params."""
    client = Mock()
    client.get.return_value = {"data": {}}
    fetch(client, start_date, end_date)
    return client.get.call_args.kwargs["params"]


@pytest.mark.parametrize(
    "start_date,end_date",
    [
        ("2026-01-01", "2026-01-31"),
        ("2026-01-15", "2026-01-15"),  # single day: the zero-width window case
        ("2026-02-01", "2026-02-28"),
    ],
    ids=["month", "single-day", "february"],
)
class TestExportWindowAgreement:
    def test_both_exporters_derive_the_same_window(self, start_date, end_date):
        activity = _captured_params(get_activity_data, start_date, end_date)
        entity = _captured_params(get_entity_export_data, start_date, end_date)

        assert activity["start_time"] == entity["start_time"]
        assert activity["end_time"] == entity["end_time"]

    def test_end_of_window_covers_the_whole_end_date(self, start_date, end_date):
        activity = _captured_params(get_activity_data, start_date, end_date)
        assert activity["end_time"] == f"{end_date}T23:59:59Z"

    def test_window_is_never_zero_width(self, start_date, end_date):
        activity = _captured_params(get_activity_data, start_date, end_date)
        assert activity["start_time"] < activity["end_time"]
