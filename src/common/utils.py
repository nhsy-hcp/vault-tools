import argparse
import calendar
import logging
import re
from datetime import UTC, datetime, timedelta

logger = logging.getLogger(__name__)

# Shared date format constants — use these everywhere instead of inline literals.
DATE_FORMAT = "%Y-%m-%d"  # Parsing/validation (YYYY-MM-DD)
FILE_DATE_FORMAT = "%Y%m%d"  # File name suffix (YYYYMMDD)


def file_prefix(cluster_name: str, cluster_id: str | None) -> str:
    """The prefix every output file name starts with: ``{cluster-name}-{cluster-id[:8]}``.

    The ID keeps two clusters that share a name (every cluster renamed to
    "vault-cluster", say) from overwriting each other's outputs. Vault's default
    names already end in eight hex characters of their own, so the ID is not
    appended a second time when the name already ends with it. Without an ID —
    a sealed node does not report one — the name alone is used.
    """
    short_id = (cluster_id or "").replace("-", "")[:8].lower()
    if not short_id or cluster_name.lower().endswith(f"-{short_id}"):
        return cluster_name
    return f"{cluster_name}-{short_id}"


def validate_date_format(date_str: str) -> None:
    """Validate date string format.

    Args:
        date_str: Date string to validate.

    Raises:
        ValueError: If date format is invalid.
    """
    try:
        datetime.strptime(date_str, DATE_FORMAT)
    except ValueError as e:
        raise ValueError(f"Invalid date format '{date_str}'. Expected format: YYYY-MM-DD") from e


def get_first_day_of_month(month: datetime) -> datetime:
    """Get the first day of the given month.

    Args:
        month: A datetime object representing any day in the target month.

    Returns:
        datetime: A datetime object set to the first day of the month.
    """
    return month.replace(day=1)


def get_last_day_of_month(month: datetime) -> datetime:
    """Get the last day of the given month.

    Args:
        month: A datetime object representing any day in the target month.

    Returns:
        datetime: A datetime object set to the last day of the month.
    """
    last_day = calendar.monthrange(month.year, month.month)[1]
    return month.replace(day=last_day)


def normalise_namespace_path(path: str | None) -> str:
    """Normalise a Vault namespace path to the canonical API form.

    Vault's namespace API expects a trailing slash on non-root paths, so that is
    what this returns. Root is the empty string. This is the single source of
    truth for the convention (finding C1) — config and CLI entry points all
    route through it rather than repeating the rule inline.

    Rules:
    - ``None``, ``""``, ``"/"``, or whitespace → ``""``  (root namespace)
    - Any other value → whitespace stripped, exactly one trailing slash

    Examples::

        normalise_namespace_path(None)        # ""
        normalise_namespace_path("")          # ""
        normalise_namespace_path("/")         # ""
        normalise_namespace_path("foo")       # "foo/"
        normalise_namespace_path("foo/")      # "foo/"
        normalise_namespace_path("foo/bar//") # "foo/bar/"
    """
    if not path:
        return ""
    stripped = path.strip().rstrip("/")
    return "" if stripped == "" else f"{stripped}/"


def get_last_month() -> datetime:
    """Get the last day of the previous month from today's date (UTC).

    Returns:
        datetime: A timezone-aware (UTC) datetime set to the last day of the
        previous month. Note the tz-awareness: combining the result with a naive
        datetime — ``get_last_month() - datetime.now()``, for instance — raises
        TypeError. Use ``datetime.now(UTC)`` on the other side of any such
        expression.
    """
    # Use UTC so behaviour is consistent regardless of the host timezone (U2).
    # U1 is already correctly implemented via calendar.monthrange above.
    return datetime.now(UTC).replace(day=1) - timedelta(days=1)


# argparse types shared by main.py and scripts/threshold-margins.py, so the
# script accepts exactly the values the CLI flags do.
_DURATION = re.compile(r"^(\d+)([smhd]?)$")
_DURATION_UNITS = {"": 1, "s": 1, "m": 60, "h": 3600, "d": 86400}


def duration_seconds(value: str) -> int:
    """argparse type: "90m", "2h", "1d" or plain seconds, as a positive number of seconds."""
    match = _DURATION.match(value.strip().lower())
    if not match or int(match[1]) == 0:
        raise argparse.ArgumentTypeError(f"invalid duration {value!r}: use a positive number with an optional s, m, h or d suffix (e.g. 2h)")
    return int(match[1]) * _DURATION_UNITS[match[2]]


def positive_int(value: str) -> int:
    """argparse type: an integer above zero."""
    try:
        number = int(value)
    except ValueError:
        number = 0
    if number <= 0:
        raise argparse.ArgumentTypeError(f"invalid value {value!r}: must be a positive integer")
    return number
