import calendar
import logging
from datetime import UTC, datetime, timedelta

logger = logging.getLogger(__name__)

# Shared date format constants — use these everywhere instead of inline literals.
DATE_FORMAT = "%Y-%m-%d"  # Parsing/validation (YYYY-MM-DD)
FILE_DATE_FORMAT = "%Y%m%d"  # File name suffix (YYYYMMDD)


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
