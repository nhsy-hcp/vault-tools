
import logging
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)

def validate_date_format(date_str: str) -> None:
    """Validate date string format.
    
    Args:
        date_str: Date string to validate.
        
    Raises:
        ValueError: If date format is invalid.
    """
    try:
        datetime.strptime(date_str, "%Y-%m-%d")
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
    next_month = month.replace(day=28) + timedelta(days=4)
    return next_month - timedelta(days=next_month.day)

def get_last_month() -> datetime:
    """Get the last day of the previous month from today's date.
    
    Returns:
        datetime: A datetime object set to the last day of the previous month.
    """
    return datetime.today().replace(day=1) - timedelta(days=1)
