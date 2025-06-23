import os
import sys
from datetime import datetime, timedelta

sys.path.insert(0, f"{os.path.dirname(__file__)}/../")

from main import _get_first_day_of_month, _get_last_day_of_month, _get_last_month


def test_get_first_day_of_month():
    month = datetime(2022, 3, 15)
    expected = datetime(2022, 3, 1, 0, 0, 0)
    assert _get_first_day_of_month(month) == expected


def test_get_last_day_of_month_1():
    month = datetime(2024, 3, 15, )
    expected = datetime(2024, 3, 31, 0, 0, 0)
    assert _get_last_day_of_month(month) == expected


def test_get_last_day_of_month_2():
    month = datetime(2024, 1, 15)
    expected = datetime(2024, 1, 31, 0, 0, 0)
    assert _get_last_day_of_month(month) == expected


def test_get_last_day_of_month_3():
    month = datetime(2023, 12, 15)
    expected = datetime(2023, 12, 31, 0, 0, 0)
    assert _get_last_day_of_month(month) == expected


def test_get_last_month():
    # Test that the function returns a datetime object for the last day of the previous month
    result = _get_last_month()
    assert isinstance(result, datetime)
    
    # Verify it's the last day of the previous month
    today = datetime.today()
    expected_month = today.month - 1 if today.month > 1 else 12
    expected_year = today.year if today.month > 1 else today.year - 1
    
    assert result.month == expected_month
    assert result.year == expected_year
    
    # Verify it's the last day of that month by checking that adding one day moves to next month
    next_day = result + timedelta(days=1)
    assert next_day.day == 1
